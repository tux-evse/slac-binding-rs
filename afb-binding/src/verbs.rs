/*
 * Copyright (C) 2015-2022 IoT.bzh Company
 * Author: Fulup Ar Foll <fulup@iot.bzh>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 */
use std::cell::Cell;
use std::rc::Rc;

use crate::prelude::*;
use afbv4::prelude::*;
use slac::prelude::*;
use typesv4::prelude::*;

#[derive(Clone, Copy)]
enum SlacRqt {
    Check,
    Clear,
    None,
}

struct JobPostCtx {
    slac: Rc<SlacSession>,
    request: Rc<Cell<SlacRqt>>,
}
AfbJobRegister!(JobPostCtrl, jobpost_callback, JobPostCtx);
fn jobpost_callback(
    _job: &AfbSchedJob,
    _signal: i32,
    ctx: &mut JobPostCtx,
) -> Result<(), AfbError> {
    let request = ctx.request.get();
    match request {
        SlacRqt::Clear => ctx.slac.evse_clear_key(),
        SlacRqt::Check => ctx.slac.send_set_key_req(),

        _ => Ok(()),
    }
}

struct IecEvtCtx {
    job_post: &'static AfbSchedJob,
    request: Rc<Cell<SlacRqt>>,
}

AfbEventRegister!(IsoEvtVerb, evt_iec6185_cb, IecEvtCtx);
fn evt_iec6185_cb(
    _event: &AfbEventMsg,
    args: &AfbData,
    ctx: &mut IecEvtCtx,
) -> Result<(), AfbError> {
    // ignore any event other than plug status
    match args.get::<&Iec6185Msg>(0)? {
        Iec6185Msg::Plugged(connected) => {
            if *connected {
                ctx.request.set(SlacRqt::Check);
                ctx.job_post.post(0)?;
            } else {
                ctx.request.set(SlacRqt::Clear);
                ctx.job_post.post(0)?;
            }
        }
        _ => {}
    }
    Ok(())
}

// this method is call each time a message is waiting on slac raw_socket
struct AsyncFdCtx {
    slac: Rc<SlacSession>,
    event: &'static AfbEvent,
}
AfbEvtFdRegister!(SessionAsyncCtrl, async_session_cb, AsyncFdCtx);
fn async_session_cb(_evtfd: &AfbEvtFd, revent: u32, ctx: &mut AsyncFdCtx) -> Result<(), AfbError> {

    if revent == AfbEvtFdPoll::IN.bits() {
        use std::mem::MaybeUninit;
        #[allow(invalid_value)]
        let mut message:SlacRawMsg= unsafe { MaybeUninit::uninit().assume_init()};
        ctx.slac.get_sock().read(&mut message)?;
        let payload = ctx.slac.decode(&message)?;
        afb_log_msg!(
            Debug,
            ctx.event,
            "iface:{} payload:{}",
            ctx.slac.get_iface(),
            payload
        );
    }
    Ok(())
}

struct TimerCtx {
    slac: Rc<SlacSession>,
}
// timer sessions maintain pending sessions when needed
AfbTimerRegister!(TimerCtrl, timer_callback, TimerCtx);
fn timer_callback(timer: &AfbTimer, _decount: u32, ctx: &mut TimerCtx) -> Result<(), AfbError> {
    let action = ctx.slac.check()?;
    afb_log_msg!(
        Info,
        timer,
        "iface:{} tic:{}",
        ctx.slac.get_iface(),
        format!("{:?}", action)
    );
    Ok(())
}

pub(crate) fn register(api: &mut AfbApi, config: ApiConfig) -> Result<(), AfbError> {
    // one afb event per slac
    let iface = config.slac.iface;
    let event = AfbEvent::new(iface);

    // create afb/slac slac session and exchange keys
    let slac = Rc::new(SlacSession::new(iface, &config.slac)?);
    slac.evse_clear_key()?;
    slac.send_set_key_req()?;

    // register dev handler within listening event loop
    AfbEvtFd::new(iface)
        .set_fd(slac.get_sock().get_sockfd())
        .set_events(AfbEvtFdPoll::IN)
        .set_callback(Box::new(AsyncFdCtx {
            slac: slac.clone(),
            event,
        }))
        .start()?;

    // slac timer check for pending request and clean them up when needed
    AfbTimer::new(config.uid)
        .set_period(config.slac.timeout)
        .set_decount(0)
        .set_callback(Box::new(TimerCtx {
            slac: slac.clone(),
        }))
        .start()?;

    // share slac request from event to async callback
    let request = Rc::new(Cell::new(SlacRqt::None));

    let job_post = AfbSchedJob::new("iec6185-job")
        .set_exec_watchdog(2) // limit exec time to 200ms;
        .set_callback(Box::new(JobPostCtx {
            slac: slac.clone(),
            request: request.clone(),
        }))
        .finalize();

    // finally subscribe to iec6185 events
    let iso_handle = AfbEvtHandler::new("iec6185-evt")
        .set_info("iec6185 event from ti-am62x binding")
        .set_pattern(to_static_str(format!(
            "{}/{}",
            config.iec_api, config.iec_evt
        )))
        .set_callback(Box::new(IecEvtCtx {
            job_post,
            request: request.clone(),
        }))
        .finalize()?;

    // register verb, event & handler into api
    api.add_evt_handler(iso_handle);
    api.add_event(event);

    Ok(())
}

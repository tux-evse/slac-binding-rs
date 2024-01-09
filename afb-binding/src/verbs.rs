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
enum SlacAction {
    Check,
    Clear,
    None,
}

struct JobPostCtx {
    slac: Rc<SlacSession>,
    action: Rc<Cell<SlacAction>>,
}
AfbJobRegister!(JobPostCtrl, jobpost_callback, JobPostCtx);
fn jobpost_callback(
    _job: &AfbSchedJob,
    _signal: i32,
    ctx: &mut JobPostCtx,
) -> Result<(), AfbError> {
    let request = ctx.action.get();
    match request {
        SlacAction::Clear => {}
        SlacAction::Check => {
            // move status to wait slac_param until timeout
            ctx.slac.set_status(
                SlacRequest::CM_SLAC_PARAM,
                SlacStatus::WAITING,
                ctx.slac.config.timeout,
            )?;
        }

        _ => {}
    }
    Ok(())
}

struct IecEvtCtx {
    job_post: &'static AfbSchedJob,
    action: Rc<Cell<SlacAction>>,
}

AfbEventRegister!(IsoEvtVerb, evt_iec6185_cb, IecEvtCtx);
fn evt_iec6185_cb(
    event: &AfbEventMsg,
    args: &AfbData,
    ctx: &mut IecEvtCtx,
) -> Result<(), AfbError> {
    // ignore any event other than plug status
    let iecmsg = args.get::<&Iec6185Msg>(0)?;
    afb_log_msg!(Debug, event, "{:?}", iecmsg);
    match iecmsg {
        Iec6185Msg::Plugged(connected) => {
            if *connected {
                ctx.action.set(SlacAction::Check);
                ctx.job_post.post(0)?;
            } else {
                ctx.action.set(SlacAction::Clear);
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
        let mut message: SlacRawMsg = unsafe { MaybeUninit::uninit().assume_init() };
        ctx.slac.get_sock().read(&mut message)?;
        let payload = ctx.slac.decode(&message)?;
        afb_log_msg!(
            Debug,
            ctx.event,
            "iface:{} payload:{}",
            ctx.slac.get_iface(),
            payload
        );

        match payload {
            SlacPayload::SlacParmCnf(_payload) => {
                ctx.event.push(SlacStatus::JOINING);
            }
            SlacPayload::SlacMatchReq(_payload) => {}
            SlacPayload::SlacMatchCnf(_payload) => {}
            _ => {}
        }
    }
    Ok(())
}

struct TimerCtx {
    slac: Rc<SlacSession>,
    event: &'static AfbEvent,
    rootv4: AfbApiV4,
    iec_api: &'static str,
}
// timer sessions maintain pending sessions when needed
AfbTimerRegister!(TimerCtrl, timer_callback, TimerCtx);
fn timer_callback(timer: &AfbTimer, _decount: u32, ctx: &mut TimerCtx) -> Result<(), AfbError> {
    match ctx.slac.check() {
        Ok(next) => {
            afb_log_msg!(
                Debug,
                timer,
                "iface:{} next:{}",
                ctx.slac.get_iface(),
                format!("{:?}", next)
            );
        }
        Err(error) => {
            // slac fail let's notify firmware
            let status= ctx.slac.get_status()?;
            afb_log_msg!(Debug, timer, "{}", error);
            AfbSubCall::call_sync(ctx.rootv4, ctx.iec_api, "slac", status)?;
            ctx.event.push(status);
        }
    }
    Ok(())
}


struct SubscribeData {
    event: &'static AfbEvent,
}
AfbVerbRegister!(SubscribeCtrl, subscribe_callback, SubscribeData);
fn subscribe_callback(
    request: &AfbRequest,
    args: &AfbData,
    ctx: &mut SubscribeData,
) -> Result<(), AfbError> {
    let subcription = args.get::<bool>(0)?;
    if subcription {
        ctx.event.subscribe(request)?;
    } else {
        ctx.event.unsubscribe(request)?;
    }
    request.reply(AFB_NO_DATA, 0);
    Ok(())
}

pub(crate) fn register(rootv4: AfbApiV4, api: &mut AfbApi, config: ApiConfig) -> Result<(), AfbError> {
    // one afb event per slac
    let iface = config.slac.iface;
    let event = AfbEvent::new(config.event);

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
            event,
            rootv4,
            iec_api: config.iec_api,

        }))
        .start()?;

    // share slac request from event to async callback
    let action = Rc::new(Cell::new(SlacAction::None));

    let job_post = AfbSchedJob::new("iec6185-job")
        .set_exec_watchdog(2) // limit exec time to 200ms;
        .set_callback(Box::new(JobPostCtx {
            slac: slac.clone(),
            action: action.clone(),
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
            action: action.clone(),
        }))
        .finalize()?;

    let subscribe = AfbVerb::new("subscribe")
        .set_callback(Box::new(SubscribeCtrl { event }))
        .set_info("subscribe Iec6185 event")
        .set_usage("true|false")
        .finalize()?;

    // register verb, event & handler into api
    api.add_verb(subscribe);
    api.add_evt_handler(iso_handle);
    api.add_event(event);

    Ok(())
}

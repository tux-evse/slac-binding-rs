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
use std::rc::Rc;

use crate::prelude::*;
use afbv4::prelude::*;
use slac::prelude::*;
use typesv4::prelude::*;

struct JobClearKeyCtx {
    slac: Rc<SlacSession>,
}
AfbJobRegister!(JobClearKeyCtrl, job_clear_key_callback, JobClearKeyCtx);
fn job_clear_key_callback(
    _job: &AfbSchedJob,
    _signal: i32,
    _data: &AfbSchedData,
    ctx: &mut JobClearKeyCtx,
) -> Result<(), AfbError> {
    let mut state = ctx.slac.get_state()?;
    send_set_key_req(&ctx.slac, &mut state)?;
    Ok(())
}

struct IecEvtCtx {
    job_post: &'static AfbSchedJob,
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
                ctx.job_post.post(0, AFB_NO_DATA)?;
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
        let message = MaybeUninit::<SlacRawMsg>::uninit();
        let mut message = unsafe { message.assume_init() };
        ctx.slac.get_sock().read(&mut message)?;
        let payload = ctx.slac.decode(&message)?;

        match payload {
            SlacPayload::SlacParmCnf(_payload) => {
                ctx.event.push(SlacStatus::JOINING);
            }
            SlacPayload::SlacMatchReq(_payload) => {
                ctx.event.push(SlacStatus::MATCHING);
            }
            SlacPayload::SlacMatchCnf(_payload) => {
                ctx.event.push(SlacStatus::MATCHED);
            }
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
    match ctx.slac.check_pending() {
        Ok(next) => match next {
            SlacRequest::CM_NONE => { /*ignore*/ }
            _ => {
                afb_log_msg!(
                    Debug,
                    timer,
                    "slac timer iface:{} next:{}",
                    ctx.slac.get_iface(),
                    format!("{:?}", next)
                );
            }
        },
        Err(error) => {
            // slac fail let's notify firmware
            afb_log_msg!(Debug, timer, "Slac session check:{}", error);
            let session_status = ctx.slac.update_status(SlacStatus::IDLE)?;
            AfbSubCall::call_sync(ctx.rootv4, ctx.iec_api, "slac", session_status)?;
            ctx.event.push(session_status);
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

struct PushStatusData {
    event: &'static AfbEvent,
}
AfbVerbRegister!(PushStatusCtrl, pushstatus_callback, PushStatusData);
fn pushstatus_callback(
    request: &AfbRequest,
    args: &AfbData,
    ctx: &mut PushStatusData,
) -> Result<(), AfbError> {
    let status = args.get::<&SlacStatus>(0)?;
    ctx.event.push(status.clone());
    request.reply(AFB_NO_DATA, 0);
    Ok(())
}

pub(crate) fn register(
    rootv4: AfbApiV4,
    api: &mut AfbApi,
    config: ApiConfig,
) -> Result<(), AfbError> {
    // one afb event per slac
    let iface = config.slac.iface;
    let event = AfbEvent::new("evt");

    // create afb/slac slac session and exchange keys
    let slac = Rc::new(SlacSession::new(iface, &config.slac)?);
    slac.evse_clear_key()?;

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
        .set_period(config.slac.timetic)
        .set_decount(0)
        .set_callback(Box::new(TimerCtx {
            slac: slac.clone(),
            event,
            rootv4,
            iec_api: config.iec_api,
        }))
        .start()?;


    let job_post = AfbSchedJob::new("iec6185-job")
        .set_exec_watchdog(2) // limit exec time to 200ms;
        .set_callback(Box::new(JobClearKeyCtx {
            slac: slac.clone(),
        }))
        .finalize();

    // finally subscribe to iec6185 events
    let iso_handle = AfbEvtHandler::new("iec6185-evt")
        .set_info("iec6185 event from ti-am62x binding")
        .set_pattern(to_static_str(format!("{}/*", config.iec_api)))
        .set_callback(Box::new(IecEvtCtx {
            job_post,
        }))
        .finalize()?;

    let subscribe = AfbVerb::new("subscribe")
        .set_callback(Box::new(SubscribeCtrl { event }))
        .set_info("subscribe Iec6185 event")
        .set_usage("true|false")
        .finalize()?;

    let push_verb = AfbVerb::new("push-status")
        .set_callback(Box::new(PushStatusCtrl { event }))
        .set_info("force Slac status push")
        .set_usage("{'UNMATCHED}")
        .finalize()?;

    // register verb, event & handler into api
    api.add_verb(subscribe);
    api.add_verb(push_verb);
    api.add_evt_handler(iso_handle);
    api.add_event(event);

    Ok(())
}

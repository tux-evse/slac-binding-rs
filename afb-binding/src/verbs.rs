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
use libslac::prelude::*;

//#[derive(Clone)]
struct AfbSlacSession {
    pub uid: &'static str,
    pub event: &'static AfbEvent,
    pub slac: SlacSession,
}

struct SessionCtx {
    session: Rc<AfbSlacSession>,
}

pub(self) fn get_session(
    sessions: &Vec<Rc<AfbSlacSession>>,
    iface: &String,
) -> Result<Rc<AfbSlacSession>, AfbError> {
    for idx in 0..sessions.len() {
        let session = sessions[idx].clone();
        if session.uid == iface {
            return Ok(session);
        }
    }
    Err(AfbError::new(
        "slac-sesion-iface",
        "Iface not found with sessions",
    ))
}

// this method is call each time a message is waiting on session raw_socket
AfbEvtFdRegister!(SessionAsyncCtrl, async_session_cb, SessionCtx);
fn async_session_cb(_evtfd: &AfbEvtFd, revent: u32, ctx: &mut SessionCtx) {
    let slac = &ctx.session.slac;
    let evt = ctx.session.event;

    if revent == AfbEvtFdPoll::IN.value() {
        match SlacRawMsg::read(slac.get_sock()) {
            Err(error) => {
                afb_log_msg!(
                    Error,
                    evt,
                    "iface:{} invalid packet error={}",
                    slac.get_iface(),
                    error
                );
            }
            Ok(message) => match slac.decode(&message) {
                Err(error) => {
                    afb_log_msg!(
                        Error,
                        evt,
                        "iface:{} Unknown message error={}",
                        slac.get_iface(),
                        error
                    );
                }
                Ok(payload) => {
                    afb_log_msg!(Debug, evt, "iface:{} payload:{}", slac.get_iface(), payload);
                }
            },
        }
    }
}

// timer sessions maintain pending sessions when needed
AfbTimerRegister!(TimerCtrl, timer_callback, SessionCtx);
fn timer_callback(timer: &AfbTimer, _decount: u32, ctx: &mut SessionCtx) {
    let slac = &ctx.session.slac;
    let evt = ctx.session.event;

    match slac.check() {
        Err(error) => {
            afb_log_msg!(Error, timer, "iface:{} error={}", slac.get_iface(), &error);
            evt.push(&error);
        }
        Ok(action) => {
            afb_log_msg!(
                Info,
                timer,
                "iface:{} tic:{}",
                slac.get_iface(),
                format!("{:?}", action)
            );
        }
    }
}

struct NewStateData {
    sessions: Vec<Rc<AfbSlacSession>>,
    //evt: &'static AfbEvent,
}
AfbVerbRegister!(NewstateCtrl, pwm_state_callback, NewStateData);
fn pwm_state_callback(
    request: &AfbRequest,
    args: &AfbData,
    ctx: &mut NewStateData,
) -> Result<(), AfbError> {
    // retrieve iface & state from argument and search for corresponding sessions
    let jrqt = args.get::<JsoncObj>(0)?;
    let iface = jrqt.get::<String>("iface")?;
    let cp_state = jrqt.get::<String>("state")?;

    let session = get_session(&ctx.sessions, &iface)?;
    let slac = &session.slac;
    let _evt = session.event;

    let status = slac.get_status()?;

    match cp_state.as_str() {
        "A" => match status {
            SlacStatus::MATCHED => slac.evse_clear_key()?,
            _ => {
                request.reply(
                    format!("rqt ignored:{} current state:{:?}", cp_state, status),
                    AFB_FAIL,
                );
            }
        },

        "B" | "C" | "D" => match slac.get_status()? {
            SlacStatus::IDLE => {
                afb_log_msg!(
                    Debug,
                    request,
                    "iface:{} CM_SET_KEY start",
                    slac.get_iface()
                );
                slac.send_set_key_req()?
            }
            _ => {
                return Ok(request.reply(
                    format!("rqt ignored:{} current state:{:?}", cp_state, status),
                    AFB_FAIL,
                ));
            }
        },
        _ => { /* case E, F */ }
    }

    //ctx.evt.subscribe(request)?;
    request.reply(AFB_NO_DATA, 0);
    Ok(())
}

pub(crate) fn register(api: &mut AfbApi, config: ApiConfig) -> Result<(), AfbError> {
    // defined sessions global handle
    let mut sessions: Vec<Rc<AfbSlacSession>> = Vec::new();

    // create a socket per declared session
    for iface in config.slac.iface.replace(" ", "").split(",") {
        let iface = to_static_str(iface.to_string());

        // one afb event per session
        let event = AfbEvent::new(iface);
        api.add_event(event);

        // create afb/slac session handle
        let session = Rc::new(AfbSlacSession {
            uid: iface,
            slac: SlacSession::new(iface, &config.slac)?,
            event: event,
        });

        // register dev handler within listening event loop
        AfbEvtFd::new(iface)
            .set_fd(session.slac.get_sock().get_sockfd())
            .set_events(AfbEvtFdPoll::IN)
            .set_callback(Box::new(SessionCtx {
                session: session.clone(),
            }))
            .start()?;

        // session timer check for pending request and clean them up when needed
        match AfbTimer::new(config.uid)
            .set_period(config.slac.timeout)
            .set_decount(0)
            .set_callback(Box::new(SessionCtx {
                session: session.clone(),
            }))
            .start()
        {
            Err(error) => {
                afb_log_msg!(Critical, api.get_apiv4(), &error);
                Err(error)
            }
            Ok(_timer) => Ok(()),
        }?;

        // add session within waiting list
        sessions.push(session)
    }

    let newstate = AfbVerb::new("newstate")
        .set_callback(Box::new(NewstateCtrl {
            sessions: sessions.clone(),
        }))
        .set_info("state Iec6185 event")
        .set_sample("{'iface':'br0','state':'B'}")?
        .set_sample("{'iface':'br0','state':'A'}")?
        .set_usage("{'iface':'xxx','state':'A|B|...'}")
        .finalize()?;

    api.add_verb(newstate);

    Ok(())
}

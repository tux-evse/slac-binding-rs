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
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Reference:
 *   https://github.com/SwitchEV/pyslac/blob/master/pyslac/session.py
 *   https://github.com/qca/open-plc-utils.git
 *   https://github.com/EVerest/libslac
 */

use sha2::{Digest, Sha256};
use std::cell::{Ref, RefCell, RefMut};
use std::mem;
use std::time::Instant;

use crate::prelude::*;
use afbv4::prelude::*;
use typesv4::prelude::*;

#[derive(Clone)]
pub struct SessionConfig {
    pub iface: &'static str,
    pub evseid: SlacStaId,
    pub nmk: SlacNmk, // Network Mask is a random 16 bytes number
    pub timeout: u32, // initial timeout in seconds
    pub timetic: u32, // session check period
}

pub struct SessionState {
    pub status: SlacStatus,   // current session status IDLE,MATCHED,...
    pub pending: SlacRequest, // ongoing request
    pub timeout: u32,         // timeout for ongoing request
    pub nonce: u32,           // request nonce
    pub stamp: Instant,       // request start time
    pub nid: SlacNid,         // session nid should be renewed for each unmatch
    pub count: usize,         // stat packet counter
    pub runid: SlacRunId, // 8 bytes identifier used to identify a running session retrieve from PEV
    pub application_type: u8, // 1 byte APPLICATION_TYPE will be 0 for SLAC
    pub security_type: u8, // 1 byte Security Type is also 0x00 for SLAC
    pub num_sounds: u8, // Number of total sounds expected to arrive from EV In 15118-3 is associated with CM_EV_match_MNBC
    pub pevid: SlacStaId, // should be PV VIN number
    pub avg_groups: u8, // number of OFDM carrier groups
    pub agv_count: u32, // number of effectively received sound messages
    pub avg_attn: [u32; SLAC_AGGGROUP_LEN], // list of average attenuation for each group
    pub pev_addr: SlacIfMac,
}

pub struct SlacSession {
    pub config: SessionConfig,
    pub state: RefCell<SessionState>,
    pub socket: SockRaw,
}

impl SlacSession {
    // Fulup TBD faire une struc SlacConfig
    pub fn new(iface: &'static str, config: &SessionConfig) -> Result<SlacSession, AfbError> {
        // state hold the dynamic data from session
        let state = RefCell::new(SessionState {
            status: SlacStatus::IDLE,
            stamp: Instant::now(),
            pending: SlacRequest::CM_NONE,
            num_sounds: SLAC_MSOUNDS,
            timeout: 0,
            nonce: 0,
            nid: [0; mem::size_of::<SlacNid>()],
            runid: [0; mem::size_of::<SlacRunId>()],
            pevid: [0; mem::size_of::<SlacStaId>()],
            avg_attn: [0; mem::size_of::<SlacGroups>()],
            count: 0,
            application_type: 0,
            security_type: 0,
            avg_groups: 0,
            agv_count: 0,
            pev_addr: ATHEROS_MAC_ADDR,
        });

        let session = SlacSession {
            state: state,
            config: config.clone(),
            socket: SockRaw::open(iface)?,
        };

        Ok(session)
    }

    // nid: network identifier nmk: network membership key
    // It generates a NID key, based on the NMK, which is a random 16 bytes value.
    // The way the NID is generated is by hashing recursively the NMK 5 times,
    // reinitialize the sha256 buffer each time. It then collects the first
    // 7 bytes of the result and shifts 4 times the least significant byte.
    // The algorithm to implement could be extracted from the Qualcomm implementation
    // in https://github.com/qca/open-plc-utils/blob/master/key/HPAVKeyNID.c
    // The procedure to get the NID described in the HPGP 1.1, section 4.4.3.1
    // does not match the algorithm presented here and in fact makes no sense;
    // :param nmk: NMK [16 bytes] randomly generated
    // :return: NID [7 bytes]
    // https://manpages.debian.org/testing/plc-utils-extra/evse.1.en.html
    pub fn mk_nid_from_nmk(&self) -> SlacNid {
        afb_log_msg!(Notice, None, "SlacSession:mk_nid_from_nmk");

        let mut hasher = Sha256::new();
        hasher.update(self.config.nmk);
        let digest = hasher.finalize();

        let mut nid: SlacNid = unsafe { mem::zeroed() };
        // collect 6 first sha256 digest bytes
        for idx in 0..nid.len() - 1 {
            nid[idx] = digest[idx];
        }
        // shift last byte for time
        nid[nid.len() - 1] = digest[digest.len() - 1] >> 4;

        nid
    }

    pub fn get_sock<'a>(&'a self) -> &'a SockRaw {
        &self.socket
    }

    pub fn get_iface(&self) -> &'static str {
        self.config.iface
    }

    #[track_caller]
    pub fn get_cell(&self) -> Result<RefMut<'_, SessionState>, AfbError> {
        match self.state.try_borrow_mut() {
            Err(_) => return afb_error!("sock-client-state", "fail to access &mut data_set"),
            Ok(value) => Ok(value),
        }
    }

    pub fn set_waiting(
        &self,
        rqt: SlacRequest,
        status: SlacStatus,
        timeout: u32,
    ) -> Result<(), AfbError> {
        afb_log_msg!(Notice, None, "SlacSession:set_waiting");
        let mut state = self.get_cell()?;
        state.pending = rqt;
        state.timeout = timeout;
        state.stamp = Instant::now();
        state.status = status;
        Ok(())
    }

    pub fn set_param_req(
        &self,
        state: &mut SessionState,
        runid: &SlacRunId,
        app_type: u8,
        secu_type: u8,
    ) {
        afb_log_msg!(Notice, None, "SlacSession:set_param_req");
        state.runid = runid.clone();
        state.application_type = app_type;
        state.security_type = secu_type;
    }

    pub fn get_pending(&self) -> Result<SlacRequest, AfbError> {
        afb_log_msg!(Notice, None, "SlacSession:get_pending");

        match self.state.try_borrow() {
            Err(_) => afb_error!("session-get-pending", "fail to access state"),
            Ok(value) => Ok(*Ref::map(value, |t| &t.pending)),
        }
    }

    pub fn get_status(&self) -> Result<SlacStatus, AfbError> {
        afb_log_msg!(Notice, None, "SlacSession:get_status");
        match self.state.try_borrow() {
            Err(_) => afb_error!("session-get-status", "fail to access state"),
            Ok(value) => Ok(*Ref::map(value, |t| &t.status)),
        }
    }

    pub fn get_nid(&self) -> Result<SlacNid, AfbError> {
        afb_log_msg!(Notice, None, "SlacSession:get_nid");
        match self.state.try_borrow() {
            Err(_) => afb_error!("session-get-nid", "fail to access state"),
            Ok(value) => Ok(Ref::map(value, |t| &t.nid).clone()),
        }
    }

    // check for pending timeout request
    // Fulup TBD: what should be do when session fail to match ???
    pub fn check_pending(&self) -> Result<SlacRequest, AfbError> {
        let mut state = self.get_cell()?;

        let action = match state.status {
            SlacStatus::WAITING => {
                let now = Instant::now();
                let elapse = now.duration_since(state.stamp).as_millis();
                if elapse > state.timeout as u128 {
                    match state.pending {
                        SlacRequest::CM_SLAC_PARAM_REQ => {
                            state.status = SlacStatus::TIMEOUT;
                            return afb_error!("session-check-timeout", "slac_param",);
                        }
                        SlacRequest::CM_MNBC_SOUND_IND => {
                            for idx in 0..state.avg_groups as usize {
                                state.avg_attn[idx] = state.avg_attn[idx] / state.agv_count;
                            }
                            state.pending
                        }
                        SlacRequest::CM_SLAC_MATCH_REQ => {
                            state.status = SlacStatus::UNMATCHED;
                            return afb_error!("session-check-timeout", "slac_match",);
                        }
                        SlacRequest::CM_SET_KEY_CNF => {
                            // resent CM_SLAC_PARAM_REQ until we get a response
                            send_set_key_req(self, &mut state)?;
                            state.pending
                        }
                        _ => SlacRequest::CM_NONE, // waiting command as no chaining
                    }
                } else {
                    SlacRequest::CM_NONE // timeout still running wait until next round
                }
            }
            _ => SlacRequest::CM_NONE, // nothing waiting
        };

        // chaining of command should be done after session.state as been freed
        let action = match action {
            SlacRequest::CM_SLAC_PARAM_REQ => {
                send_set_key_req(self, &mut state)?; // retry SET_KEY_REQ
                SlacRequest::CM_SET_KEY_CNF
            }
            _ => action, // nothing to be done
        };

        Ok(action)
    }

    pub fn evse_clear_key(&self, state: &mut SessionState) -> Result<(), AfbError> {
        afb_log_msg!(Notice, None, "SlacSession:evse_clear_key");
        state.nid = [0; SLAC_NID_LEN];
        state.pending = SlacRequest::CM_NONE;
        state.status = SlacStatus::IDLE;
        Ok(())
    }

    pub fn decode<'a>(&self, msg: &'a SlacRawMsg) -> Result<SlacPayload<'a>, AfbError> {
        let mut state = self.get_cell()?;
        let payload = match msg.mime_parse()? {
            //got CM_SET_KEY.CNF store source mac addr
            SlacPayload::SetKeyCnf(payload) => {
                afb_log_msg!(Notice, None, "get SlacPayload::SetKeyCnf (CM_SET_KEY.CNF)");

                if payload.result != 1 /*bug*/ || payload.your_nonce != state.nonce {
                    return afb_error!(
                        "session-set-key-req",
                        "invalid payload result:{}, valid-nonces:{}",
                        payload.result,
                        payload.your_nonce == state.nonce
                    );
                }

                state.pending = SlacRequest::CM_SLAC_PARAM_REQ;
                state.timeout = self.config.timeout;
                state.stamp = Instant::now();
                state.status = SlacStatus::WAITING;
                payload.as_slac_payload()?
            }

            // CM_SLAC_PARAM.REQ start SLAC negotiation
            SlacPayload::SlacParmReq(payload) => {
                afb_log_msg!(Notice, None, "get SlacPayload::SlacParmReq (CM_SLAC_PARAM.REQ)");
                self.set_param_req(
                    &mut state,
                    &payload.run_id,
                    payload.application_type,
                    payload.application_type,
                );

                state.pev_addr = msg.ethernet.ether_shost; // let's update vehicle source ether addr
                state.pending = SlacRequest::CM_ATTEN_CHAR_IND;
                state.timeout = SLAC_RESP_TIMEOUT;
                state.stamp = Instant::now();
                state.status = SlacStatus::WAITING;
                send_slac_param_cnf(self, &mut state)?;

                payload.as_slac_payload()?
            }

            // CM_MNBC_SOUND.IND (until sound_count or sound_timeout)
            SlacPayload::MnbcSoundInd(payload) => {
                // Time specified by the EV for the Characterization has expired
                // or num of total sounds is >= expected sounds thus, the Atten
                // data must be grouped and averaged before the loop is
                // terminated [V2G3-A09-19]
                afb_log_msg!(
                    Notice,
                    None,
                    "SlacPayload::MnbcSoundInd (CM_MNBC_SOUND.IND)"
                );

                if !matches!(state.pending, SlacRequest::CM_MNBC_SOUND_IND) {
                    return afb_error!("session-mnbc-sound", "No sound expected");
                }

                if !slice_equal(&payload.run_id, &state.runid)
                    || payload.security_type != state.security_type
                    || payload.application_type != state.application_type
                {
                    return afb_error!("session-mnbc-sound", "invalid payload content",);
                }

                // state.num_sound is decremented when receiving CM_ATTEN_PROFILE.IND
                if state.num_sounds - 1 != payload.remaining_sound_count {
                    return afb_error!("session-mnbc-sound", "invalid counting sequence",);
                }

                state.pevid = payload.pevid;
                state.stamp = Instant::now();
                state.pending = SlacRequest::CM_ATTEN_CHAR_IND;
                state.timeout = SLAC_ATTEN_RESULTS_TIMEOUT;

                state.status = SlacStatus::WAITING;
                payload.as_slac_payload()?
            }

            // CM_ATTEN_PROFILE.IND individual sounding result
            SlacPayload::AttenProfileInd(payload) => {
                // The GP specification recommends that the EVSE-HLE set an overall
                // timer once the cm_start_atten_char message is received and use it
                // to terminate the msound loop in case some msounds are lost
                // During this process, the EV will send a CM_MNBC_SOUND.IND containing
                // a payload that corresponds and is defined within the class MnbcSound as:
                // |Application Type|Security Type|SenderID|Cnt|RunID|RSVD|Rnd|
                // For each CM_MNBC_SOUND.IND, the EVSE PLC node will send to the host
                // application a CM_ATTEN_PROFILE.IND whose payload is defined within
                // the class AttenProfile:
                // |PEV MAC|NumGroups|RSVD|AAG 1| AAG 2| AAG 3...|
                // The sounds reception loop is comprised by the following steps:
                // 1. awaiting for the reception of a packet
                // 2. Check for incorrect metadata like Application Type, RunID, ...
                // 3. Check if the packet is a CM_MNBC_SOUND or CM_ATTEN_PROFILE
                // 4. if it is a CM_MNBC_SOUND
                // accept only CM_MNBC_SOUND.IND that match RunID from the earlier
                // CM_SLAC_PARAM.REQ and CM_START_ATTRN_CHAT.IND;
                // each CM_MNBC_MSOUND.IND is accompanied by a CM_ATTEN_PROFILE.IND
                // but sometimes they arrive out of expected order;
                // store the running total of CM_ATTEN_PROFILE.IND.AAG values in
                // the session variable and compute the average based on actual
                // number of sounds before returning;
                afb_log_msg!(
                    Notice,
                    None,
                    "get SlacPayload::AttenProfileInd (CM_ATTEN_PROFILE.IND)"
                );
                if !slice_equal(&payload.pev_mac, &state.pev_addr) {
                    return afb_error!("session-attend-profile", "invalid source PEV Mac addr",);
                }

                state.num_sounds = state.num_sounds - 1;
                state.agv_count = state.agv_count + 1;
                state.avg_groups = payload.num_groups;
                for idx in 0..state.avg_groups as usize {
                    state.avg_attn[idx] = state.avg_attn[idx] + payload.aag[idx] as u32;
                }

                // got all soundings reply with CM_ATTEN_CHAR.IND
                if state.num_sounds == 0 {
                    for idx in 0..state.avg_groups as usize {
                        state.avg_attn[idx] = state.avg_attn[idx] / state.agv_count;
                    }
                    state.pending = SlacRequest::CM_SLAC_MATCH_REQ;
                    state.timeout = SLAC_MATCH_TIMEOUT * 10; // Fulup TBD
                    state.stamp = Instant::now();
                    send_atten_char_ind(self, &mut state)?;
                }
                payload.as_slac_payload()?
            }

            // CM_START_ATTEN_CHAR.IND (Broadcast Message) Announce sounding process start
            // The full process should finish after 600ms, timer is set at 800ms
            SlacPayload::StartAttentCharInd(payload) => {
                // As is stated in ISO15118-3, the EV will send 3 consecutive as broadcast
                afb_log_msg!(Notice, None, "SlacPayload::StartAttentCharInd");
                if !slice_equal(&payload.run_id, &state.runid)
                    || payload.resp_type != cglue::CM_SLAC_PARM_CNF_RESP_TYPE
                    || payload.security_type != state.security_type
                    || payload.application_type != state.application_type
                {
                    return afb_error!("session-start-attend-char-ind", "invalid payload content",);
                }
                state.pev_addr = payload.forwarding_sta;
                state.num_sounds = payload.num_sounds;

                // the value sent by the EV for the timeout has a factor of 1/100
                // Thus, if the value is e.g. 6, the original value is 600 ms (6 * 100)
                // ATTENTION
                // There are cases where there are overhead on the incoming sound
                // frames, causing a timeout.
                // However, according to the following requirements:
                // [V2G3-A09-30] - The EV shall start the timeout timer
                // TT_EV_atten_results (max 1200 ms) when sending the first
                // CM_START_ATTEN_CHAR.IND.
                // [V2G3-A09-31] - While the timer TT_EV_atten_results (max 1200 ms) is
                // running, the EV shall process incoming CM_ATTEN_CHAR.IND messages.
                // Which means, we can use a larger timeout (like 800 ms) so that
                // we receive all or mostly all of the sounds.
                // In order to still respect the standard, we just override the time
                // set by the EV in CM_START_ATTEN_CHAR if ATTEN_RESULTS_TIMEOUT is not None
                // ??? payload.timeout as u32 * 100

                state.pending = SlacRequest::CM_MNBC_SOUND_IND;
                state.timeout = cglue::CM_SLAC_PARM_CNF_TIMEOUT as u32;
                state.stamp = Instant::now();
                state.status = SlacStatus::WAITING;

                payload.as_slac_payload()? // set session to wait for sound messages
            }

            // CM_ATTEN_CHAR.RSP confirmation for sounding OK/FX
            SlacPayload::AttenCharRsp(payload) => {
                afb_log_msg!(Notice, None, "SlacPayload::AttenCharRsp(CM_ATTEN_CHAR.RSP)");
                if !slice_equal(&payload.run_id, &state.runid)
                    || payload.result != cglue::CM_ATTEN_CHAR_RSP_RESULT
                    || payload.security_type != state.security_type
                    || payload.application_type != state.application_type
                {
                    return afb_error!("session-start-attend-char-ind", "invalid payload content",);
                }

                payload.as_slac_payload()? // set session to wait for sound messages
            }

            // CM_SLAC_MATCH.REQ
            SlacPayload::SlacMatchReq(payload) => {
                afb_log_msg!(
                    Notice,
                    None,
                    "get SlacPayload::SlacMatchReq (CM_SLAC_MATCH.REQ)"
                );
                if !slice_equal(&payload.run_id, &state.runid)
                    || payload.security_type != state.security_type
                    || payload.application_type != state.application_type
                {
                    return afb_error!("session-start-attend-char-ind", "invalid payload content",);
                }

                // update PEV station identity
                state.pevid = payload.pev_id;
                state.pev_addr = payload.pev_mac;

                send_slac_match_cnf(self, &mut state)?;
                payload.as_slac_payload()?
            }

            SlacPayload::SetKeyReq(payload) => {
                afb_log_msg!(
                    Notice,
                    None,
                    "get SlacPayload::SetKeyReq ignored (CM_SET_KEY.REQ)"
                );
                return afb_error!("slac-msg-unexpected", "{}", payload);
            }

            SlacPayload::SlacMatchCnf(payload) => {
                afb_log_msg!(
                    Notice,
                    None,
                    "get SlacPayload::SlacMatchCnf ignored (CM_SLAC_MATCH.CNF)"
                );
                return afb_error!("slac-msg-unexpected", "{}", payload);
            }
            SlacPayload::SlacParmCnf(payload) => {
                afb_log_msg!(
                    Notice,
                    None,
                    "get SlacPayload::SlacParmCnf ignored (CM_SLAC_PARAM.CNF)"
                );
                return afb_error!("slac-msg-unexpected", "{}", payload);
            }

            SlacPayload::AttenCharInd(payload) => {
                afb_log_msg!(Notice, None, "get SlacPayload::AttenCharInd ignored");
                return afb_error!("slac-msg-unexpected", "{}", payload);
            }
        };

        Ok(payload)
    }
}

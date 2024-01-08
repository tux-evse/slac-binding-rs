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
use std::cell::{Ref, RefCell};
use std::mem;
use std::time::Instant;

use crate::prelude::*;
use afbv4::prelude::*;

// Session state extracted from Switch/PySlac code
#[derive(Clone, Copy, Debug)]
pub enum SlacStatus {
    MATCHED,
    MATCHING,
    UNMATCHED,
    WAITING,
    JOINING,
    IDLE,
}

#[allow(non_camel_case_types)]
#[derive(Clone, Copy, Debug)]
pub enum SlacRequest {
    CM_SET_KEY,
    CM_SLAC_PARAM,
    CM_MNBC_SOUND,
    CM_SLAC_MATCH,

    CM_NONE, // nothing pending
}

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
    pub pevmac: SlacIfMac,
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
            pevmac: BROADCAST_ADDR,
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

    pub fn set_status(
        &self,
        rqt: SlacRequest,
        status: SlacStatus,
        timeout: u32,
    ) -> Result<(), AfbError> {
        afb_log_msg!(Notice, None, "SlacSession:set_status");
        match self.state.try_borrow_mut() {
            Err(_) => {
                return afb_error!(
                    "session-update-state",
                    "fail to access state",
                )
            }
            Ok(mut state) => {
                state.pending = rqt;
                state.timeout = timeout;
                state.stamp = Instant::now();
                state.status = status;
            }
        }
        Ok(())
    }

    pub fn set_param_req(
        &self,
        runid: &SlacRunId,
        app_type: u8,
        secu_type: u8,
    ) -> Result<(), AfbError> {
        afb_log_msg!(Notice, None, "SlacSession:set_param_req");
        match self.state.try_borrow_mut() {
            Err(_) => return afb_error!("session-set-runid", "fail to access state"),
            Ok(mut state) => {
                state.runid = runid.clone();
                state.application_type = app_type;
                state.security_type = secu_type;
            }
        }
        Ok(())
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
    pub fn check(&self) -> Result<SlacRequest, AfbError> {
        let action = match self.state.try_borrow_mut() {
            Err(_) => return afb_error!("session-check", "fail to access state"),
            Ok(mut state) => {
                if let SlacStatus::WAITING = state.status {
                    let now = Instant::now();
                    let elapse = now.duration_since(state.stamp).as_millis();
                    if elapse > state.timeout as u128 {
                        match state.pending {
                            SlacRequest::CM_SLAC_PARAM => state.pending,
                            SlacRequest::CM_MNBC_SOUND => {
                                for idx in 0..state.avg_groups as usize {
                                    state.avg_attn[idx] = state.avg_attn[idx] / state.agv_count;
                                }
                                state.pending
                            }
                            SlacRequest::CM_SLAC_MATCH => {
                                state.status = SlacStatus::UNMATCHED;
                                return afb_error!(
                                    "session-check-match",
                                    "timeout while waiting match",
                                )
                            }

                            _ => SlacRequest::CM_NONE, // waiting command as no chaining
                        }
                    } else {
                        SlacRequest::CM_NONE // timeout still running wait until next round
                    }
                } else {
                    SlacRequest::CM_NONE // nothing waiting
                }
            }
        };

        // chaining of command should be done after session.state as been freed
        let action = match action {
            SlacRequest::CM_SLAC_PARAM => {
                self.send_set_key_req()?; // retry SET_KEY_REQ
                SlacRequest::CM_SET_KEY
            }
            SlacRequest::CM_MNBC_SOUND => {
                self.send_atten_char()?;
                SlacRequest::CM_MNBC_SOUND
            }
            _ => action, // nothing to be done
        };

        Ok(action)
    }

    // EVSE/PEV -> HPGP Node
    // PEV-HLE sets the NMK and NID on PEV-PLC using CM_SET_KEY.REQ;
    // the NMK and NID must match those provided by EVSE-HLE using
    // CM_SLAC_MATCH.CNF;
    // The configuration of the low-layer communication module with the
    // parameters of the logical network may be done with the MMEs
    // CM_SET_KEY.REQ and CM_SET_KEY.CNF.
    // Table A.8 from ISO15118-3 defines all the parameters needed and their
    // value for this call
    // My Nonce for that STA may remain constant for a run of a protocol),
    // but a new nonce should be generated for each new protocol run.
    // This reflects the purpose of nonces to provide a STA with a quantity i
    // t believes to be freshly generated (to defeat replay attacks) and to
    // use for association of messages within the protocol run.
    // Refer to Section 7.10.7.3 for generation of nonces.
    // The only secure way to remove a STA from an AVLN is to change the NMK
    pub fn send_set_key_req(&self) -> Result<(), AfbError> {
        afb_log_msg!(Notice, None, "SlacSession:send_set_key_req");
        let nid = self.mk_nid_from_nmk();
        let nonce: u32 = GetTime::mk_nonce();

        let payload = cglue::cm_set_key_req {
            key_type: cglue::CM_SET_KEY_REQ_KEY_TYPE_NMK,
            my_nonce: nonce,
            your_nonce: 0,
            pid: cglue::CM_SET_KEY_REQ_PID_HLE,
            prn: htole16(cglue::CM_SET_KEY_REQ_PRN_UNUSED), // enforce big indian (zero does not need conversion)
            pmn: cglue::CM_SET_KEY_REQ_PMN_UNUSED,
            cco_capability: cglue::CM_SET_KEY_REQ_CCO_CAP_NONE,
            nid: nid,
            new_eks: cglue::CM_SET_KEY_REQ_PEKS_NMK_KNOWN_TO_STA,
            new_key: self.config.nmk,
        };

        match self.state.try_borrow_mut() {
            Err(_) => {
                return afb_error!(
                    "session-send-param-req",
                    "fail to access state",
                )
            }
            Ok(mut state) => {
                payload.send(&self.socket, &ATHEROS_ADDR)?;
                state.nonce = nonce;
                state.nid = nid;
            }
        };

        // PEV should respond with CM_SLAC_PARAM.REQ
        self.set_status(
            SlacRequest::CM_SLAC_PARAM,
            SlacStatus::WAITING,
            self.config.timeout,
        )?;
        Ok(())
    }

    // CM_SLAC_PARAM.CNF
    pub fn send_param_cnf(&self) -> Result<(), AfbError> {
        afb_log_msg!(Notice, None, "SlacSession:send_param_cnf");
        match self.state.try_borrow() {
            Err(_) => {
                return afb_error!(
                    "session-send-param-req",
                    "fail to access state",
                )
            }
            Ok(state) => {
                let payload = SlacParmCnf {
                    application_type: state.application_type,
                    security_type: state.security_type,
                    run_id: state.runid.clone(),
                    m_sound_target: state.pevmac.clone(),
                    num_sounds: SLAC_MSOUNDS,
                    timeout: SLAC_INIT_TIMEOUT,
                    resp_type: cglue::CM_SLAC_PARM_CNF_RESP_TYPE,
                    forwarding_sta: state.pevmac.clone(),
                };

                payload.send(&self.socket, &state.pevmac)?;
            }
        }

        // waiting for PEV soundings
        self.set_status(
            SlacRequest::CM_MNBC_SOUND,
            SlacStatus::WAITING,
            SLAC_RESP_TIMEOUT,
        )?;

        Ok(())
    }

    pub fn send_atten_char(&self) -> Result<(), AfbError> {
        afb_log_msg!(Notice, None, "SlacSession:send_atten_char");
        match self.state.try_borrow() {
            Err(_) => {
                return afb_error!(
                    "session-send-atten-char",
                    "fail to access state",
                )
            }
            Ok(state) => {
                let mut agg_group: SlacGroups = [0 as u8; SLAC_AGGGROUP_LEN];
                for idx in 0..state.avg_groups as usize {
                    agg_group[idx] = state.avg_attn[idx] as u8;
                }

                let payload = AttenCharInd {
                    application_type: state.application_type,
                    security_type: state.security_type,
                    run_id: state.runid.clone(),
                    source_address: self.socket.get_ifmac(),
                    source_id: state.pevid.clone(),
                    num_sounds: state.agv_count as u8,
                    resp_id: self.config.evseid.clone(),
                    attenuation_profile: cglue::cm_atten_char_ind__bindgen_ty_1 {
                        num_groups: state.avg_groups,
                        aag: agg_group,
                    },
                };
                payload.send(&self.socket, &state.pevmac)?;
            }
        };

        self.set_status(
            SlacRequest::CM_SLAC_MATCH,
            SlacStatus::WAITING,
            SLAC_RESP_TIMEOUT,
        )?;
        Ok(())
    }

    // CM_SLAC_MATCH config to join EVSE logical network
    pub fn send_slac_match(&self) -> Result<(), AfbError> {
        afb_log_msg!(Notice, None, "SlacSession:send_slac_match");
        match self.state.try_borrow() {
            Err(_) => {
                return afb_error!(
                    "session-send-slac-match",
                    "fail to access state",
                )
            }
            Ok(state) => {
                let payload = SlacMatchCnf {
                    application_type: state.application_type,
                    security_type: state.security_type,
                    run_id: state.runid.clone(),
                    mvf_length: htole16(cglue::CM_SLAC_MATCH_CNF_MVF_LENGTH), // MVF should be little endian
                    pev_id: state.pevid.clone(),
                    pev_mac: state.pevmac.clone(),
                    evse_id: self.config.evseid.clone(),
                    evse_mac: self.socket.get_ifmac(),
                    _rerserved: [0; 8],
                    nid: state.nid.clone(),
                    _reserved2: 0,
                    nmk: self.config.nmk.clone(),
                };
                payload.send(&self.socket, &state.pevmac)?;
            }
        };

        self.set_status(
            SlacRequest::CM_SLAC_MATCH,
            SlacStatus::MATCHED,
            SLAC_RESP_TIMEOUT,
        )?;
        Ok(())
    }

    pub fn evse_clear_key(&self) -> Result<(), AfbError> {
        afb_log_msg!(Notice, None, "SlacSession:evse_clear_key");
        match self.state.try_borrow_mut() {
            Err(_) => return afb_error!("session-clear-key", "fail to access state"),
            Ok(mut state) => {
                    state.nid=[0; SLAC_NID_LEN];
                    state.pending= SlacRequest::CM_NONE;
                    state.status=SlacStatus::IDLE;
                }
        }
        Ok(())
    }

    pub fn decode<'a>(&self, msg: &'a SlacRawMsg) -> Result<SlacPayload<'a>, AfbError> {
        let payload = match msg.parse()? {
            //got CM_SET_KEY.CNF reply CM_SLAC_PARAM.CNF
            SlacPayload::SetKeyCnf(payload) => {
                afb_log_msg!(Notice, None, "SlacPayload::SetKeyCnf");
                match self.state.try_borrow() {
                    Err(_) => {
                        return afb_error!("session-set-key-cnf", "fail to access state")
                    }
                    Ok(state) => {
                        if payload.result != 0 || payload.your_nonce != state.nonce {
                            return afb_error!(
                                "session-set-key-cnf",
                                "invalid payload content",
                            )
                        }

                        // Fulup what to do with payload data ???
                    }
                }
                // should we wait for CM_SLAC_PARAM.REQ if then how long
                self.set_status(
                    SlacRequest::CM_SLAC_PARAM,
                    SlacStatus::WAITING,
                    self.config.timeout,
                )?;
                payload.as_slac_payload()?
            }

            //got CM_SLAC_PARAM.REQ reply CM_SLAC_PARAM.CNF
            SlacPayload::SlacParmReq(payload) => {
                afb_log_msg!(Notice, None, "SlacPayload::SlacParmReq");
                self.set_param_req(
                    &payload.run_id,
                    payload.application_type,
                    payload.application_type,
                )?;

                self.send_param_cnf()?;
                payload.as_slac_payload()?
            }

            // CM_MNBC_SOUND.IND (until sound_count or sound_timeout)
            SlacPayload::MnbcSoundInd(payload) => {
                // Time specified by the EV for the Characterization has expired
                // or num of total sounds is >= expected sounds thus, the Atten
                // data must be grouped and averaged before the loop is
                // terminated [V2G3-A09-19]
                afb_log_msg!(Notice, None, "SlacPayload::MnbcSoundInd");
                let remaining = match self.state.try_borrow_mut() {
                    Err(_) => {
                        return afb_error!("session-mnbc-sound", "fail to access state")
                    }
                    Ok(mut state) => {
                        if !matches!(state.pending, SlacRequest::CM_MNBC_SOUND) {
                            return afb_error!("session-mnbc-sound", "No sound expected")
                        }

                        if slice_equal(&payload.run_id, &state.runid)
                            || payload.security_type != state.security_type
                            || payload.application_type != state.application_type
                        {
                            return afb_error!(
                                "session-mnbc-sound",
                                "invalid payload content",
                            )
                        }
                        state.pevid = payload.pevid;
                        let count = payload.remaining_sound_count;

                        // We goot enough sound let compute attenuation groups
                        if count == 0 {
                            for idx in 0..state.avg_groups as usize {
                                state.avg_attn[idx] = state.avg_attn[idx] / state.agv_count;
                            }
                        }
                        count
                    }
                };

                // got all soundings reply with CM_ATTEN_CHAR.IND
                if remaining == 0 {
                    self.send_atten_char()?;
                }

                payload.as_slac_payload()?
            }

            // CM_SLAC_MATCH.REQ
            SlacPayload::SlacMatchReq(payload) => {
                afb_log_msg!(Notice, None, "SlacPayload::SlacMatchReq");
                match self.state.try_borrow_mut() {
                    Err(_) => {
                        return afb_error!(
                            "session-start-attend-char-ind",
                            "fail to access state",
                        )
                    }
                    Ok(mut state) => {
                        if slice_equal(&payload.run_id, &state.runid)
                            || payload.security_type != state.security_type
                            || payload.application_type != state.application_type
                        {
                            return afb_error!(
                                "session-start-attend-char-ind",
                                "invalid payload content",
                            )
                        }

                        // update PEV station identity
                        state.pevid = payload.pev_id;
                        state.pevmac = payload.pev_mac;
                    }
                }

                self.send_slac_match()?;
                payload.as_slac_payload()?
            }

            // CM_START_ATTEN_CHAR.IND (Broadcast Message)
            SlacPayload::StartAttentCharInd(payload) => {
                // As is stated in ISO15118-3, the EV will send 3 consecutive
                // CM_START_ATTEN_CHAR, regardless if the first one was correctly
                // received and processed. However, the PLC just forwards 1 to the
                // application, so we just need to process 1
                afb_log_msg!(Notice, None, "SlacPayload::StartAttentCharInd");
                match self.state.try_borrow_mut() {
                    Err(_) => {
                        return afb_error!(
                            "session-start-attend-char-ind",
                            "fail to access state",
                        )
                    }
                    Ok(mut state) => {
                        if slice_equal(&payload.run_id, &state.runid)
                            || payload.resp_type != cglue::CM_SLAC_PARM_CNF_RESP_TYPE
                            || payload.security_type != state.security_type
                            || payload.application_type != state.application_type
                        {
                            return afb_error!(
                                "session-start-attend-char-ind",
                                "invalid payload content",
                            )
                        }
                        state.pevmac = payload.forwarding_sta;
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
                        payload.timeout as u32 * 100
                    }
                };
                // set session to wait for sound messages
                payload.as_slac_payload()?
            }

            SlacPayload::AttenCharRsp(payload) => {
                // response to AttenCharInd
                afb_log_msg!(Notice, None, "SlacPayload::AttenCharRsp");
                match self.state.try_borrow() {
                    Err(_) => {
                        return afb_error!(
                            "session-atten-char-rsp",
                            "fail to access state",
                        )
                    }
                    Ok(state) => {
                        if slice_equal(&payload.run_id, &state.runid)
                            || payload.security_type != state.security_type
                            || payload.application_type != state.application_type
                        {
                            return afb_error!(
                                "session-atten-char-rsp",
                                "invalid payload content",
                            )
                        }
                    }
                };

                if payload.result != 0 {
                    return afb_error!(
                        "session-atten-char-rsp",
                        "invalid result status",
                    )
                }

                payload.as_slac_payload()?
            }

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
                afb_log_msg!(Notice, None, "SlacPayload::AttenProfileInd");
                match self.state.try_borrow_mut() {
                    Err(_) => {
                        return afb_error!(
                            "session-attend-profile",
                            "fail to access state",
                        )
                    }
                    Ok(mut state) => {
                        if slice_equal(&payload.pev_mac, &state.pevmac) {
                            return afb_error!(
                                "session-attend-profile",
                                "invalid source PEV Mac addr",
                            )
                        }

                        state.agv_count = state.agv_count + 1;
                        state.avg_groups = payload.num_groups;
                        for idx in 0..state.avg_groups as usize {
                            state.avg_attn[idx] = state.avg_attn[idx] + payload.aag[idx] as u32;
                        }
                    }
                };
                payload.as_slac_payload()?
            }

            _ => {
                return afb_error!(
                    "session-decode",
                    "unknown homeplug response mimetype ",
                )
            }
        };

        Ok(payload)
    }
}

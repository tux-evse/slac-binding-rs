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
 *
 * Note:
 *   messages definition documentation are copied from Switch PySlac implementation
 *   messages cglue::struct definition are copied from Pionix libslac implementation
 */

use crate::prelude::*;
use afbv4::prelude::*;
use std::fmt;
use std::mem;
use typesv4::prelude::*;

// export public types to rust world
pub const SLAC_NID_LEN: usize = cglue::NID_LEN as usize;
pub const SLAC_NMK_LEN: usize = cglue::NMK_LEN as usize;
pub const SLAC_STATID_LEN: usize = cglue::PEV_ID_LEN as usize;
pub const ETHER_ADDR_LEN: usize = cglue::ETHER_ADDR_LEN as usize;
pub const SLAC_AGGGROUP_LEN: usize = cglue::AAG_LIST_LEN as usize;
pub const SLAC_RUNID_LEN: usize = cglue::RUN_ID_LEN as usize;

pub type SlacNid = [u8; SLAC_NID_LEN];
pub type SlacNmk = [u8; SLAC_NMK_LEN];
pub type SlacIfMac = [u8; ETHER_ADDR_LEN];
pub type SlacRunId = [u8; SLAC_RUNID_LEN];
pub type SlacGroups = [u8; SLAC_AGGGROUP_LEN];
pub type SlacStaId = [u8; SLAC_STATID_LEN];
pub const BROADCAST_ADDR: SlacIfMac = [0xFF; ETHER_ADDR_LEN];
pub const ATHEROS_MAC_ADDR: SlacIfMac = [0x00, 0xb0, 0x52, 0x00, 0x00, 0x01];

#[allow(non_camel_case_types)]
#[derive(Clone, Copy, Debug)]
#[repr(u16)]
pub enum SlacRequest {
    CM_SET_KEY_REQ = cglue::MMTYPE_CM_SET_KEY | cglue::MMTYPE_MODE_REQ,
    CM_SET_KEY_CNF = cglue::MMTYPE_CM_SET_KEY | cglue::MMTYPE_MODE_CNF,
    CM_START_ATTENT_IND = cglue::MMTYPE_CM_START_ATTEN_CHAR | cglue::MMTYPE_MODE_IND,
    CM_SLAC_PARAM_REQ = cglue::MMTYPE_CM_SLAC_PARAM | cglue::MMTYPE_MODE_REQ,
    CM_SLAC_PARAM_CNF = cglue::MMTYPE_CM_SLAC_PARAM | cglue::MMTYPE_MODE_CNF,
    CM_SLAC_MATCH_CNF = cglue::MMTYPE_CM_ATTEN_CHAR | cglue::MMTYPE_MODE_CNF,
    CM_SLAC_MATCH_REQ = cglue::MMTYPE_CM_ATTEN_CHAR | cglue::MMTYPE_MODE_REQ,
    CM_MNBC_SOUND_IND = cglue::MMTYPE_CM_MNBC_SOUND | cglue::MMTYPE_MODE_IND,
    CM_ATTEN_CHAR_IND = cglue::MMTYPE_CM_ATTEN_CHAR | cglue::MMTYPE_MODE_IND,
    CM_ATTEN_CHAR_PROFILE_IND= cglue::MMTYPE_CM_ATTEN_PROFILE | cglue::MMTYPE_MODE_IND,

    CM_NONE = 0, // nothing pending
}

impl SlacRequest {
    pub fn from_u16(value: u16) -> Self {
        unsafe { std::mem::transmute(value) }
    }
}

// To enforce C packing SlacRaw msg is defined within C header
pub type SlacRawMsg = cglue::cm_slac_raw_msg;

// Associated with CM_SET_KEY.REQ, defined in chapter 11.5.4 of the HPGP
// standard. Check also table page 586, table 11-87
// Also table A.8 from ISO15118-3
// EVSE/PEV -> HPGP Node
// This payload is defined as follows:
// |KeyType|MyNonce|YourNonce|PID|PRN|PMN|CCoCap|NID|NewEKS|NewKey|

// KeyType [1 byte] = 0x01: Fixed value to indicate NMK
// MyNonce [4 bytes] = 0x00000000: Fixed value, used by the emitter of the
//                                 message and fixed over one session.
//                                 If in another message, the receiver receives
//                                 a different value, then it may consider
//                                 that the communication was compromised
// YourNonce [4 bytes] = 0x00000000: Fixed value, encrypted payload not used.
//                                   This field has the same rationale as
//                                   MyNonce but in the opposite direction
//                                   of the communication
// PID [1 byte] = 0x04: Fixed value to indicate "HLE protocol"
// PRN [2 bytes] = 0x0000: Fixed value, encrypted payload not used
// PMN [1 byte] = 0x00: Fixed value, encrypted payload not used
// CCo Capability [1 byte] = 0x00 : CCo Capability according to station role;
//                                  Ususally the value is variable, but is used
// NID [7 bytes]: 54 LSBs contain the Network identifier and the rest is 0b00
//                Network ID derived from the NMK by the EVSE according to
//                [HPGP], 4.4.3.1
// NewEKS [1 byte] = 0x01: Fixed value to indicate NMK
// NewKey [16 bytes]: NMK (Network Mask, random value per session)
// Message size is = 44 bytes
pub type SetKeyReq = cglue::cm_set_key_req;
impl SetKeyReq {
    pub fn send(self, sock: &SockRaw, dstaddr: &SlacIfMac) -> Result<(), AfbError> {
        let rqt = SlacRawMsg {
            ethernet: cglue::ether_header::new(sock, dstaddr),
            homeplug: cglue::homeplug_header::new(cglue::MMTYPE_CM_SET_KEY),
            payload: cglue::cm_slac_payload { set_key_req: self },
        };
        let size = mem::size_of::<cglue::ether_header>()
            + mem::size_of::<cglue::homeplug_header>()
            + mem::size_of::<cglue::cm_set_key_req>();

        rqt.send(sock, size)?;
        Ok(())
    }
}
impl fmt::Display for SetKeyReq {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        // because of packet unaligned struct we need to copy values
        let my_nonce = self.my_nonce;
        let your_nonce = self.your_nonce;
        let prn = self.prn;
        let text = format!(
            "SetKeyReq:{{ key_type:{}, my_nonce:{:02x?}, your_nonce:{:02X?}, pid:{:02X?}, prn:{:02X?}, cco:{:02X?}, nid:{:02X?}, new_key:{:02X?} }}",
            self.key_type, my_nonce, your_nonce, self.pid, prn, self.cco_capability, self.nid,self.new_key
        );
        fmt.pad(&text)
    }
}

// Associated with CM_SET_KEY.CNF, defined in chapter 11.5.5 of the HPGP
// standard. Check also table page 586, table 11-87
// Also table A.8 from ISO15118-3
// HPGP Node -> EVSE/PEV
// This payload is defined as follows:
// |Result|MyNonce|YourNonce|PID|PRN|PMN|CCoCap|

// Result [1 byte]: 0x00 - Success, 0x01 - Failure
// MyNonce [4 bytes]: Random number that will be used to verify next message
//                    from other end; in encrypted portion of payload.
// YourNonce [4 bytes]: Last nonce received from recipient; it will be used
//                      by recipient to verify this message;
//                      in encrypted portion of payload.
// PID [1 byte]: Protocol for which Set Key is confirmed
// PRN [2 bytes]: Protocol Run Number (refer to Section 11.5.2.4)
// PMN [1 byte]: Protocol Message Number (refer to Section 11.5.2.5
// CCo Capability [1 byte]: The two LSBs of this field contain the STA’s
//                          CCo capability. The interpretation of these bits
//                          is the same as in Section 4.4.3.13.4.6.2.
//                          The six MSBs of this field are set to 0b000000
// Message size is = 14 bytes
pub type SetKeyCnf = cglue::cm_set_key_cnf;
impl SetKeyCnf {
    pub fn as_slac_payload(&self) -> Result<SlacPayload, AfbError> {
        Ok(SlacPayload::SetKeyCnf(&self))
    }

    pub fn send(self, sock: &SockRaw, dstaddr: &SlacIfMac) -> Result<(), AfbError> {
        let rqt = SlacRawMsg {
            ethernet: cglue::ether_header::new(sock, dstaddr),
            homeplug: cglue::homeplug_header::new(
                cglue::MMTYPE_CM_SET_KEY | cglue::MMTYPE_MODE_CNF,
            ),
            payload: cglue::cm_slac_payload { set_key_cnf: self },
        };
        let size = mem::size_of::<cglue::ether_header>()
            + mem::size_of::<cglue::homeplug_header>()
            + mem::size_of::<cglue::cm_set_key_req>();

        rqt.send(sock, size)?;
        Ok(())
    }
}
impl fmt::Display for SetKeyCnf {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        // because of packet unaligned struct we need to copy values
        let my_nonce = self.my_nonce;
        let your_nonce = self.your_nonce;
        let prn = self.prn;
        let text = format!(
            "SetKeyCnf:{{ result:{:02X?}, my_nonce:{:#0x?}, your_nonce:{:#0x?}, pid:{:02X?}, prn:{:02X?}, cco:{:02X?} }}",
            self.result, my_nonce, your_nonce, self.pid, prn, self.cco_capability
        );
        fmt.pad(&text)
    }
}

// CM_START_ATTEN_CHAR.IND in chapter 11.5.47 of the HPGP
// Broadcast Message PEV -> EVSE
// This payload is defined as follows originally :
// |Application Type|Security Type| NUM_SOUNDS| Time_Out| RESP_TYPE |
// |FORWARDING_STA |RunID|
// Application Type [1 byte]: 0x00 Fixed value indicating 'PEV- EVSE matching'
// Security Type [1 bytes]: 0x00 Fixed value indicating 'No Security'
// The following parameters are under a nested field called in the HPGP
// standard as ACVarField (Attenuation Characterization Variable Field)
// NUM_SOUNDS [1 byte]: Number of M-Sounds transmitted by the GP station
//                      during the SLAC process
// Time_Out [1 byte]: Max time window on which the M-Sounds are sent,
//                    associated with TT_EVSE_match_MNBC of the spec and
//                    SLAC_ATTEN_TIMEOUT of enums.py. Multiple of 100 ms, i.e.,
//                    if Time_Out = 6, it means the timeout is equal to 600ms
// RESP_TYPE [1 byte] - SLAC_RESP_TYPE: Fixed value indicating
//                                      'Other Green PHY station'
// FORWARDING_STA [6 bytes]: EV Host MAC; The destination of SLAC results is
//                           always the EV Host
// RunID [8 bytes]: This value shall be the same as the one in
//                  CM_SLAC_PARM.REQ message sent by the EV
// Message size is = 19 bytes
pub type StartAttentCharInd = cglue::cm_start_atten_char_ind;
impl StartAttentCharInd {
    pub fn as_slac_payload(&self) -> Result<SlacPayload, AfbError> {
        Ok(SlacPayload::StartAttentCharInd(self))
    }
}
impl fmt::Display for StartAttentCharInd {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = format!(
            "StartAttentCharInd:{{ app_type:{:02X?}, security:{:02X?}, num_sound:{}, timeout:{}, resp_type:{:02X?}, forwarding_stat:{:02X?}, runid:{:02X?} }}",
            self.application_type, self.security_type, self.num_sounds, self.timeout, self.resp_type, self.forwarding_sta, self.run_id
        );
        fmt.pad(&text)
    }
}

// CM_SLAC_PARM.REQ, defined in chapter 11.5.45 of the HPGP
// Broadcast Message PEV -> EVSE
// standard. Check also table page 586, table 11-87
// Also table A.2 from ISO15118-3
// This payload is defined as follows originally :
// |Application Type|Security Type|Run ID|CipherSuiteSetSize| CipherSuite..
// Application Type [1 byte]: 0x00 Fixed value indicating 'PEV- EVSE matching'
// Security Type [1 bytes]: 0x00 Fixed value indicating 'No Security'
// Run ID [8 bytes]: Identifier for a matching run, randomly chosen by
//                   the EV for each CM_SLAC_PARM.REQ message and constant
//                   for all following messages of the same run
// CipherSuiteSetSize [1 byte]: Number of supported cipher suites N.
// CipherSuite [1] [2 bytes]: First supported cipher suite.
// CipherSuite [N] [2 bytes]: Nth supported cipher suite.
// However, since Security Type is set as 0x00, Cipher suit is not used, thus
// the payload resumes to:
// |Application Type|Security Type|Run ID|
// Message size is = 10 bytes
pub type SlacParmReq = cglue::cm_slac_parm_req;
impl SlacParmReq {
    pub fn as_slac_payload(&self) -> Result<SlacPayload, AfbError> {
        Ok(SlacPayload::SlacParmReq(self))
    }
}
impl fmt::Display for SlacParmReq {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = format!(
            "SlacParmReq:{{ app_type:{:02x?}, security:{:02x?},runid:{:02X?} }}",
            self.application_type, self.security_type, self.run_id
        );
        fmt.pad(&text)
    }
}
// PEV-HLE broadcasts CM_SLAC_PARM requests until at least one
// Unicast Message EVSE -> PEV
// matching CM_SLAC_PARM confirm is received; matching confirm
// has the same run identifier; EVSE-HLE returns information to
// the PEV-HLE;
// Associated with CM_SLAC_PARM.CNF, defined in chapter 11.5.46 of the HPGP
// standard. Check table page 586, table 11-87 also table A.2 from ISO15118-3
// This payload is defined as follows, originally :
// | M-SOUND_TARGET | NUM_SOUNDS| Time_Out| RESP_TYPE |
// |FORWARDING_STA | APPLICATION_TYPE| SECURITY_TYPE| RunID| *CipherSuite*
// M-SOUND_TARGET [6 byte] - 0xFFFFFFFFFFFF: Indicates the MAC address of the
//                                             GP STA with which the STA shall
//                                             initiate the Signal Level
//                                             Attenuation Characterization
//                                             Process.Fixed value indicating
//                                             that M-Sounds to be sent as
//                                             Ethernet broadcast
// NUM_SOUNDS [1 byte] - SLAC_MSOUNDS: Number of expected M-Sounds
//                                     transmitted by the GP station
//                                     during the SLAC process
// Time_Out [1 byte] - SLAC_ATTEN_TIMEOUT: Duration TT_EVSE_match_MNBC while
//                                         the EVSE receives incoming M-SOUNDS
//                                         after a CM_START_ATTEN_CHAR.IND. On
//                                         other words, indicates the amount of
//                                         time within which the GP STA will
//                                         complete the transmission of SOUND
//                                         MPDUs during the Signal Level
//                                         Attenuation Characterization Process.
//                                         The time is in multiples of 100 msec.
//                                         E.g, Time_Out = 6 corresponds to 600ms
// RESP_TYPE [1 byte] - SLAC_RESP_TYPE: Fixed value indicating 'Other GP station'
//                                         Indicates whether the recipient of the
//                                         SOUND MPDUs shall communicate the signal
//                                         attenuation characteristic profile data to
//                                         the HLE or another GP STA.
// FORWARDING_STA [6 bytes]: EV Host MAC; The destination of SLAC results is
//                             always the EV Host. Only valid if RESP_TYPE = 0x01
// APPLICATION_TYPE [1 byte] - 0x00: Fixed value indicating 'PEV-EVSE Matching'
// SECURITY_TYPE [1 byte] - 0x00: Fixed value indicating “No Security”
// RunID [8 bytes]: This value shall be the same as the one sent in the
//                     CM_SLAC_PARM.REQ message by the EV
// * CipherSuite [2 bytes] *: Selected Cipher Suite
// *Since Security Type is 0x00, CipherSuite wont be present in the payload
// Message size is = 25 bytes
pub type SlacParmCnf = cglue::cm_slac_parm_cnf;
impl SlacParmCnf {
    pub fn send(self, sock: &SockRaw, pevaddr: &SlacIfMac) -> Result<(), AfbError> {
        let rqt = SlacRawMsg {
            ethernet: cglue::ether_header::new(sock, pevaddr),
            homeplug: cglue::homeplug_header::new(
                cglue::MMTYPE_CM_SLAC_PARAM | cglue::MMTYPE_MODE_CNF,
            ),
            payload: cglue::cm_slac_payload {
                slac_parm_cnf: self,
            },
        };
        let size = mem::size_of::<cglue::ether_header>()
            + mem::size_of::<cglue::homeplug_header>()
            + mem::size_of::<cglue::cm_slac_parm_cnf>();
        rqt.send(sock, size)?;
        Ok(())
    }

    pub fn as_slac_payload(&self) -> Result<SlacPayload, AfbError> {
        Ok(SlacPayload::SlacParmCnf(self))
    }
}
impl fmt::Display for SlacParmCnf {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = format!(
            "SlacParmCnf:{{ m_sound_target:{:02x?}, num_sounds:{}, timeout:{}, resp_type:{:02X?}, forwarding_stat:{:02X?}, app_type:{:02x}, sec_type:{:02x}, runid:{:02X?} }}",
            self.m_sound_target, self.num_sounds, self.timeout, self.resp_type, self.forwarding_sta, self.application_type, self.security_type, self.run_id
        );
        fmt.pad(&text)
    }
}

// CM_MNBC_SOUND.IND in chapter 11.5.54 of the HPGP
// PEV -> EVSE (HPGP Node) Broadcast Message
// standard. Check table page 586, table 11-87, also table A.4 from ISO15118-3
// This payload is defined as follows, originally :
// |Application Type|Security Type|SenderID|Cnt|RunID|RSVD|Rnd|
// Application Type [1 byte]: 0x00 Fixed value indicating 'PEV- EVSE matching'
// Security Type [1 bytes]: 0x00 Fixed value indicating 'No Security'
// The following parameters are under a nested field called in the HPGP
// standard as MSVarField (MNBC Sound Variable Field)
// SenderID [17 bytes] - 0x00: Sender’s Identification. According to HPGP:
//                             If APPLICATION_TYPE=0x00 then Sender ID is
//                             PEV’s VIN code.
//                             But 15118-3 defines it as 0x00
// Cnt [1 byte]: Countdown counter for number of Sounds remaining
// According to HPGP spec, RunID has 16 Bytes, but 15118-3 just uses 8 bytes,
// so the other 8 are set to 0x00 and are reserved
// RunID [8 bytes]: This value shall be the same as the one in
//                  CM_SLAC_PARM.REQ message sent by the EV
// RSVD [8 bytes] - 0x00: Reserved
// Rnd [16 bytes]: Random Value
// Message size is = 52 bytes
pub type MnbcSoundInd = cglue::cm_mnbc_sound_ind;
impl MnbcSoundInd {
    pub fn as_slac_payload(&self) -> Result<SlacPayload, AfbError> {
        Ok(SlacPayload::MnbcSoundInd(self))
    }
}
impl fmt::Display for MnbcSoundInd {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = format!(
            "MnbcSoundInd:{{ app_type:{:02x},sec_type:{:02x}, pevid:{:02X?}, remaining_sound_count:{}, runid:{:02X?}, random:{:02X?} }}",
            self.application_type, self.security_type,self.pevid, self.remaining_sound_count,  self.run_id, self.random
        );
        fmt.pad(&text)
    }
}

// CM_ATTEN_PROFILE.IND
// Sent by the HLE (HighLevel Entity/PLC chip) to the EVSE host application
// Standard table A.4 from ISO15118-3
// This payload is defined as follows originally :
// |PEV MAC|NumGroups|RSVD|AAG 1| AAG 2| AAG 3...|
// PEV MAC [6 byte]: MAC address of EV Host
// NumGroups [1 bytes]: 0x3A Number of OFDM carrier groups used for the SLAC
//                           signal characterization.
// RSVD [1 bytes] - 0x00: Reserved
// AAG 1 [1 byte]: Average Attenuation of Group 1
// AAG Nth [1 byte]: Average Attenuation of Group Nth
// Message size is = 66 bytes
pub type AttenProfileInd = cglue::cm_atten_profile_ind;
impl AttenProfileInd {
    pub fn as_slac_payload(&self) -> Result<SlacPayload, AfbError> {
        Ok(SlacPayload::AttenProfileInd(self))
    }
}
impl fmt::Display for AttenProfileInd {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = format!(
            "AttenProfileInd:{{ pev_mac:{:02X?}, num_groups:{}, aag:{:02X?} }}",
            self.pev_mac, self.num_groups, self.aag
        );
        fmt.pad(&text)
    }
}

// CM_ATTEN_CHAR.IND in chapter 11.5.48 of the HPGP
// Unicast Message EVSE -> PEV
// With this message, the EVSE shares with the PEV,
// the results of the sounds received per group
// standard. Check table page 586, table 11-87 also table A.4 from ISO15118-3
// This payload is defined as follows originally :
// |Application Type|Security Type| SOURCE_ADDRESS| RunID| SOURCE_ID| RESP_ID|
// |NumSounds| ATTEN_PROFILE|
// ATTEN_PROFILE = |NumGroups|AAG 1| AAG 2| AAG 3...|
// Application Type [1 byte]: 0x00 Fixed value indicating 'PEV- EVSE matching'
// Security Type [1 bytes]: 0x00 Fixed value indicating 'No Security'
// The following parameters are under a nested field called in the HPGP
// standard as ACVarField (Attenuation Characterization Variable Field)
// SOURCE_ADDRESS [6 bytes]: MAC Address of EV Host which initiated the SLAC
// RunID [8 bytes]: This value shall be the same as the one in
//                  CM_SLAC_PARM.REQ message sent by the EV
// SOURCE_ID [17 bytes] - 0x00...00: - The unique identifier of the station
//                                     that sent the M-Sounds (not used by ISO)
// RESP_ID [17 bytes] - 0x00...00: - The unique identifier of the station that
//                                   is sending this message (not used by ISO)
// NUM_SOUNDS [1 byte]: Number of M-Sounds used for generation of the
//                      ATTEN_PROFILE
// ATTEN_PROFILE [59 bytes]: Signal Level Attenuation (Field format in table
//                           'ATTEN_PROFILE' of [HPGP])
//                           ATTEN_PROFILE = |NumGroups|AAG 1| AAG 2| AAG 3...|
// Message size is = 110 bytes
pub type AttenCharInd = cglue::cm_atten_char_ind;
impl AttenCharInd {
    pub fn send(self, sock: &SockRaw, pevaddr: &SlacIfMac) -> Result<(), AfbError> {
        let rqt = SlacRawMsg {
            ethernet: cglue::ether_header::new(sock, pevaddr),
            homeplug: cglue::homeplug_header::new(cglue::MMTYPE_CM_SET_KEY),
            payload: cglue::cm_slac_payload {
                atten_char_ind: self,
            },
        };

        let size = mem::size_of::<cglue::ether_header>()
            + mem::size_of::<cglue::homeplug_header>()
            + mem::size_of::<cglue::cm_atten_char_ind>();
        rqt.send(sock, size)?;
        Ok(())
    }

    pub fn as_slac_payload(&self) -> Result<SlacPayload, AfbError> {
        Ok(SlacPayload::AttenCharInd(self))
    }
}
impl fmt::Display for AttenCharInd {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = format!(
            "AttenCharInd:{{ app_type:{:02x}, sec_type:{:02x}, source_address:{:02X?}, run_id:{:02X?}, source_id:{:02X?}, resp_id:{:02X?}, num_sound:{}, agg_num:{}, agg_list:{:02X?} }}",
            self.application_type, self.security_type,self.source_address, self.run_id,  self.source_id, self.resp_id, self.num_sounds, self.attenuation_profile.num_groups, self.attenuation_profile.aag
        );
        fmt.pad(&text)
    }
}

// CM_ATTEN_CHAR.RSP in chapter 11.5.49 of the HPGP
// Unicast Message PEV -> EVSE
// standard. Check table page 586, table 11-87 also table A.4 from ISO15118-3
// This payload is defined as follows originally :
// |Application Type|Security Type| SOURCE_ADDRESS| RunID| SOURCE_ID| RESP_ID|
// |Result|
// Application Type [1 byte]: 0x00 Fixed value indicating 'PEV- EVSE matching'
// Security Type [1 bytes]: 0x00 Fixed value indicating 'No Security'
// The following parameters are under a nested field called in the HPGP
// standard as ACVarField (Attenuation Characterization Variable Field)
// SOURCE_ADDRESS [6 bytes]: MAC Address of EV Host which initiated the SLAC
// RunID [8 bytes]: This value shall be the same as the one in
//                     CM_SLAC_PARM.REQ message sent by the EV
// SOURCE_ID [17 bytes] - 0x00: - HPGP defines it as the unique identifier
//                                 from the station that sent the M-sounds.
//                                 ISO15118-3 defines it as 0x00
// RESP_ID [17 byte] - 0x00: - HPGP defines it as the unique identifier
//                             of the station that is sending this message.
//                             ISO15118-3 defines it as 0x00
// Result [1 byte] - 0x00: Fixed value of 0x00 indicates a successful SLAC
//                         process
// Message size is = 43 bytes
pub type AttenCharRsp = cglue::cm_atten_char_rsp;
impl AttenCharRsp {
    pub fn as_slac_payload(&self) -> Result<SlacPayload, AfbError> {
        Ok(SlacPayload::AttenCharRsp(self))
    }
}
impl fmt::Display for AttenCharRsp {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = format!(
            "AttenCharRsp:{{ app_type:{:02x},sec_type:{:02x}, source_address:{:02X?}, run_id:{:02X?}, source_id:{:02X?}, resp_id:{:02X?}, result:{:02X?} }}",
            self.application_type, self.security_type,self.source_address, self.run_id,  self.source_id, self.resp_id, self.result
        );
        fmt.pad(&text)
    }
}
// Associated with CM_SLAC_MATCH.REQ in chapter 11.5.57 of the HPGP
// Unicast Message PEV -> EVSE
// standard. Check table A.7 from ISO15118-3
// This payload is defined as follows originally :
// |Application Type|Security Type| MVFLength| PEV_ID| PEV_MAC| EVSE_ID|
// EVSE MAC|RunID|RSVD|
// Application Type [1 byte] - 0x00: Fixed value indicating 'PEV- EVSE matching'
// Security Type [1 bytes] - 0x00: Fixed value indicating 'No Security'
// MVFLength [2 bytes] - 0x3e: (Fixed value) Match Variable Field Length
// The following parameters are under a nested field called in the HPGP
// standard as MatchVarField (Match Variable Field)
// PEV ID [17 bytes] - 0x00:
// PEV MAC [6 bytes]: MAC Address of the EV Host
// EVSE ID [17 bytes] - 0x00:
// EVSE MAC [6 bytes]: MAC Address of the EVSE Host
// RunID [8 bytes]: This value shall be the same as the one in
//                     CM_SLAC_PARM.REQ message sent by the EV
// RSVD [8 bytes] - 0x00: Reserved
pub type SlacMatchReq = cglue::cm_slac_match_req;
impl SlacMatchReq {
    pub fn as_slac_payload(&self) -> Result<SlacPayload, AfbError> {
        Ok(SlacPayload::SlacMatchReq(self))
    }
}
impl fmt::Display for SlacMatchReq {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        // because of packet unaligned struct we need to copy values
        let mvf_length = self.mvf_length;
        let text = format!(
            "SlacMatchReq:{{ app_type:{:02x}, sec_type:{:02x}, mvf_len:{}, pev_id:{:02X?}, pev_mac:{:02X?}, evse_id:{:02X?}, evse_mac:{:02X?}, run_id:{:02X?} }}",
            self.application_type, self.security_type,mvf_length, self.pev_id,  self.pev_mac, self.evse_id, self.evse_mac, self.run_id
        );
        fmt.pad(&text)
    }
}

// CM_SLAC_MATCH.CNF in chapter 11.5.58 of the HPGP
// Unicast EVSE -> PEV
// standard. Check table A.7 from ISO15118-3
// The selected EVSE responses to the EV request with a CM_SLAC_MATCH.CNF,
// which contains all parameters to be set to join the logical network of
// the EVSE.
// This payload is defined as follows originally:
// |Application Type|Security Type| MVFLength| PEV_ID| PEV_MAC| EVSE_ID|
// EVSE MAC|RunID|RSVD1|NID|RSVD2|NMK
// Application Type [1 byte] - 0x00: Fixed value indicating 'PEV- EVSE matching'
// Security Type [1 bytes] - 0x00: Fixed value indicating 'No Security'
// MVFLength [2 bytes] - 0x56: (Fixed value) Match Variable Field Length
// The following parameters are under a nested field called in the HPGP
// standard as MatchVarField (Match Variable Field)
// PEV ID [17 bytes] - 0x00:
// PEV MAC [6 bytes]: MAC Address of the EV Host
// EVSE ID [17 bytes] - 0x00:
// EVSE MAC [6 bytes]: MAC Address of the EVSE Host
// RunID [8 bytes]: This value shall be the same as the one in
//                     CM_SLAC_PARM.REQ message sent by the EV
// RSVD1 [8 bytes] - 0x00: Reserved
// NID [7 bytes]: Network ID derived from the NMK by the EVSE
//                 according to [HPGP], 4.4.3.1
// RSVD2 [8 bytes] - 0x00: Reserved
// NMK [16 bytes]: Private Network Membership Key of the EVSE (random value)
// Message size is = 97 bytes
pub type SlacMatchCnf = cglue::cm_slac_match_cnf;
impl SlacMatchCnf {
    pub fn send(self, sock: &SockRaw, pev_addr: &SlacIfMac) -> Result<(), AfbError> {
        let rqt = SlacRawMsg {
            ethernet: cglue::ether_header::new(sock, pev_addr),
            homeplug: cglue::homeplug_header::new(cglue::MMTYPE_CM_SET_KEY),
            payload: cglue::cm_slac_payload {
                slac_match_cnf: self,
            },
        };
        let size = mem::size_of::<cglue::ether_header>()
            + mem::size_of::<cglue::homeplug_header>()
            + mem::size_of::<cglue::cm_slac_match_cnf>();
        rqt.send(sock, size)?;
        Ok(())
    }

    pub fn as_slac_payload(&self) -> Result<SlacPayload, AfbError> {
        Ok(SlacPayload::SlacMatchCnf(self))
    }
}
impl fmt::Display for SlacMatchCnf {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        // because of packet unaligned struct we need to copy values
        let mvf_length = self.mvf_length;
        let text = format!(
            "SlacMatchCnf:{{ app_type:{:02x}, sec_type:{:02x}, mvf_len:{}, pev_id:{:02X?}, pev_mac:{:02X?}, evse_id:{:02X?}, evse_mac:{:02X?}, run_id:{:02X?}, nid:{:02X?}, nmk:{:02X?} }}",
            self.application_type, self.security_type,mvf_length, self.pev_id,  self.pev_mac, self.evse_id, self.evse_mac, self.run_id, self.nid, self.nmk
        );
        fmt.pad(&text)
    }
}

// Slac generic messages enum payload
pub enum SlacPayload<'a> {
    SetKeyReq(&'a SetKeyReq),
    SetKeyCnf(&'a SetKeyCnf),
    SlacParmReq(&'a SlacParmReq),
    SlacParmCnf(&'a SlacParmCnf),
    StartAttentCharInd(&'a StartAttentCharInd),
    MnbcSoundInd(&'a MnbcSoundInd),
    AttenProfileInd(&'a AttenProfileInd),
    AttenCharInd(&'a AttenCharInd),
    AttenCharRsp(&'a AttenCharRsp),
    SlacMatchReq(&'a SlacMatchReq),
    SlacMatchCnf(&'a SlacMatchCnf),
}

impl<'a> fmt::Display for SlacPayload<'a> {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        // because of packet unaligned struct we need to copy values
        match self {
            SlacPayload::SetKeyReq(payload) => payload.fmt(fmt),
            SlacPayload::SetKeyCnf(payload) => payload.fmt(fmt),
            SlacPayload::SlacParmReq(payload) => payload.fmt(fmt),
            SlacPayload::SlacParmCnf(payload) => payload.fmt(fmt),
            SlacPayload::StartAttentCharInd(payload) => payload.fmt(fmt),
            SlacPayload::MnbcSoundInd(payload) => payload.fmt(fmt),
            SlacPayload::AttenProfileInd(payload) => payload.fmt(fmt),
            SlacPayload::AttenCharInd(payload) => payload.fmt(fmt),
            SlacPayload::AttenCharRsp(payload) => payload.fmt(fmt),
            SlacPayload::SlacMatchReq(payload) => payload.fmt(fmt),
            SlacPayload::SlacMatchCnf(payload) => payload.fmt(fmt),
        }
    }
}

impl SlacRawMsg {
    pub fn read(socket: &SockRaw) -> Result<SlacRawMsg, AfbError> {
        let mut rqt: SlacRawMsg = unsafe { mem::zeroed() };
        socket.read(&mut rqt)?;
        if rqt.ethernet.get_type() != cglue::ETH_P_HOMEPLUG_GREENPHY {
            return afb_error!("SetKeyCnf-read-fail", "invalid ether type");
        }

        if rqt.homeplug.mmv != cglue::MMV_HOMEPLUG_GREENPHY {
            return afb_error!("SetKeyCnf-read-fail", "invalid homeplug type",);
        }
        Ok(rqt)
    }

    pub fn send(&self, socket: &SockRaw, len: usize) -> Result<(), AfbError> {
        let buffer = self as *const _ as *const ::std::os::raw::c_void;
        socket.write(buffer, len)?;
        Ok(())
    }

    pub fn get_srcmac<'a>(&'a self) -> &'a SlacIfMac {
        &self.ethernet.ether_shost
    }

    pub fn get_homeplug<'a>(&'a self) -> &'a cglue::homeplug_header {
        &self.homeplug
    }

    // parse message mimetype and return a Rust typed payload
    pub fn mime_parse<'a>(&'a self) -> Result<SlacPayload, AfbError> {
        let payload = match SlacRequest::from_u16(self.homeplug.get_mmtype()) {
            SlacRequest::CM_SET_KEY_CNF => {
                SlacPayload::SetKeyCnf(unsafe { &self.payload.set_key_cnf })
            }
            SlacRequest::CM_SET_KEY_REQ => {
                SlacPayload::SetKeyReq(unsafe { &self.payload.set_key_req })
            }
            SlacRequest::CM_START_ATTENT_IND => {
                SlacPayload::StartAttentCharInd(unsafe { &self.payload.start_atten_char_ind })
            }
            SlacRequest::CM_SLAC_PARAM_REQ => {
                SlacPayload::SlacParmReq(unsafe { &self.payload.slac_parm_req })
            }
            SlacRequest::CM_SLAC_PARAM_CNF => {
                SlacPayload::SlacParmCnf(unsafe { &self.payload.slac_parm_cnf })
            }
            SlacRequest::CM_MNBC_SOUND_IND => {
                SlacPayload::MnbcSoundInd(unsafe { &self.payload.mnbc_sound_ind })
            }
            SlacRequest::CM_ATTEN_CHAR_IND => {
                SlacPayload::AttenCharInd(unsafe { &self.payload.atten_char_ind })
            }
            SlacRequest::CM_ATTEN_CHAR_PROFILE_IND => {
                SlacPayload::AttenProfileInd(unsafe { &self.payload.atten_profile_ind })
            }
            SlacRequest::CM_SLAC_MATCH_CNF => {
                SlacPayload::SlacMatchCnf(unsafe { &self.payload.slac_match_cnf })
            }

            _ => {
                return afb_error!(
                    "slac-msg-parse",
                    "unsupport message mmype:{:#04x}",
                    self.homeplug.get_mmtype()
                )
            }
        };
        Ok(payload)
    }
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
pub fn send_set_key_req(session: &SlacSession, state: &mut SessionState) -> Result<(), AfbError> {
    afb_log_msg!(Notice, None, "SlacSession:send_set_key_req");
    let nid = session.mk_nid_from_nmk();
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
        new_key: session.config.nmk,
    };

    payload.send(&session.socket, &ATHEROS_MAC_ADDR)?;
    state.nonce = nonce;
    state.nid = nid;
    state.pending = SlacRequest::CM_SLAC_PARAM_REQ;
    state.timeout = session.config.timeout;
    state.status = SlacStatus::IDLE;

    Ok(())
}

pub fn send_set_key_cnf(
    session: &SlacSession,
    state: &mut SessionState,
    remote_nonce: u32,
) -> Result<(), AfbError> {
    afb_log_msg!(Notice, None, "SlacSession:send_set_key_cnf");
    let nonce: u32 = GetTime::mk_nonce();

    let payload = cglue::cm_set_key_cnf {
        my_nonce: nonce,
        your_nonce: remote_nonce,
        pid: cglue::CM_SET_KEY_REQ_PID_HLE,
        prn: htole16(cglue::CM_SET_KEY_REQ_PRN_UNUSED), // enforce big indian (zero does not need conversion)
        pmn: cglue::CM_SET_KEY_REQ_PMN_UNUSED,
        cco_capability: cglue::CM_SET_KEY_REQ_CCO_CAP_NONE,
        result: 0,
        padding: [0; 3],
    };

    state.pending = SlacRequest::CM_NONE;
    state.timeout = session.config.timeout;
    state.status = SlacStatus::IDLE;

    payload.send(&session.socket, &state.pev_addr)?;
    Ok(())
}

// CM_SLAC_PARAM.CNF
pub fn send_slac_param_cnf(
    session: &SlacSession,
    state: &mut SessionState,
) -> Result<(), AfbError> {
    afb_log_msg!(Notice, None, "SlacSession:send_slac_param_cnf");

    let payload = SlacParmCnf {
        application_type: state.application_type,
        security_type: state.security_type,
        run_id: state.runid.clone(),
        m_sound_target: state.pev_addr.clone(),
        num_sounds: SLAC_MSOUNDS,
        timeout: SLAC_INIT_TIMEOUT,
        resp_type: cglue::CM_SLAC_PARM_CNF_RESP_TYPE,
        forwarding_sta: state.pev_addr.clone(),
    };

    state.pending = SlacRequest::CM_START_ATTENT_IND;
    state.timeout = SLAC_RESP_TIMEOUT;
    state.status = SlacStatus::WAITING;

    payload.send(&session.socket, &state.pev_addr)?;
    Ok(())
}

pub fn send_atten_char_ind(
    session: &SlacSession,
    state: &mut SessionState,
) -> Result<(), AfbError> {
    afb_log_msg!(Notice, None, "SlacSession:send_atten_char_ind");

    let mut agg_group: SlacGroups = [0 as u8; SLAC_AGGGROUP_LEN];
    for idx in 0..state.avg_groups as usize {
        agg_group[idx] = state.avg_attn[idx] as u8;
    }

    let payload = AttenCharInd {
        application_type: state.application_type,
        security_type: state.security_type,
        run_id: state.runid.clone(),
        source_address: session.socket.get_ifmac(),
        source_id: state.pevid.clone(),
        num_sounds: state.agv_count as u8,
        resp_id: session.config.evseid.clone(),
        attenuation_profile: cglue::cm_atten_char_ind__bindgen_ty_1 {
            num_groups: state.avg_groups,
            aag: agg_group,
        },
    };
    state.pending = SlacRequest::CM_SLAC_MATCH_CNF;
    state.timeout = SLAC_RESP_TIMEOUT;
    state.status = SlacStatus::MATCHED;

    payload.send(&session.socket, &state.pev_addr)?;
    Ok(())
}

// CM_SLAC_MATCH.CNF config to join EVSE logical network
pub fn send_slac_match_cnf(session: &SlacSession, state: &mut SessionState) -> Result<(), AfbError> {
    afb_log_msg!(Notice, None, "SlacSession:send_slac_match_cnf");

    let payload = SlacMatchCnf {
        application_type: state.application_type,
        security_type: state.security_type,
        run_id: state.runid.clone(),
        mvf_length: htole16(cglue::CM_SLAC_MATCH_CNF_MVF_LENGTH), // MVF should be little endian
        pev_id: state.pevid.clone(),
        pev_mac: state.pev_addr.clone(),
        evse_id: session.config.evseid.clone(),
        evse_mac: session.socket.get_ifmac(),
        _rerserved: [0; 8],
        nid: state.nid.clone(),
        _reserved2: 0,
        nmk: session.config.nmk.clone(),
    };

    state.pending = SlacRequest::CM_NONE;
    state.timeout = SLAC_RESP_TIMEOUT;
    state.status = SlacStatus::MATCHED;

    payload.send(&session.socket, &state.pev_addr)?;
    Ok(())
}

/*
 * Copyright (C) 2015-2022 IoT.bzh Company
 * Author: Fulup Ar Foll <fulup@iot.bzh>
 *
 * Licensed under the Apache License; Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing; software
 * distributed under the License is distributed on an "AS IS" BASIS;
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND; either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Reference:
 *   https://github.com/SwitchEV/pyslac/blob/master/pyslac/session.py
 *   https://github.com/qca/open-plc-utils.git
 *   https://github.com/EVerest/libslac
 *
 * Note:
 *  static values and documentation taken from Switch PySlac code
 */

<<<<<<< HEAD
use afbv4::prelude::AfbError;
=======
use afbv4::prelude::*;
>>>>>>> 85bebc7 (fix afbv4 new dependenci model)


//  [V2G3-M06-05]- In case NO communication could be established with a
//  5 % control pilot duty cycle (matching process not started); if the EVSE
//  wants to switch to a nominal duty cycle; then the change from 5 % to a
//  nominal duty cycle shall be done with a specific sequence
//  B2 or C2 (5 %) -> E or F -> B2 (nominal value) to allow backward
//  compatibility. The minimum time at the control pilot state E or F is
//  defined by T_step_EF.

//  [V2G3-M06-06] In case a communication has already been established within
//  5 % control pilot duty cycle (“Matched state” reached or
//  matching process ongoing); a change from 5 % to a nominal duty cycle shall be
//  done with a X1 state in the middle (minimum time as defined in [IEC-3]
//  Seq 9.2); to signal the EV that the control pilot duty cycle will change to a
//  nominal duty cycle

//  [V2G3 M06-07] - If an AC EVSE applies a 5 % control pilot duty cycle;
//  and the EVSE receives NO SLAC request within TT_EVSE_SLAC_init; the EVSE
//  shall go to state E or F for T_step_EF (min 4 s); shall go back to 5 % duty
//  cycle; and  shall reset the TT_EVSE_SLAC_init timeout before being ready to
//  answer a matching request again. This sequence shall be retried
//  C_sequ_retry times (2). At the end; without any reaction; the EVSE shall go
//  to state X1

//  [V2G3-M06-08] After positive EIM; if no matching process is running; the EVSE
//  shall signal control pilot state E/F for T_step_EF; then signal control pilot
//  state X1/X2 (nominal).

//  [V2G3 -M06-09] If a control pilot state E/F -> Bx; Cx; Dx transition is used
//  for triggering retries or legacy issues; the state E/F shall be at least
//  T_step_EF.

//  [V2G2-852] - If no positive authorization information from an EIM has been
//  received the EVSE shall apply PWM equal to 5 %.

//  [V2G2-853] - If an EVSE receives positive authorization information from an
//  EIM the EVSE shall apply a nominal duty cycle.

//  [V2G2-931] - The EVSE shall signal a PWM of 5 % or nominal duty cycle after
//  sending the message AuthorizationRes.

//    Timeouts defined by ISO15118-3 in table A.1 P3
//    Warning: some timeout seems too short and have been expanded


// Time between the moment the EVSE detects state B and the reception of the
// first SLAC Message; i.e. CM_SLAC_PARM.REQ.
pub const SLAC_INIT_TIMEOUT:u8 = 50; // [TT_EVSE_SLAC_init=20 s - 50 s]

// Timeout for the reception of either CM_VALIDATE.REQ or CM_SLAC_MATCH.REQ
// message; after reception of CM_ATTEN_CHAR.RSP
pub const SLAC_MATCH_TIMEOUT:u32 = 10 * 1000; // [TT_EVSE_match_session=10 s]

// Time the EV shall wait for CM_ATTEN_CHAR.IND after sending the first
// CM_START_ATTEN_CHAR.IND
pub const SLAC_ATTEN_RESULTS_TIMEOUT:u32 = 1200; // [TT_EV_atten_results = 1200 ms]

// Timeout used for awaiting for a Request
pub const SLAC_REQ_TIMEOUT:u32 = 400; // [TT_match_sequence = 400 ms]

// Timeout used for awaiting for a Response
pub const SLAC_RESP_TIMEOUT:u32 = 200; // [TT_match_response = 200 ms]

// According to the standard:
// [V2G3-A09-124] - In case the matching process is considered as FAILED;
// wait for a time of TT_ matching_rate before restarting the process.

// [V2G3-A09-125] - If the matching process fails for all retries started
// within TT_matching_repetition; the matching process shall be stopped
// in “Unmatched” state (see Figure 11).

// The number maximum of retries is defined by C_conn_max_match = min 3
// So; if within the TT_matching_repetition (10 s) time; the number of
// retries expires; the matching process shall be stopped
// in “Unmatched” state. (ISO Requirement couldnt be found for this;
// but this is the logical steps to do)

// Total time while the new SLAC repetitions can happen.
// Once this timer is expired; the Matching process is considered FAILED
pub const SLAC_TOTAL_REPETITIONS_TIMEOUT:u32 = 10*1000; // [TT_matching_repetition = 10 s]

// Time to wait for the repetition of the matching process
pub const SLAC_REPETITION_TIMEOUT:u32 = 400; // [TT_matching_rate = 400 ms]

// Time required to await while in state E or F (used in some use cases;
// like the one defined by [V2G3 M06-07])
pub const SLAC_E_F_TIMEOUT:u32 = 4000; // [T_step_EF = min 4 s]

// Timeout on the EVSE side that triggers the calculation of the average
// attenuation profile. Time is in multiples of 100 ms. In this case; we have
// 600 ms (6 * 100)

// Timers.SLAC_ATTEN_TIMEOUT is the only value in the Timers class that its use
// is supposed to be done as an integer (type int)
pub const SLAC_ATTEN_TIMEOUT:u32 = 6 * 1000; // [TT_EVSE_match_MNBC = 600 ms]

// number of sounds
pub const SLAC_MSOUNDS:u8 = 10;

// convert an hexadecimal string "0x1,0x2,...0xN" into an &[u8] slice
pub fn hexa_to_byte(input: &str, buffer: &mut [u8]) -> Result<(), AfbError> {
    if input.len() != 3*buffer.len() -1 {
        return Err(AfbError::new("string-ecode-hexa", format!("invalid len {}!=2*{}", input.len(), buffer.len())))
    } else {
        let mut idx=0;
        for hexa in input.split(':') {
            match u8::from_str_radix(hexa, 16) {
                Ok(value) => buffer[idx]=value,
                Err(_) => return Err(AfbError::new("string-ecode-hexa", "invalid haxa encoding"))
            }
            idx=idx+1;
        }
    }
    Ok(())
}
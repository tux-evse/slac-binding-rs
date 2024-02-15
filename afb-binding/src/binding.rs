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

use crate::prelude::*;
use afbv4::prelude::*;
use slac::prelude::*;
use typesv4::prelude::*;

pub struct ApiConfig {
    pub uid: &'static str,
    pub slac: SessionConfig,
    pub iec_api: &'static str,
}

// wait until both apis (iso+slac) to be ready before trying event subscription
struct ApiUserData {
    iec_api: &'static str,
}

impl AfbApiControls for ApiUserData {
    // the API is created and ready. At this level user may subcall api(s) declare as dependencies
    fn start(&mut self, api: &AfbApi) -> Result<(), AfbError> {
        afb_log_msg!(Notice, api, "subscribing energy api:{}", self.iec_api);
        AfbSubCall::call_sync(api, self.iec_api, "subscribe", true)?;
        Ok(())
    }

    // mandatory unsed declaration
    fn as_any(&mut self) -> &mut dyn Any {
        self
    }
}

// Binding init callback started at binding load time before any API exist
// -----------------------------------------
pub fn binding_init(rootv4: AfbApiV4, jconf: JsoncObj) -> Result<&'static AfbApi, AfbError> {
    afb_log_msg!(Info, rootv4, "config:{}", jconf);

    // register custom afb-v4 type converter
    am62x_registers()?;
    slac_registers()?;

    let uid = jconf.get::<&'static str>("uid")?;
    let api =jconf.default::<&'static str>("api",uid) ?;
    let info = jconf.default::<&'static str>("info","")?;
    let iso_itf = jconf.default::<&'static str>("iso_itf", "eth2")?;

    let value = jconf.default::<&'static str>("nmk", "50:D3:E4:93:3F:85:5B:70:40:78:4D:F8:15:AA:8D:B7")?;
    // translate from hexa string to byte array
    let mut nmk: SlacNmk = [0; SLAC_NMK_LEN];
    hexa_to_byte(value, &mut nmk)?;

    let value = jconf.default::<&'static str>("evseid", ":Tux::EvSe:0x0000")?;
    if value.len() != SLAC_STATID_LEN {
        return Err(AfbError::new(
            "binding-slac-config",
            format!(
                "Invalid evseid len (should be {} Byte not {}",
                SLAC_STATID_LEN,
                value.len()
            ),
        ));
    }

    let iec_api = jconf.get::<&'static str>("iec_api")?;
    let mut evseid: SlacStaId = [0; SLAC_STATID_LEN];
    for idx in 0..evseid.len() {
        evseid[idx] = value.as_bytes()[idx];
    }

    let timeout = jconf.default::<u32>("timeout", 20)?;
    let timetic = jconf.default::<u32>("timetic", 3)?;

    let slac_config = SessionConfig {
        iface:iso_itf,
        nmk,
        evseid,
        timeout: timeout * 1000,
        timetic: timetic * 1000,
    };

    let api_config = ApiConfig {
        uid,
        iec_api,
        slac: slac_config,
    };

    // create a new api
    let api = AfbApi::new(api)
        .set_info(info)
        .set_callback(Box::new(ApiUserData { iec_api }));

    // register verbs and events
    register(rootv4,api, api_config)?;

    // request iec6185 micro service api and finalize api
    api.require_api(iec_api);

    // if acls set apply them
    if let Ok(value) = jconf.get::<String>("permission") {
        let perm = to_static_str(value);
        api.set_permission(AfbPermission::new(perm));
    };

    if let Ok(value) = jconf.get::<i32>("verbosity") {
        api.set_verbosity(value);
    };

    // freeze & activate api
    Ok(api.finalize()?)
}

// register binding within afbv4
AfbBindingRegister!(binding_init);

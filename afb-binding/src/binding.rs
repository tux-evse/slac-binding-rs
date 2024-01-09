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

pub(crate) fn to_static_str(value: String) -> &'static str {
    Box::leak(value.into_boxed_str())
}

pub struct ApiConfig {
    pub uid: &'static str,
    pub slac: SessionConfig,
    pub iec_api: &'static str,
    pub iec_evt: &'static str,
}

impl AfbApiControls for ApiConfig {
    fn config(&mut self, api: &AfbApi, jconf: JsoncObj) -> Result<(), AfbError> {
        afb_log_msg!(Debug, api, "api={} config={}", api.get_uid(), jconf);

        Ok(())
    }

    // mandatory for downcasting back to custom api data object
    fn as_any(&mut self) -> &mut dyn Any {
        self
    }
}

// wait until both apis (iso+slac) to be ready before trying event subscription
struct ApiUserData {
    iec_api: &'static str,
}

impl AfbApiControls for ApiUserData {
    // the API is created and ready. At this level user may subcall api(s) declare as dependencies
    fn start(&mut self, api: &AfbApi) -> Result<(), AfbError> {
        afb_log_msg!(Error, api, "subscribing energy api:{}", self.iec_api);
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

    let uid = if let Ok(value) = jconf.get::<String>("uid") {
        to_static_str(value)
    } else {
        "slac"
    };

    let info = if let Ok(value) = jconf.get::<String>("info") {
        to_static_str(value)
    } else {
        ""
    };

    let iso_itf = if let Ok(value) = jconf.get::<String>("iso_itf") {
        to_static_str(value)
    } else {
        "br0"
    };

    let value = if let Ok(value) = jconf.get::<String>("nmk") {
        to_static_str(value)
    } else {
        // for debug use Qualcomm open-plc-utils NMK value
        "50:D3:E4:93:3F:85:5B:70:40:78:4D:F8:15:AA:8D:B7"
    };
    // translate from hexa string to byte array
    let mut nmk: SlacNmk = [0; SLAC_NMK_LEN];
    hexa_to_byte(value, &mut nmk)?;

    let value = if let Ok(value) = jconf.get::<String>("evseid") {
        to_static_str(value)
    } else {
        ":Tux::EvSe:0x0000"
    };
    if value.len() != SLAC_STATID_LEN {
        return Err(AfbError::new(
            "binding-session-config",
            format!(
                "Invalid evseid len (should be {} Byte not{}",
                SLAC_STATID_LEN,
                value.len()
            ),
        ));
    }

    let iec_api = if let Ok(value) = jconf.get::<String>("iec6185_api") {
        to_static_str(value)
    } else {
        return Err(AfbError::new(
            "binding-iec6185-config",
            "iec6185 micro service api SHOULD be defined",
        ));
    };

    let iec_evt = if let Ok(value) = jconf.get::<String>("iec6185_evt") {
        to_static_str(value)
    } else {
        return Err(AfbError::new(
            "binding-iec6185-config",
            "iec6185 micro service event name SHOULD be defined",
        ));
    };

    let mut evseid: SlacStaId = [0; SLAC_STATID_LEN];
    for idx in 0..evseid.len() {
        evseid[idx] = value.as_bytes()[idx];
    }

    let timeout = if let Ok(value) = jconf.get::<u32>("timeout") {
        value
    } else {
        20
    };

    let timetic = if let Ok(value) = jconf.get::<u32>("timetic") {
        value
    } else {
        3
    };

    let acls = if let Ok(value) = jconf.get::<String>("acls") {
        AfbPermission::new(to_static_str(value))
    } else {
        AfbPermission::new("acl:rmsg:ti")
    };

    // NID and NMK should

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
        iec_evt,
        slac: slac_config,
    };

    // create a new api
    let api = AfbApi::new(uid)
        .set_info(info)
        .set_permission(acls)
        .set_callback(Box::new(ApiUserData { iec_api }));

    // update root api because we need it within iec event handler
    api.set_apiv4(rootv4);

    // register verbs and events
    register(api, api_config)?;

    // request iec6185 micro service api and finalize api
    api.require_api(iec_api);

    // freeze & activate api
    Ok(api.finalize()?)
}

// register binding within afbv4
AfbBindingRegister!(binding_init);

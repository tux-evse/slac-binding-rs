/*
 * Copyright (C) 2015-2023 IoT.bzh Company
 * Author: Fulup Ar Foll <fulup@iot.bzh>
 *
 * Redpesk samples code/config use MIT License and can be freely copy/modified even within proprietary code
 * License: $RP_BEGIN_LICENSE$ SPDX:MIT https://opensource.org/licenses/MIT $RP_END_LICENSE$
 *
 * Debug: wireshark -i eth0 -k -S -f "host slac.biastaging.com and tcp port 80"
 */

use afbv4::prelude::*;
use typesv4::prelude::*;

// This rootv4 demonstrate how to test an external rootv4 that you load within the same afb-binder process and security context
// It leverages test (Test Anything Protocol) that is compatible with redpesk testing report.
struct TapUserData {
    autostart: bool,
    autoexit: bool,
    output: AfbTapOutput,
    target: &'static str,
}

// AfbApi userdata implements AfbApiControls trait
impl AfbApiControls for TapUserData {
    fn start(&mut self, api: &AfbApi) -> Result<(), AfbError> {
        afb_log_msg!(Notice, api, "starting slac testing");

        // check tad_id on server
        let subscribe = AfbTapTest::new("subscribe", self.target, "subscribe")
            .set_info("subscribe slac event")
            .add_arg(true)?
            .finalize()?;

        AfbTapSuite::new(api, "Tap Demo Test")
            .set_info("slac frontend -> occp server test")
            .set_timeout(0)
            .add_test(subscribe)
            .set_autorun(self.autostart)
            .set_autoexit(self.autoexit)
            .set_output(self.output)
            .finalize()?;
        Ok(())
    }

    fn config(&mut self, api: &AfbApi, jconf: JsoncObj) -> Result<(), AfbError> {
        afb_log_msg!(Debug, api, "api={} config={}", api.get_uid(), jconf);
        match jconf.get::<bool>("autostart") {
            Ok(value) => self.autostart = value,
            Err(_error) => {}
        };

        match jconf.get::<bool>("autoexit") {
            Ok(value) => self.autoexit = value,
            Err(_error) => {}
        };

        match jconf.get::<String>("output") {
            Err(_error) => {}
            Ok(value) => match value.to_uppercase().as_str() {
                "JSON" => self.output = AfbTapOutput::JSON,
                "TAP" => self.output = AfbTapOutput::TAP,
                "NONE" => self.output = AfbTapOutput::NONE,
                _ => {
                    afb_log_msg!(
                        Error,
                        api,
                        "Invalid output should be json|tap (default used)"
                    );
                }
            },
        };

        Ok(())
    }

    // mandatory for downcasting back to custom apidata object
    fn as_any(&mut self) -> &mut dyn Any {
        self
    }
}

AfbVerbRegister!(StateRequestVerb, state_request_cb);
fn state_request_cb(rqt: &AfbRequest, _args: &AfbData) -> Result<(), AfbError> {
    rqt.reply(AFB_NO_DATA, 0);
    Ok(())
}

// init callback started at binding load time before any API exist
// ---------------------------------------------------------------
pub fn binding_test_init(rootv4: AfbApiV4, jconf: JsoncObj) -> Result<&'static AfbApi, AfbError> {
    let uid = jconf.get::<&'static str>("uid")?;
    let target = jconf.get::<&'static str>("target")?;

    let tap_config = TapUserData {
        autostart: jconf.default::<bool>("autostart", true)?,
        autoexit: jconf.default::<bool>("autoexit", true)?,
        output: AfbTapOutput::TAP,
        target,
    };

    // custom type should register once per binder
    slac_registers()?;

    let subscribe_verb = AfbVerb::new("subscribe")
        .set_info("Mock iec subscribe api")
        .set_callback(Box::new(StateRequestVerb {}))
        .finalize()?;

    afb_log_msg!(Notice, rootv4, "slac test uid:{} target:{}", uid, target);
    let api = AfbApi::new(uid)
        .set_info("Testing slac tap reporting")
        .require_api(target)
        .set_callback(Box::new(tap_config))
        .add_verb(subscribe_verb)
        .seal(false)
        .finalize()?;
    Ok(api)
}

// register rootv4 within libafb
AfbBindingRegister!(binding_test_init);
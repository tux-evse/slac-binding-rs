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
use serde::{Deserialize, Serialize};
use afbv4::prelude::*;

AfbDataConverter!(iec6185_msg, Iec6185Msg);
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "lowercase")]
pub enum Iec6185Msg {
    Plugged(bool),
    PowerRqt(bool),
    CableImax(u32),
    RelayOn(bool),
    Error(String),
}


pub fn am62x_registers() -> Result <(), AfbError> {
    // add binding custom converter
    iec6185_msg::register()?;
    Ok(())
}
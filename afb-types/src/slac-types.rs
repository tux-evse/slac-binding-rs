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

AfbDataConverter!(slac_status, SlacStatus);
#[derive(Serialize, Deserialize, Debug, Clone, Copy)]
#[serde(rename_all = "lowercase", untagged)]
// Session state extracted from Switch/PySlac code
pub enum SlacStatus {
    MATCHED,
    MATCHING,
    UNMATCHED,
    WAITING,
    JOINING,
    TIMEOUT,
    IDLE,
}

pub fn slac_registers() -> Result <(), AfbError> {
    // add binding custom converter
    slac_status::register()?;
    Ok(())
}
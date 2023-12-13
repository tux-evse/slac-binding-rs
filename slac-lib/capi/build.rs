/*
 * Copyright (C) 2015-2023 IoT.bzh Company
 * Author: Fulup Ar Foll <fulup@iot.bzh>
 *
 * Redpesk interface code/config use MIT License and can be freely copy/modified even within proprietary code
 * License: $RP_BEGIN_LICENSE$ SPDX:MIT https://opensource.org/licenses/MIT $RP_END_LICENSE$
 *
*/
use std::env;

fn main() {
    // invalidate the built crate whenever the wrapper changes
    println!("cargo:rerun-if-changed=capi/capi-map.h");
    println!("cargo:rustc-link-search=/usr/local/lib64");
    if let Ok(value) = env::var("CARGO_TARGET_DIR") {
        if let Ok(profile) = env::var("PROFILE") {
            println!("cargo:rustc-link-search=crate={}{}", value, profile);
        }
    }
    let header = "
    // -----------------------------------------------------------------------
    //         <- private 'libslac' Rust/C unsafe binding ->
    // -----------------------------------------------------------------------
    //   Do not exit this file it will be regenerated automatically by cargo.
    //   Check:
    //     - build.rs for C/Rust glue options
    //     - src/capi/capi-map.h for C prototype inputs
    // -----------------------------------------------------------------------
    ";
    let libslac = bindgen::Builder::default()
        .header("capi/capi-map.h") // Pionix C++ prototype wrapper input
        .raw_line(header)
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .derive_debug(false)
        .layout_tests(false)
        //.allowlist_function("read")
        .allowlist_function("__errno_location")
        .allowlist_function("errno")
        .allowlist_function("strerror_r")
        .allowlist_type("cm_.*")
        .allowlist_type("sockaddr_.*")
        .allowlist_type("ether_header")
        .allowlist_type("homeplug_header")
        .allowlist_type("ifreq")
        .allowlist_var("CLIB_.*")
        .allowlist_var("CM_.*")
        .allowlist_var("TT_.*")
        .allowlist_var("C_EV_.*")
        .allowlist_var(".*_HOMEPLUG_GREENPHY")
        .allowlist_var(".*_LEN")
        .allowlist_var("MMTYPE_.*")
        .allowlist_function("bind")
        .allowlist_function("socket")
        .allowlist_function("[h,n]to.[l,s]")
        .allowlist_function("setsockopt")
        .allowlist_function("ifreq")
        .allowlist_function("ioctl")
        .allowlist_function("fcntl")
        .allowlist_function("read")
        .allowlist_function("send")
        .allowlist_function("close")
        .allowlist_function("connect")
        .allowlist_function("time")
        .allowlist_function("localtime")
        .allowlist_function("strftime")
        .allowlist_function("clock_gettime")
        .allowlist_var("SOCK_.*")
        .allowlist_var("INET_.*")
        .allowlist_var("AF_.*")
        .generate()
        .expect("Unable to generate libslac");

    libslac
        .write_to_file("capi/_capi-map.rs")
        .expect("Couldn't write libslac!");
}

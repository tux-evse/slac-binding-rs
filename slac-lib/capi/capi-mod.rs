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
 */

use std::ffi::CStr;
use std::ffi::CString;
use std::fmt;
use std::mem;

use afbv4::prelude::*;

pub type Cchar = ::std::os::raw::c_char;

const MAX_ERROR_LEN: usize = 256;
pub mod cglue {
    #![allow(dead_code)]
    #![allow(non_upper_case_globals)]
    #![allow(non_camel_case_types)]
    #![allow(non_snake_case)]
    include!("_capi-map.rs");
}

use crate::prelude::*;

// move host int16 to little indian
pub fn htole16(value: u16) -> u16 {
    let indian: [u8; 2] = unsafe { mem::transmute(1 as u16) };
    if indian[0] == 1 {
        value
    } else {
        let input: [u8; 2] = unsafe { mem::transmute(value) };
        let output: [u8; 2] = [input[1], input[0]];

        let value: u16 = unsafe { mem::transmute(output) };
        value
    }
}

pub fn slice_equal(elm1: &[u8], elm2: &[u8]) -> bool {
    if elm1.len() != elm2.len() {
        return false;
    };

    for idx in 0..elm1.len() {
        if elm1[idx] != elm2[idx] {
            return false;
        };
    }
    return true;
}

pub fn get_perror() -> String {
    let mut buffer = [0 as ::std::os::raw::c_char; MAX_ERROR_LEN];
    unsafe {
        cglue::strerror_r(
            *cglue::__errno_location(),
            &mut buffer as *mut Cchar,
            MAX_ERROR_LEN,
        )
    };
    let cstring = unsafe { CStr::from_ptr(&mut buffer as *const Cchar) };
    let slice: &str = cstring.to_str().unwrap();
    slice.to_owned()
}

pub struct SockRaw {
    iface: &'static str,
    sockfd: ::std::os::raw::c_int,
    srcmac: SlacIfMac,
    protocol: u16,
}

impl fmt::Display for SockRaw {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = format!(
            "sockraw:{{iface:{}, sockfd:{}, srcmac:{:02X?}, protocol:{}}}",
            self.iface, self.sockfd, self.srcmac, self.protocol
        );
        fmt.pad(&text)
    }
}

// open a raw socket. Seting so_broadcast is not needed as we use layer2 packet without any IP addr.
// at create dst addr is set to 0 (should it be to FF ?). Later one dest mac should be updated to switch to unicast mode
impl SockRaw {
    pub fn open(ethdev: &'static str) -> Result<SockRaw, AfbError> {
        //let protocol = unsafe { cglue::htons(cglue::INET_ETH_P_ALL) };
        let sockfd =
            unsafe { cglue::socket(cglue::INET_PF_PACKET as i32, cglue::INET_SOCKRAW, 0 as i32) };

        if sockfd < 0 {
            return Err(AfbError::new(
                "slac-sockraw-socket",
                format!(
                    "layer2 socket missing 'CAP_NET_RAW' capability, info:{}",
                    get_perror()
                ),
            ));
        }

        // get iface mac addr
        let mut ifreq: cglue::ifreq = unsafe { mem::zeroed() };
        let iname = ethdev.as_bytes();
        unsafe {
            for idx in 0..ifreq.ifr_ifrn.ifrn_name.len() {
                if idx == iname.len() {
                    break;
                };
                ifreq.ifr_ifrn.ifrn_name[idx] = iname[idx] as Cchar;
            }
        }

        // get iface mac addr
        let rc = unsafe { cglue::ioctl(sockfd, cglue::INET_SIOCGIFHWADDR as u64, &ifreq) };
        let ifmac = if rc < 0 {
            return Err(AfbError::new(
                "slac-sockraw-socket",
                format!("Fail to get iface:{} mac addr", ethdev),
            ));
        } else {
            let mut macaddr: SlacIfMac = [0; ETHER_ADDR_LEN];
            let addr = unsafe { ifreq.ifr_ifru.ifru_hwaddr.sa_data };
            for idx in 0..ETHER_ADDR_LEN {
                macaddr[idx] = addr[idx] as u8;
            }
            macaddr
        };

        // get iface index
        let status = unsafe { cglue::ioctl(sockfd, cglue::INET_SIOCGIFINDEX as u64, &ifreq) };
        if status < 0 {
            unsafe { cglue::close(sockfd) };
            return Err(AfbError::new("slac-capi-iface-idx", get_perror()));
        }
        let ifidx = unsafe { ifreq.ifr_ifru.ifru_ivalue };

        let mut sockaddr = unsafe { mem::zeroed::<cglue::sockaddr_ll>() };
        sockaddr.sll_ifindex = ifidx;
        sockaddr.sll_family = cglue::INET_PF_PACKET;
        sockaddr.sll_protocol = unsafe { cglue::htons(cglue::ETH_P_HOMEPLUG_GREENPHY) };
        sockaddr.sll_halen = cglue::INET_ETH_ALEN;
        sockaddr.sll_hatype = cglue::INET_PACKET_HOST as u16 | cglue::INET_PACKET_MULTICAST as u16;
        //https://stackoverflow.com/questions/73384742/layer-2-socket-programming

        let status = unsafe {
            cglue::bind(
                sockfd,
                &sockaddr as *const _ as *const cglue::sockaddr,
                mem::size_of::<cglue::sockaddr_ll>() as cglue::socklen_t,
            )
        };
        if status < 0 {
            unsafe { cglue::close(sockfd) };
            return Err(AfbError::new("slac-capi-bind", get_perror()));
        }
        // dst mac to 0 force broadcast, it should be replace later to enable Unicast with PEV MacAddr.
        Ok(SockRaw {
            iface: ethdev,
            sockfd,
            protocol: cglue::ETH_P_HOMEPLUG_GREENPHY, // keep host indianness for debug
            srcmac: ifmac,
        })
    }

    pub fn get_sockfd(&self) -> ::std::os::raw::c_int {
        self.sockfd
    }

    pub fn get_ifmac(&self) -> SlacIfMac {
        self.srcmac.clone()
    }

    // read with ETH_P_ALL require ethernet metadata to prefix data buffer
    pub fn read(&self, buffer: &mut SlacRawMsg) -> Result<(), AfbError> {
        let count = unsafe {
            cglue::read(
                self.sockfd,
                buffer as *const _ as *mut ::std::os::raw::c_void,
                mem::size_of::<SlacRawMsg>(),
            )
        };

        if count <= 0 {
            Err(AfbError::new("sockraw-read-fail", get_perror()))
        } else {
            Ok(())
        }
    }

    // write with ETH_P_ALL require ethernet metadata to prefix data buffer
    pub fn write(&self, buffer: *const ::std::os::raw::c_void, len: usize) -> Result<(), AfbError> {

        // layer2 packet should be 60 byte minimum
        let len = if len > 60 { len } else { 60 };

        let count = unsafe { cglue::send(self.sockfd, buffer, len, 0) };

        if count != len as isize {
            Err(AfbError::new("slac-capi-write", get_perror()))
        } else {
            Ok(())
        }
    }
}

pub struct GetTime {}

impl GetTime {
    // return Linux current date/time as a string
    pub fn _as_string(format: &str) -> Result<String, ()> {
        let fmt = match CString::new(format) {
            Err(_err) => return Err(()),
            Ok(value) => value,
        };
        let time = unsafe { cglue::time(0 as *mut cglue::time_t) };
        let locale = unsafe { cglue::localtime(&time) };
        let mut buffer: [Cchar; 64] = [0; 64];
        unsafe { cglue::strftime(buffer.as_mut_ptr(), buffer.len(), fmt.as_ptr(), locale) };
        let cstring = unsafe { CStr::from_ptr(buffer.as_ptr()) };
        let slice = match cstring.to_str() {
            Err(_err) => return Err(()),
            Ok(value) => value,
        };
        Ok(slice.to_owned())
    }

    // return timenasec value ns subset as fake uid number
    pub fn mk_nonce() -> u32 {
        unsafe {
            let mut timeval: cglue::timespec = mem::zeroed();
            cglue::clock_gettime(cglue::CLIB_CLOCK_MONOTONIC, &mut timeval);
            (timeval.tv_nsec & 0x00000000FFFFFFFF) as u32
        }
    }
}

impl cglue::ether_header {
    pub fn new(sock: &SockRaw, dmac: &SlacIfMac) -> cglue::ether_header {
        cglue::ether_header {
            ether_shost: sock.srcmac.clone(),
            ether_dhost: dmac.clone(),
            ether_type: unsafe { cglue::htons(sock.protocol) },
        }
    }

    pub fn get_type(&self) -> u16 {
        unsafe { cglue::ntohs(self.ether_type) }
    }
}

impl cglue::homeplug_header {
    pub fn new(mmtype: u16) -> cglue::homeplug_header {
        cglue::homeplug_header {
            mmv: cglue::MMV_HOMEPLUG_GREENPHY,
            mmtype: htole16(mmtype),
            fmni: 0,
            fmsn: 0,
        }
    }

    // retreive mtype verifying reqpond masq flag
    pub fn get_mmtype(&self, masq: u16) -> Result<u16, AfbError> {
        let mtype = htole16(self.mmtype);

        if masq & mtype != masq {
            Err(AfbError::new("capi-get_mmtype", "invalid respond masq"))
        } else {
            Ok(mtype ^ masq)
        }
    }

    pub fn get_mmv(&self) -> u8 {
        self.mmv
    }
}

/*
 * Copyright 2015-2018 Yubico AB
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

//! Module for handling OTPs

use regex::Regex;
use std::os::raw::{c_uchar, c_ushort};

use std::collections::HashMap;

use error;
use error::Error;

use rustc_serialize::hex::FromHex; // TODO(adma): use SERDE instead

use super::lyh;
use super::Session;

static AEAD_LENGTH: usize = 36;

lazy_static! {
    static ref OTP_RE: Regex = Regex::new("[cbdefghijklnrtuv]{44}$").unwrap();
}

lazy_static! {
    static ref MODHEX_MAP: HashMap<char, char> = {
        let mut m = HashMap::new();
        m.insert('c', '0');
        m.insert('b', '1');
        m.insert('d', '2');
        m.insert('e', '3');
        m.insert('f', '4');
        m.insert('g', '5');
        m.insert('h', '6');
        m.insert('i', '7');
        m.insert('j', '8');
        m.insert('k', '9');
        m.insert('l', 'a');
        m.insert('n', 'b');
        m.insert('r', 'c');
        m.insert('t', 'd');
        m.insert('u', 'e');
        m.insert('v', 'f');
        m
    };
}

#[derive(Debug, Copy, Clone)]
/// OTP
pub struct Otp<'r> {
    /// Public ID
    pub public_id: &'r str,
    /// Value
    pub value: [u8; 16],
}

fn to_bytes(otp: &str) -> [u8; 16] {
    let mut s = String::new();
    for c in otp.chars() {
        s.push(*MODHEX_MAP.get(&c).unwrap());
    }

    let mut ret = [0; 16];
    ret.clone_from_slice(&s.from_hex().unwrap());
    ret
}

/// Check whether or not a string is valid ModHex
pub fn is_modhex(otp: &str) -> bool {
    for c in otp.chars() {
        if MODHEX_MAP.get(&c).is_none() {
            return false;
        }
    }

    true
}

impl<'r> Otp<'r> {
    /// Create and OTP from a string of text
    pub fn new(string: &'r str) -> Option<Otp> {
        if OTP_RE.is_match(string) {
            Some(Otp {
                public_id: &string[0..12],
                value: to_bytes(&string[12..]),
            })
        } else {
            None
        }
    }
}

#[derive(Debug, Copy, Clone)]
/// Decrypted OTP
pub struct DecryptedOtp {
    /// Use counter
    pub use_counter: u16,
    /// Session counter
    pub session_counter: u8,
    /// Timestamp high
    pub timestamp_high: u8,
    /// Timestamp low
    pub timestamp_low: u16,
}

impl ::std::fmt::Display for DecryptedOtp {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        write!(
            f,
            "u:{:06} c:{:04} h:{:04} l:{:06}",
            self.use_counter, self.session_counter, self.timestamp_high, self.timestamp_low
        )
    }
}

impl Session {
    /// Decrypt an OTP
    pub fn decrypt_otp(
        &self,
        key_id: u16,
        aead: &[u8],
        otp: &[u8; 16],
    ) -> Result<DecryptedOtp, Error> {
        let mut use_ctr: c_ushort = 0;
        let mut session_ctr: c_uchar = 0;
        let mut tstph: c_uchar = 0;
        let mut tstpl: c_ushort = 0;

        debug!(
            "Decrypt OTP {:?} with AEAD {:?} using session {:?}",
            otp, aead, self.ptr
        );
        error::result_from_libyh(unsafe {
            lyh::yh_util_decrypt_otp(
                self.ptr,
                key_id,
                aead.as_ptr(),
                AEAD_LENGTH,
                otp.as_ptr(),
                &mut use_ctr,
                &mut session_ctr,
                &mut tstph,
                &mut tstpl,
            )
        }).and(Ok(DecryptedOtp {
            use_counter: use_ctr,
            session_counter: session_ctr,
            timestamp_high: tstph,
            timestamp_low: tstpl,
        }))
    }
}

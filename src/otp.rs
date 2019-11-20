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
    static ref MODHEX_MAP: HashMap<char, char> =
    [('c', '0'),
     ('b', '1'),
     ('d', '2'),
     ('e', '3'),
     ('f', '4'),
     ('g', '5'),
     ('h', '6'),
     ('i', '7'),
     ('j', '8'),
     ('k', '9'),
     ('l', 'a'),
     ('n', 'b'),
     ('r', 'c'),
     ('t', 'd'),
     ('u', 'e'),
     ('v', 'f')]
     .iter().cloned().collect();
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
    let s: String = otp.chars().map(|c| MODHEX_MAP.get(&c).unwrap()).collect();

    let mut ret = [0; 16];
    ret.clone_from_slice(&s.from_hex().unwrap());
    ret
}

/// Check whether or not a string is valid ModHex
pub fn is_modhex(otp: &str) -> bool {
    otp.chars().all(|c| MODHEX_MAP.contains_key(&c))
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

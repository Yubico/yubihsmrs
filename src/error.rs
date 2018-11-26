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

use lyh;
use std::error;
use std::fmt;

/// Enum listing possible errors from `YubiHSM`.
#[derive(Debug, Clone, Copy)]
pub enum Error {
    /// An error from an underlying libyubihsm call.
    LibYubiHsm(lyh::Error),
    /// Unexpected length value
    WrongLength(usize, usize),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::LibYubiHsm(ref err) => err.fmt(f),
            Error::WrongLength(ref exp, ref found) => {
                write!(f, "Wrong length, expected {}, found {}", exp, found)
            }
        }
    }
}

impl error::Error for Error {
    fn description(&self) -> &str {
        match *self {
            Error::LibYubiHsm(ref err) => err.description(),
            Error::WrongLength(_, _) => "Wrong length",
        }
    }

    fn cause(&self) -> Option<&error::Error> {
        match *self {
            Error::LibYubiHsm(ref err) => Some(err),
            Error::WrongLength(_, _) => None,
        }
    }
}

// Public but not re-exported by lib.rs, so only visible within crate.

pub fn result_from_libyh(code: lyh::yh_rc) -> ::std::result::Result<(), Error> {
    match code {
        lyh::yh_rc::YHR_SUCCESS => Ok(()),
        err => Err(Error::LibYubiHsm(lyh::Error::new(err))),
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn check_errors() {
        let x = Error::LibYubiHsm(lyh::Error::AuthSessionError);
        println!("The error is {}", x);
    }
}

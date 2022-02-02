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

extern crate num_enum;

use std::error;
use std::fmt;
use std::os::raw::c_int;

/// FFI return type of the public functions
pub type yh_rc = c_int;

#[repr(i32)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, num_enum::FromPrimitive)]
/// Return type of the public functions
pub enum yh_rc_enum {
    /// Successs
    YHR_SUCCESS = 0,
    /// Memory error
    YHR_MEMORY = -1,
    /// Init error
    YHR_INIT_ERROR = -2,
    /// Net error
    YHR_NET_ERROR = -3,
    /// Connector not found
    YHR_CONNECTOR_NOT_FOUND = -4,
    /// Invalid parameters
    YHR_INVALID_PARAMS = -5,
    /// Wrong length
    YHR_WRONG_LENGTH = -6,
    /// Buffer too small
    YHR_BUFFER_TOO_SMALL = -7,
    /// Cryptogram error
    YHR_CRYPTOGRAM_MISMATCH = -8,
    /// Authenticate session error
    YHR_AUTH_SESSION_ERROR = -9,
    /// MAC not matching
    YHR_MAC_MISMATCH = -10,
    /// Device success
    YHR_DEVICE_OK = -11,
    /// Invalid command
    YHR_DEVICE_INV_COMMAND = -12,
    /// Malformed command / invalid data
    YHR_DEVICE_INV_DATA = -13,
    /// Invalid session
    YHR_DEVICE_INV_SESSION = -14,
    /// Message encryption / verification failed
    YHR_DEVICE_AUTH_FAIL = -15,
    /// All sessions are allocated
    YHR_DEVICE_SESSIONS_FULL = -16,
    /// Session creation failed
    YHR_DEVICE_SESSION_FAILED = -17,
    /// Storage failure
    YHR_DEVICE_STORAGE_FAILED = -18,
    /// Wrong length
    YHR_DEVICE_WRONG_LENGTH = -19,
    /// Wrong permissions for operation
    YHR_DEVICE_INV_PERMISSION = -20,
    /// Log buffer is full and forced audit is set
    YHR_DEVICE_LOG_FULL = -21,
    /// Object not found
    YHR_DEVICE_OBJ_NOT_FOUND = -22,
    /// Id use is illegal
    YHR_DEVICE_ID_ILLEGAL = -23,
    /// OTP submitted is invalid
    YHR_DEVICE_INVALID_OTP = -24,
    /// Device is in demo mode and has to be power cycled
    YHR_DEVICE_DEMO_MODE = -25,
    /// The command execution has not terminated
    YHR_DEVICE_CMD_UNEXECUTED = -26,
    /// Unknown error
    YHR_GENERIC_ERROR = -27,
    /// Object with given ID already exists
    YHR_DEVICE_OBJECT_EXISTS = -28,
    /// Connector operation failed
    YHR_CONNECTOR_ERROR = -29,
    /// Return value when encountering SSH CA constraint violation
    YHR_DEVICE_SSH_CA_CONSTRAINT_VIOLATION = -30,
    /// Return value when an algorithm is disabled
    YHR_DEVICE_ALGORITHM_DISABLED = -31,
    #[num_enum(default)]
    /// Return value for unknown error codes
    YHR_UNKNOWN_ERROR = -99
}

#[derive(Clone, Copy, Debug)]
/// Rust enum of possible error types
pub enum Error {
    /// Success
    Success,

    /// Unable to allocate memory
    Memory,

    /// Unable to initialize libyubihsm
    InitError,

    /// Libcurl error
    NetworkError,

    /// Unable to find a suitable connector
    ConnectorNotFound,

    /// Invalid argument to a function
    InvalidParams,

    /// Mismatch between expected and received length
    WrongLength,

    /// MNot enough space to store data
    BufferTooSmall,

    /// Unable to verify cryptogram
    CryptogramMismatch,

    /// Unable to authenticate session
    AuthSessionError,

    /// Unable to verify MAC
    MacMismatch,

    /// No error from the device
    DeviceOk,

    /// Invalid command
    DeviceInvalidCommand,

    /// Malformed command / invalid data
    DeviceInvalidData,

    /// Invalid session
    DeviceInvalidSession,

    /// Malformed encryption / verification failed
    DeviceAuthenticationFailed,

    /// All sessions are allocated
    DeviceSessionsFull,

    /// Session creation failed
    DeviceSessionFailed,

    /// Storage failure
    DeviceStorageFailed,

    /// Wrong length
    DeviceWrongLength,

    /// Wrong permissions for operation
    DeviceInvalidPermissions,

    /// Log buffer is full and forced audit is set
    DeviceLogFull,

    /// Object not found
    DeviceObjectNotFound,

    /// Illegal ID used
    DeviceIdIllegal,

    /// Invalid OTP
    DeviceInvalidOtp,

    /// Demo mode, power cycle the device
    DeviceDemoMode,

    /// The command execution has not terminated
    DeviceCmdUnexecuted,

    /// Generic error
    GenericError,

    /// Object with given ID and type already exists
    ObjectExists,

    /// Connector operation failed
    ConnectorError,

    /// Return value when encountering SSH CA constraint violation
    SshCaConstraintViolation,

    /// Return value when an algorithm is disabled
    AlgorithmDisabled,

    /// Unknown error
    Unknown
}

fn code_to_err(return_code: yh_rc_enum) -> Error {
    match return_code {
        yh_rc_enum::YHR_SUCCESS => Error::Success,
        yh_rc_enum::YHR_MEMORY => Error::Memory,
        yh_rc_enum::YHR_INIT_ERROR => Error::InitError,
        yh_rc_enum::YHR_NET_ERROR => Error::NetworkError,
        yh_rc_enum::YHR_CONNECTOR_NOT_FOUND => Error::ConnectorNotFound,
        yh_rc_enum::YHR_INVALID_PARAMS => Error::InvalidParams,
        yh_rc_enum::YHR_WRONG_LENGTH => Error::WrongLength,
        yh_rc_enum::YHR_BUFFER_TOO_SMALL => Error::BufferTooSmall,
        yh_rc_enum::YHR_CRYPTOGRAM_MISMATCH => Error::CryptogramMismatch,
        yh_rc_enum::YHR_AUTH_SESSION_ERROR => Error::AuthSessionError,
        yh_rc_enum::YHR_MAC_MISMATCH => Error::MacMismatch,
        yh_rc_enum::YHR_DEVICE_OK => Error::DeviceOk,
        yh_rc_enum::YHR_DEVICE_INV_COMMAND => Error::DeviceInvalidCommand,
        yh_rc_enum::YHR_DEVICE_INV_DATA => Error::DeviceInvalidData,
        yh_rc_enum::YHR_DEVICE_INV_SESSION => Error::DeviceInvalidSession,
        yh_rc_enum::YHR_DEVICE_AUTH_FAIL => Error::DeviceAuthenticationFailed,
        yh_rc_enum::YHR_DEVICE_SESSIONS_FULL => Error::DeviceSessionsFull,
        yh_rc_enum::YHR_DEVICE_SESSION_FAILED => Error::DeviceSessionFailed,
        yh_rc_enum::YHR_DEVICE_STORAGE_FAILED => Error::DeviceStorageFailed,
        yh_rc_enum::YHR_DEVICE_WRONG_LENGTH => Error::DeviceWrongLength,
        yh_rc_enum::YHR_DEVICE_INV_PERMISSION => Error::DeviceInvalidPermissions,
        yh_rc_enum::YHR_DEVICE_LOG_FULL => Error::DeviceLogFull,
        yh_rc_enum::YHR_DEVICE_OBJ_NOT_FOUND => Error::DeviceObjectNotFound,
        yh_rc_enum::YHR_DEVICE_ID_ILLEGAL => Error::DeviceIdIllegal,
        yh_rc_enum::YHR_DEVICE_INVALID_OTP => Error::DeviceInvalidOtp,
        yh_rc_enum::YHR_DEVICE_DEMO_MODE => Error::DeviceDemoMode,
        yh_rc_enum::YHR_DEVICE_CMD_UNEXECUTED => Error::DeviceCmdUnexecuted,
        yh_rc_enum::YHR_GENERIC_ERROR => Error::GenericError,
        yh_rc_enum::YHR_DEVICE_OBJECT_EXISTS => Error::ObjectExists,
        yh_rc_enum::YHR_CONNECTOR_ERROR => Error::ConnectorError,
        yh_rc_enum::YHR_DEVICE_SSH_CA_CONSTRAINT_VIOLATION => Error::SshCaConstraintViolation,
        yh_rc_enum::YHR_DEVICE_ALGORITHM_DISABLED => Error::AlgorithmDisabled,
        yh_rc_enum::YHR_UNKNOWN_ERROR => Error::Unknown
    }
}

fn code_to_str(return_code: Error) -> &'static str {
    match return_code {
        Error::Success => "Success",
        Error::Memory => "Unable to allocate memory",
        Error::InitError => "Unable to initialize the libyubihsm",
        Error::NetworkError => "Libcurl error",
        Error::ConnectorNotFound => "Unable to find a suitable connector",
        Error::InvalidParams => "Invalid argument to a function",
        Error::WrongLength => "Mismatch between expected and received length",
        Error::BufferTooSmall => "MNot enough space to store data",
        Error::CryptogramMismatch => "Unable to verify cryptogram",
        Error::AuthSessionError => "Unable to authenticate session",
        Error::MacMismatch => "Unable to verify MAC",
        Error::DeviceOk => "No error from the device",
        Error::DeviceInvalidCommand => "Invalid command",
        Error::DeviceInvalidData => "Malformed command / invalid data",
        Error::DeviceInvalidSession => "Invalid session",
        Error::DeviceAuthenticationFailed => "Malformed encryption / verification failed",
        Error::DeviceSessionsFull => "All sessions are allocated",
        Error::DeviceSessionFailed => "Session creation failed",
        Error::DeviceStorageFailed => "Storage failure",
        Error::DeviceWrongLength => "Wrong length",
        Error::DeviceInvalidPermissions => "Wrong permissions for operation",
        Error::DeviceLogFull => "Log buffer is full and forced audit is set",
        Error::DeviceObjectNotFound => "Object not found",
        Error::DeviceIdIllegal => "Illegal ID used",
        Error::DeviceInvalidOtp => "Invalid OTP",
        Error::DeviceDemoMode => "Demo mode, power cycle the device",
        Error::DeviceCmdUnexecuted => "The command execution has not terminated",
        Error::GenericError => "Generic error",
        Error::ObjectExists => "Object with given ID and type already exists",
        Error::ConnectorError => "Connector operation failed",
        Error::SshCaConstraintViolation => "SSH CA constraint violation",
        Error::AlgorithmDisabled => "Algorithm disabled",
        Error::Unknown => "Unknown error"
    }
}

impl From<yh_rc> for Error {
    fn from(return_code: yh_rc) -> Self {
        Self::from(yh_rc_enum::from(return_code))
    }
}

impl From<yh_rc_enum> for Error {
    fn from(return_code: yh_rc_enum) -> Self {
        code_to_err(return_code)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", code_to_str(*self))
    }
}

impl error::Error for Error {
    fn description(&self) -> &str {
        code_to_str(*self)
    }
}

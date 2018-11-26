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

#![allow(non_camel_case_types)]
#![deny(
    missing_docs,
    missing_debug_implementations,
    missing_copy_implementations,
    trivial_casts,
    trivial_numeric_casts,
    unstable_features,
    unused_import_braces,
    unused_qualifications
)]

//! FFI bindings for libyubihsm

pub use self::error::*;

use std::os::raw::{c_char, c_int, c_uint};

/// Errors constants and strings returned by the C library
pub mod error;

/// Length of context array for authentication
pub const YH_CONTEXT_LEN: usize = 16;
/// Length of host challenge for authentication
pub const YH_HOST_CHAL_LEN: usize = 8;
/// Maximum length of message buffer
pub const YH_MSG_BUF_SIZE: c_uint = 2048;
/// Length of authentication keys
pub const YH_KEY_LEN: usize = 16;
/// Device vendor ID
pub const YH_VID: c_uint = 0x1050;
/// Device product ID
pub const YH_PID: c_uint = 0x0030;
/// Response flag for commands
pub const YH_CMD_RESP_FLAG: c_uint = 0x80;
/// Max session the device may hold
pub const YH_MAX_SESSIONS: c_uint = 16;
/// Default encryption key
pub const YH_DEFAULT_ENC_KEY: [u8; YH_KEY_LEN] = [
    0x09, 0x0b, 0x47, 0xdb, 0xed, 0x59, 0x56, 0x54, 0x90, 0x1d, 0xee, 0x1c, 0xc6, 0x55, 0xe4, 0x20,
];
/// Default MAC key
pub const YH_DEFAULT_MAC_KEY: [u8; YH_KEY_LEN] = [
    0x59, 0x2f, 0xd4, 0x83, 0xf7, 0x59, 0xe2, 0x99, 0x09, 0xa0, 0x4c, 0x45, 0x05, 0xd2, 0xce, 0x0a,
];

/// Default authentication key password
pub const YH_DEFAULT_PASSWORD: &[u8; 9usize] = b"password\x00";
/// Salt to be used for PBKDF2 key derivation
pub const YH_DEFAULT_SALT: &[u8; 7usize] = b"Yubico\x00";
/// Number of iterations for PBKDF2 key derivation
pub const YH_DEFAULT_ITERS: c_uint = 10000;
/// Length of capabilities array
pub const YH_CAPABILITIES_LEN: usize = 8;
/// Max log entries the device may hold
pub const YH_MAX_LOG_ENTRIES: c_uint = 64;
/// Length of object labels
pub const YH_OBJ_LABEL_LEN: usize = 40;
/// Max number of domains
pub const YH_MAX_DOMAINS: c_uint = 16;

// Verbosity levels
/// Verbosity disabled
pub const YH_VERB_QUIET: c_uint = 0x00;
/// Verbosity filter for intermediate values messages
pub const YH_VERB_INTERMEDIATE: c_uint = 0x01;
/// Verbosity filter for crypto messages
pub const YH_VERB_CRYPTO: c_uint = 0x02;
/// Verbosity filter for raw messages
pub const YH_VERB_RAW: c_uint = 0x04;
/// Verbosity filter for info messages
pub const YH_VERB_INFO: c_uint = 0x08;
/// Verbosity filter for error messages
pub const YH_VERB_ERR: c_uint = 0x10;
/// Verbosity fully enabled
pub const YH_VERB_ALL: c_uint = 0xff;

/// Max number of algorithms
pub const YH_MAX_ALGORITHM_COUNT: usize = 256;
/// Size that the log digest is truncated to
pub const YH_LOG_DIGEST_SIZE: usize = 16;
/// Origin is generated
pub const YH_ORIGIN_GENERATED: c_uint = 0x01;
/// Origin is imported
pub const YH_ORIGIN_IMPORTED: c_uint = 0x02;
/// Origin is wrapped, used in combination with objects' original origin
pub const YH_ORIGIN_IMPORTED_WRAPPED: c_uint = 0x10;

#[repr(C)]
#[derive(Debug, Copy, Clone)]
/// Connector handle
pub struct yh_connector {
    _unused: [u8; 0],
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
/// Session handle
pub struct yh_session {
    _unused: [u8; 0],
}

/// Capabilitites representation
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct yh_capabilities {
    /// Capabilities are represented as an 8 byte uint8_t array
    pub capabilities: [u8; YH_CAPABILITIES_LEN],
}

impl Default for yh_capabilities {
    fn default() -> yh_capabilities {
        yh_capabilities {
            capabilities: [0; YH_CAPABILITIES_LEN],
        }
    }
}

#[test]
fn bindgen_test_layout_yh_capabilities() {
    assert_eq!(
        ::std::mem::size_of::<yh_capabilities>(),
        8usize,
        concat!("Size of: ", stringify!(yh_capabilities))
    );
    assert_eq!(
        ::std::mem::align_of::<yh_capabilities>(),
        1usize,
        concat!("Alignment of ", stringify!(yh_capabilities))
    );
    let x: *const _ = unsafe { &(*(0 as *const yh_capabilities)).capabilities };
    assert_eq!(
        x as usize,
        0usize,
        concat!(
            "Alignment of field: ",
            stringify!(yh_capabilities),
            "::",
            stringify!(capabilities)
        )
    );
}

#[repr(u32)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
/// Command byte definitions
pub enum yh_cmd {
    /// Echo, request
    YHC_ECHO = 0x01,
    /// Echo, response
    YHC_ECHO_R = 0x01 | YH_CMD_RESP_FLAG,
    /// Create session, request
    YHC_CREATE_SESSION = 0x03,
    /// Create session, response
    YHC_CREATE_SESSION_R = 0x03 | YH_CMD_RESP_FLAG,
    /// Authenticate session, request
    YHC_AUTHENTICATE_SESSION = 0x04,
    /// Authenticate session, response
    YHC_AUTHENTICATE_SESSION_R = 0x04 | YH_CMD_RESP_FLAG,
    /// Session message, request
    YHC_SESSION_MESSAGE = 0x05,
    /// Session message, response
    YHC_SESSION_MESSAGE_R = 0x05 | YH_CMD_RESP_FLAG,
    /// Get device info, request
    YHC_GET_DEVICE_INFO = 0x06,
    /// Get device info, response
    YHC_GET_DEVICE_INFO_R = 0x06 | YH_CMD_RESP_FLAG,
    /// Reset device, request
    YHC_RESET_DEVICE = 0x08,
    /// Reset device, response
    YHC_RESET_DEVICE_R = 0x08 | YH_CMD_RESP_FLAG,
    /// Close session, request
    YHC_CLOSE_SESSION = 0x40,
    /// Close session, response
    YHC_CLOSE_SESSION_R = 0x40 | YH_CMD_RESP_FLAG,
    /// Get storage statistics, request
    YHC_GET_STORAGE_INFO = 0x41,
    /// Get storage statistics, response
    YHC_GET_STORAGE_INFO_R = 0x41 | YH_CMD_RESP_FLAG,
    /// Put opaque object, request
    YHC_PUT_OPAQUE = 0x42,
    /// Put opaque object, response
    YHC_PUT_OPAQUE_R = 0x42 | YH_CMD_RESP_FLAG,
    /// Get opaque object, request
    YHC_GET_OPAQUE = 0x43,
    /// Get opaque object, response
    YHC_GET_OPAQUE_R = 0x43 | YH_CMD_RESP_FLAG,
    /// Put authkey, request
    YHC_PUT_AUTHENTICATION_KEY = 0x44,
    /// Put authkey, response
    YHC_PUT_AUTHENTICATION_KEY_R = 0x44 | YH_CMD_RESP_FLAG,
    /// Put asymmetric key, request
    YHC_PUT_ASYMMETRIC_KEY = 0x45,
    /// Put asymmetric key, response
    YHC_PUT_ASYMMETRIC_KEY_R = 0x45 | YH_CMD_RESP_FLAG,
    /// Generate asymmetric key, request
    YHC_GENERATE_ASYMMETRIC_KEY = 0x46,
    /// Generate asymmetric key, response
    YHC_GENENERATE_ASYMMETRIC_KEY_R = 0x46 | YH_CMD_RESP_FLAG,
    /// Sign data with RSA-PKCS1v1.5, request
    YHC_SIGN_PKCS1 = 0x47,
    /// Sign data with RSA-PKCS1v1.5, response
    YHC_SIGN_PKCS1_R = 0x47 | YH_CMD_RESP_FLAG,
    /// List objects, request
    YHC_LIST_OBJECTS = 0x48,
    /// List objects, response
    YHC_LIST_OBJECTS_R = 0x48 | YH_CMD_RESP_FLAG,
    /// Decrypt data with RSA-PKCS1v1.5, request
    YHC_DECRYPT_PKCS1 = 0x49,
    /// Decrypt data with RSA-PKCS1v1.5, response
    YHC_DECRYPT_PKCS1_R = 0x49 | YH_CMD_RESP_FLAG,
    /// Export an object wrapped, request
    YHC_EXPORT_WRAPPED = 0x4a,
    /// Export an object warpped, response
    YHC_EXPORT_WRAPPED_R = 0x4a | YH_CMD_RESP_FLAG,
    /// Import a wrapped object, request
    YHC_IMPORT_WRAPPED = 0x4b,
    /// Import a wrapped object, response
    YHC_IMPORT_WRAPPED_R = 0x4b | YH_CMD_RESP_FLAG,
    /// Put a wrapkey, request
    YHC_PUT_WRAP_KEY = 0x4c,
    /// Put a wrapkey, response
    YHC_PUT_WRAP_KEY_R = 0x4c | YH_CMD_RESP_FLAG,
    /// Get audit logs, request
    YHC_GET_LOG_ENTRIES = 0x4d,
    /// Get audit logs, response
    YHC_GET_LOG_ENTRIES_R = 0x4d | YH_CMD_RESP_FLAG,
    /// Get object information, request
    YHC_GET_OBJECT_INFO = 0x4e,
    /// Get object information, response
    YHC_GET_OBJECT_INFO_R = 0x4e | YH_CMD_RESP_FLAG,
    /// Set a global option, request
    YHC_SET_OPTION = 0x4f,
    /// Set a global option, response
    YHC_SET_OPTION_R = 0x4f | YH_CMD_RESP_FLAG,
    /// Get a global option, request
    YHC_GET_OPTION = 0x50,
    /// Get a global option, response
    YHC_GET_OPTION_R = 0x50 | YH_CMD_RESP_FLAG,
    /// Get pseudo random data, request
    YHC_GET_PSEUDO_RANDOM = 0x51,
    /// Get pseudo random data, response
    YHC_GET_PSEUDO_RANDOM_R = 0x51 | YH_CMD_RESP_FLAG,
    /// Put HMAC key, request
    YHC_PUT_HMAC_KEY = 0x52,
    /// Put HMAC key, response
    YHC_PUT_HMAC_KEY_R = 0x52 | YH_CMD_RESP_FLAG,
    /// Sign data with HMAC, request
    YHC_SIGN_HMAC = 0x53,
    /// Sign data with HMAC, response
    YHC_SIGN_HMAC_R = 0x53 | YH_CMD_RESP_FLAG,
    /// Get a public key, request
    YHC_GET_PUBLIC_KEY = 0x54,
    /// Get a public key, response
    YHC_GET_PUBLIC_KEY_R = 0x54 | YH_CMD_RESP_FLAG,
    /// Sign data using RSA-PSS, request
    YHC_SIGN_PSS = 0x55,
    /// Sign data using RSA-PSS, response
    YHC_SIGN_PSS_R = 0x55 | YH_CMD_RESP_FLAG,
    /// Sign data using ECDSA, request
    YHC_SIGN_ECDSA = 0x56,
    /// Sign data using ECDSA, response
    YHC_SIGN_ECDSA_R = 0x56 | YH_CMD_RESP_FLAG,
    /// Perform a ECDH exchange, request
    YHC_DERIVE_ECDH = 0x57,
    /// Perform a ECDH exchange, response
    YHC_DERIVE_ECDH_R = 0x57 | YH_CMD_RESP_FLAG,
    /// Delete an object, request
    YHC_DELETE_OBJECT = 0x58,
    /// Delete an object, response
    YHC_DELETE_OBJECT_R = 0x58 | YH_CMD_RESP_FLAG,
    /// Decyrpt data using RSA-OAEP, request
    YHC_DECRYPT_OAEP = 0x59,
    /// Decyrpt data using RSA-OAEP, response
    YHC_DECRYPT_OAEP_R = 0x59 | YH_CMD_RESP_FLAG,
    /// Generate HMAC key, request
    YHC_GENERATE_HMAC_KEY = 0x5a,
    /// Generate HMAC key, response
    YHC_GENERATE_HMAC_KEY_R = 0x5a | YH_CMD_RESP_FLAG,
    /// Generate wrap key, request
    YHC_GENERATE_WRAP_KEY = 0x5b,
    /// Generate wrap key, response
    YHC_GENERATE_WRAP_KEY_R = 0x5b | YH_CMD_RESP_FLAG,
    /// Verify HMAC data, request
    YHC_VERIFY_HMAC = 0x5c,
    /// Verify HMAC data, response
    YHC_VERIFY_HMAC_R = 0x5c | YH_CMD_RESP_FLAG,
    /// Sign SSH certificate
    YHC_SIGN_SSH_CERTIFICATE = 0x5d,
    /// Sign SSH certificate
    YHC_SIGN_SSH_CERTIFICATE_R = 0x5d | YH_CMD_RESP_FLAG,
    /// Put template, request
    YHC_PUT_TEMPLATE = 0x5e,
    /// Put template, response
    YHC_PUT_TEMPLATE_R = 0x5e | YH_CMD_RESP_FLAG,
    /// Get template, request
    YHC_GET_TEMPLATE = 0x5f,
    /// Get template, response
    YHC_GET_TEMPLATE_R = 0x5f | YH_CMD_RESP_FLAG,
    /// Decrypt OTP, request
    YHC_DECRYPT_OTP = 0x60,
    /// Decrypt OTP, response
    YHC_DECRYPT_OTP_R = 0x60 | YH_CMD_RESP_FLAG,
    /// Create OTP AEAD, request
    YHC_CREATE_OTP_AEAD = 0x61,
    /// Create OTP AEAD, response
    YHC_CREATE_OTP_AEAD_R = 0x61 | YH_CMD_RESP_FLAG,
    /// Generate OTP AEAD from random, request
    YHC_RANDOMIZE_OTP_AEAD = 0x62,
    /// Generate OTP AEAD from random, response
    YHC_RANDOMIZE_OTP_AEAD_R = 0x62 | YH_CMD_RESP_FLAG,
    /// Rewrap OTP AEAD, request
    YHC_REWRAP_OTP_AEAD = 0x63,
    /// Rewrap OTP AEAD, response
    YHC_REWRAP_OTP_AEAD_R = 0x63 | YH_CMD_RESP_FLAG,
    /// Sign attestation certificate, request
    YHC_SIGN_ATTESTATION_CERTIFICATE = 0x64,
    /// Sign attestaton certificate, response
    YHC_SIGN_ATTESTATION_CERTIFICATE_R = 0x64 | YH_CMD_RESP_FLAG,
    /// Put OTP AEAD, request
    YHC_PUT_OTP_AEAD_KEY = 0x65,
    /// Put OTP AEAD, response
    YHC_PUT_OTP_AEAD_KEY_R = 0x65 | YH_CMD_RESP_FLAG,
    /// Generate OTP AEAD key, request
    YHC_GENERATE_OTP_AEAD_KEY = 0x66,
    /// Generate OTP AEAD key, response
    YHC_GENERATE_OTP_AEAD_KEY_R = 0x66 | YH_CMD_RESP_FLAG,
    /// Set log index, request
    YHC_SET_LOG_INDEX = 0x67,
    /// Set log index, response
    YHC_SET_LOG_INDEX_R = 0x67 | YH_CMD_RESP_FLAG,
    /// Wrap data, request
    YHC_WRAP_DATA = 0x68,
    /// Wrap data, response
    YHC_WRAP_DATA_R = 0x68 | YH_CMD_RESP_FLAG,
    /// Unwrap data, request
    YHC_UNWRAP_DATA = 0x69,
    /// Unwrap data, response
    YHC_UNWRAP_DATA_R = 0x69 | YH_CMD_RESP_FLAG,
    /// Sign data with EDDSA, request
    YHC_SIGN_EDDSA = 0x6a,
    /// Sign data with EDDSA, response
    YHC_SIGN_EDDSA_R = 0x6a | YH_CMD_RESP_FLAG,
    /// Blink the device, request
    YHC_BLINK_DEVICE = 0x6b,
    /// Blink the device, response
    YHC_BLINK_DEVICE_R = 0x6b | YH_CMD_RESP_FLAG,
    /// Change Authentication key, request
    YHC_CHANGE_AUTHENTICATION_KEY = 0x6c,
    /// Change Authentication key, response
    YHC_CHANGE_AUTHENTICATION_KEY_R = 0x6c | YH_CMD_RESP_FLAG,
    /// Error
    YHC_ERROR = 0x7f,
}

#[repr(u32)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
/// Object types
pub enum yh_object_type {
    /// Any object type (convenience value, not in libyubihsm)
    YH_ANY = 0x00,
    /// Opaque object
    YH_OPAQUE = 0x01,
    /// Authentication key
    YH_AUTHENTICATION_KEY = 0x02,
    /// Asymmetric key
    YH_ASYMMETRIC_KEY = 0x03,
    /// Wrap key
    YH_WRAP_KEY = 0x04,
    /// HMAC key
    YH_HMAC_KEY = 0x05,
    /// Template
    YH_TEMPLATE = 0x06,
    /// OTP AEAD key
    YH_OTP_AEAD_KEY = 0x07,
    /// Public key (virtual)
    YH_PUBLIC_KEY = 0x83,
}

impl Default for yh_object_type {
    fn default() -> yh_object_type {
        yh_object_type::YH_ANY
    }
}

#[repr(u32)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
/// Algorithms
pub enum yh_algorithm {
    /// Any algorithm (convenience value, not in libyubihsm)
    YH_ALGO_ANY = 0,
    /// RSA PKCS1v1.5 with SHA1
    YH_ALGO_RSA_PKCS1_SHA1 = 1,
    /// RSA PKCS1v1.5 with SH256
    YH_ALGO_RSA_PKCS1_SHA256 = 2,
    /// RSA PKCS1v1.5 with SHA384
    YH_ALGO_RSA_PKCS1_SHA384 = 3,
    /// RSA PKCS1v1.5 with SHA512
    YH_ALGO_RSA_PKCS1_SHA512 = 4,
    /// RSA PSS with SHA1
    YH_ALGO_RSA_PSS_SHA1 = 5,
    /// RSA PSS with SHA256
    YH_ALGO_RSA_PSS_SHA256 = 6,
    /// RSA PSS with SHA384
    YH_ALGO_RSA_PSS_SHA384 = 7,
    /// RSA PSS with SHA512
    YH_ALGO_RSA_PSS_SHA512 = 8,
    /// RSA 2048
    YH_ALGO_RSA_2048 = 9,
    /// RSA 3072
    YH_ALGO_RSA_3072 = 10,
    /// RSA 4096
    YH_ALGO_RSA_4096 = 11,
    /// SEC-P256 curve
    YH_ALGO_EC_P256 = 12,
    /// SEC-P384 curve
    YH_ALGO_EC_P384 = 13,
    /// SEC-P521 curve
    YH_ALGO_EC_P521 = 14,
    /// K256 curve
    YH_ALGO_EC_K256 = 15,
    /// Brainpool P256 curve
    YH_ALGO_EC_BP256 = 16,
    /// Brainpool P384 curve
    YH_ALGO_EC_BP384 = 17,
    /// Brainpool P512 curve
    YH_ALGO_EC_BP512 = 18,
    /// HMAC-SHA1
    YH_ALGO_HMAC_SHA1 = 19,
    /// HMAC-SHA256
    YH_ALGO_HMAC_SHA256 = 20,
    /// HMAC-SHA384
    YH_ALGO_HMAC_SHA384 = 21,
    /// HMAC-SHA512
    YH_ALGO_HMAC_SHA512 = 22,
    /// ECDSA-SHA1
    YH_ALGO_EC_ECDSA_SHA1 = 23,
    /// ECDH
    YH_ALGO_EC_ECDH = 24,
    /// RSA-OAEP with SHA1
    YH_ALGO_RSA_OAEP_SHA1 = 25,
    /// RSA-OAEP with SHA256
    YH_ALGO_RSA_OAEP_SHA256 = 26,
    /// RSA-OAEP with SHA384
    YH_ALGO_RSA_OAEP_SHA384 = 27,
    /// RSA-OAEP with SHA512
    YH_ALGO_RSA_OAEP_SHA512 = 28,
    /// AES-128 CCM wrap
    YH_ALGO_AES128_CCM_WRAP = 29,
    /// Opaque data
    YH_ALGO_OPAQUE_DATA = 30,
    /// Opaque X.509
    YH_ALGO_OPAQUE_X509_CERTIFICATE = 31,
    /// MGF1 with SHA1
    YH_ALGO_MGF1_SHA1 = 32,
    /// MGF1 with SHA256
    YH_ALGO_MGF1_SHA256 = 33,
    /// MGF1 with SHA384
    YH_ALGO_MGF1_SHA384 = 34,
    /// MGF1 with SHA512
    YH_ALGO_MGF1_SHA512 = 35,
    /// Template
    YH_ALGO_TEMPLATE_SSH = 36,
    /// Yubico OTP with AES-128
    YH_ALGO_AES128_YUBICO_OTP = 37,
    /// Yubico AES auhtentication
    YH_ALGO_AES128_YUBICO_AUTHENTICATION = 38,
    /// Yubico OTP with AES-192
    YH_ALGO_AES192_YUBICO_OTP = 39,
    /// Yubico OTP with AES-256
    YH_ALGO_AES256_YUBICO_OTP = 40,
    /// AES-192 CCM wrap
    YH_ALGO_AES192_CCM_WRAP = 41,
    /// AES-256 CCM wrap
    YH_ALGO_AES256_CCM_WRAP = 42,
    /// ECDSA with SHA256
    YH_ALGO_EC_ECDSA_SHA256 = 43,
    /// ECDSA with SHA384
    YH_ALGO_EC_ECDSA_SHA384 = 44,
    /// ECDSA with SHA512
    YH_ALGO_EC_ECDSA_SHA512 = 45,
    /// ED25519 curve
    YH_ALGO_EC_ED25519 = 46,
    /// SEC-P224 curve
    YH_ALGO_EC_P224 = 47,
}

impl Default for yh_algorithm {
    fn default() -> yh_algorithm {
        yh_algorithm::YH_ALGO_ANY
    }
}

#[repr(u32)]
/// Device-global options
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum yh_option {
    /// Forced audit mode
    YH_OPTION_FORCE_AUDIT = 1,
    /// Audit logging per command
    YH_OPTION_COMMAND_AUDIT = 3,
}

#[repr(u32)]
/// Connector options
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum yh_connector_option {
    /// File with CA certificate to validate the connector with (const char *) not
    /// implemented on Windows
    YH_CONNECTOR_HTTPS_CA = 1,
    /// Proxy server to use for connecting to the connector (const char *) not
    /// implemented on Windows
    YH_CONNECTOR_PROXY_SERVER = 2,
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
/// Logging struct as returned by device
pub struct yh_log_entry {
    /// Monotonically increasing index
    pub number: u16,
    /// What command was executed @see yh_cmd
    pub command: u8,
    /// Length of in-data
    pub length: u16,
    /// ID of authentication key used
    pub session_key: u16,
    /// ID of first object used
    pub target_key: u16,
    /// ID of second object used
    pub second_key: u16,
    /// Command result @see yh_cmd
    pub result: u8,
    /// Systick at time of execution
    pub systick: u32,
    /// Truncated sha256 digest of this last digest + this entry
    pub digest: [u8; YH_LOG_DIGEST_SIZE],
}

#[test]
fn bindgen_test_layout_yh_log_entry() {
    assert_eq!(
        ::std::mem::size_of::<yh_log_entry>(),
        32usize,
        concat!("Size of: ", stringify!(yh_log_entry))
    );
    assert_eq!(
        ::std::mem::align_of::<yh_log_entry>(),
        1usize,
        concat!("Alignment of ", stringify!(yh_log_entry))
    );
    let x: *const _ = unsafe { &(*(0 as *const yh_log_entry)).number };
    assert_eq!(
        x as usize,
        0usize,
        concat!(
            "Alignment of field: ",
            stringify!(yh_log_entry),
            "::",
            stringify!(number)
        )
    );
    let x: *const _ = unsafe { &(*(0 as *const yh_log_entry)).command };
    assert_eq!(
        x as usize,
        2usize,
        concat!(
            "Alignment of field: ",
            stringify!(yh_log_entry),
            "::",
            stringify!(command)
        )
    );
    let x: *const _ = unsafe { &(*(0 as *const yh_log_entry)).length };
    assert_eq!(
        x as usize,
        3usize,
        concat!(
            "Alignment of field: ",
            stringify!(yh_log_entry),
            "::",
            stringify!(length)
        )
    );
    let x: *const _ = unsafe { &(*(0 as *const yh_log_entry)).session_key };
    assert_eq!(
        x as usize,
        5usize,
        concat!(
            "Alignment of field: ",
            stringify!(yh_log_entry),
            "::",
            stringify!(session_key)
        )
    );
    let x: *const _ = unsafe { &(*(0 as *const yh_log_entry)).target_key };
    assert_eq!(
        x as usize,
        7usize,
        concat!(
            "Alignment of field: ",
            stringify!(yh_log_entry),
            "::",
            stringify!(target_key)
        )
    );
    let x: *const _ = unsafe { &(*(0 as *const yh_log_entry)).second_key };
    assert_eq!(
        x as usize,
        9usize,
        concat!(
            "Alignment of field: ",
            stringify!(yh_log_entry),
            "::",
            stringify!(second_key)
        )
    );
    let x: *const _ = unsafe { &(*(0 as *const yh_log_entry)).result };
    assert_eq!(
        x as usize,
        11usize,
        concat!(
            "Alignment of field: ",
            stringify!(yh_log_entry),
            "::",
            stringify!(result)
        )
    );
    let x: *const _ = unsafe { &(*(0 as *const yh_log_entry)).systick };
    assert_eq!(
        x as usize,
        12usize,
        concat!(
            "Alignment of field: ",
            stringify!(yh_log_entry),
            "::",
            stringify!(systick)
        )
    );
    let x: *const _ = unsafe { &(*(0 as *const yh_log_entry)).digest };
    assert_eq!(
        x as usize,
        16usize,
        concat!(
            "Alignment of field: ",
            stringify!(yh_log_entry),
            "::",
            stringify!(digest)
        )
    );
}

#[repr(C, packed)]
/// Label handle
pub struct yh_label {
    /// Label
    pub label: [::std::os::raw::c_char; YH_OBJ_LABEL_LEN + 1],
}

impl ToString for yh_label {
    fn to_string(&self) -> String {
        String::from(
            unsafe { ::std::ffi::CStr::from_ptr(&self.label[0]) }
                .to_str()
                .unwrap(),
        )
    }
}

impl ::std::fmt::Debug for yh_label {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl Default for yh_label {
    fn default() -> yh_label {
        yh_label {
            label: [0; YH_OBJ_LABEL_LEN + 1],
        }
    }
}

impl Clone for yh_label {
    fn clone(&self) -> yh_label {
        yh_label { label: self.label }
    }
}

impl Copy for yh_label {}

#[repr(C, packed)]
#[derive(Debug, Default, Clone, Copy)]
/// Object descriptor
pub struct yh_object_descriptor {
    /// Object capabilities @see yh_capabilities
    pub capabilities: yh_capabilities,
    /// Object ID
    pub id: u16,
    /// Object length
    pub len: u16,
    /// Object domains
    pub domains: u16,
    /// Object type
    pub type_: yh_object_type,
    /// Object algorithm
    pub algorithm: yh_algorithm,
    /// Object sequence
    pub sequence: u8,
    /// Object origin
    pub origin: u8,
    /// Object label
    pub label: yh_label,
    /// Object delegated capabilities
    pub delegated_capabilities: yh_capabilities,
}

#[test]
fn bindgen_test_layout_yh_object_descriptor() {
    assert_eq!(
        ::std::mem::size_of::<yh_object_descriptor>(),
        73usize,
        concat!("Size of: ", stringify!(yh_object_descriptor))
    );
    assert_eq!(
        ::std::mem::align_of::<yh_object_descriptor>(),
        1usize,
        concat!("Alignment of ", stringify!(yh_object_descriptor))
    );
    let x: *const _ = unsafe { &(*(0 as *const yh_object_descriptor)).capabilities };
    assert_eq!(
        x as usize,
        0usize,
        concat!(
            "Alignment of field: ",
            stringify!(yh_object_descriptor),
            "::",
            stringify!(capabilities)
        )
    );
    let x: *const _ = unsafe { &(*(0 as *const yh_object_descriptor)).id };
    assert_eq!(
        x as usize,
        8usize,
        concat!(
            "Alignment of field: ",
            stringify!(yh_object_descriptor),
            "::",
            stringify!(id)
        )
    );
    let x: *const _ = unsafe { &(*(0 as *const yh_object_descriptor)).len };
    assert_eq!(
        x as usize,
        10usize,
        concat!(
            "Alignment of field: ",
            stringify!(yh_object_descriptor),
            "::",
            stringify!(len)
        )
    );
    let x: *const _ = unsafe { &(*(0 as *const yh_object_descriptor)).domains };
    assert_eq!(
        x as usize,
        12usize,
        concat!(
            "Alignment of field: ",
            stringify!(yh_object_descriptor),
            "::",
            stringify!(domains)
        )
    );
    let x: *const _ = unsafe { &(*(0 as *const yh_object_descriptor)).type_ };
    assert_eq!(
        x as usize,
        14usize,
        concat!(
            "Alignment of field: ",
            stringify!(yh_object_descriptor),
            "::",
            stringify!(type_)
        )
    );
    let x: *const _ = unsafe { &(*(0 as *const yh_object_descriptor)).algorithm };
    assert_eq!(
        x as usize,
        18usize,
        concat!(
            "Alignment of field: ",
            stringify!(yh_object_descriptor),
            "::",
            stringify!(algorithm)
        )
    );
    let x: *const _ = unsafe { &(*(0 as *const yh_object_descriptor)).sequence };
    assert_eq!(
        x as usize,
        22usize,
        concat!(
            "Alignment of field: ",
            stringify!(yh_object_descriptor),
            "::",
            stringify!(sequence)
        )
    );
    let x: *const _ = unsafe { &(*(0 as *const yh_object_descriptor)).origin };
    assert_eq!(
        x as usize,
        23usize,
        concat!(
            "Alignment of field: ",
            stringify!(yh_object_descriptor),
            "::",
            stringify!(origin)
        )
    );
    let x: *const _ = unsafe { &(*(0 as *const yh_object_descriptor)).label };
    assert_eq!(
        x as usize,
        24usize,
        concat!(
            "Alignment of field: ",
            stringify!(yh_object_descriptor),
            "::",
            stringify!(label)
        )
    );
    let x: *const _ = unsafe { &(*(0 as *const yh_object_descriptor)).delegated_capabilities };
    assert_eq!(
        x as usize,
        65usize,
        concat!(
            "Alignment of field: ",
            stringify!(yh_object_descriptor),
            "::",
            stringify!(delegated_capabilities)
        )
    );
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
/// Capabilities
pub struct yh_cap {
    /// Name
    pub name: *const c_char,
    /// Bit
    pub bit: c_int,
}

#[test]
fn bindgen_test_layout_yh_cap() {
    assert_eq!(
        ::std::mem::size_of::<yh_cap>(),
        16usize,
        concat!("Size of: ", stringify!(yh_cap))
    );
    assert_eq!(
        ::std::mem::align_of::<yh_cap>(),
        8usize,
        concat!("Alignment of ", stringify!(yh_cap))
    );
    let x: *const _ = unsafe { &(*(0 as *const yh_cap)).name };
    assert_eq!(
        x as usize,
        0usize,
        concat!(
            "Alignment of field: ",
            stringify!(yh_cap),
            "::",
            stringify!(name)
        )
    );
    let x: *const _ = unsafe { &(*(0 as *const yh_cap)).bit };
    assert_eq!(
        x as usize,
        8usize,
        concat!(
            "Alignment of field: ",
            stringify!(yh_cap),
            "::",
            stringify!(bit)
        )
    );
}

extern "C" {
    #[link_name = "yh_capability"]
    pub static mut yh_capability: [yh_cap; 47usize];
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
/// Algorithms
pub struct yh_algo {
    /// Name
    pub name: *const c_char,
    /// Algorithm
    pub algorithm: yh_algorithm,
}

#[test]
fn bindgen_test_layout_yh_algo() {
    assert_eq!(
        ::std::mem::size_of::<yh_algo>(),
        16usize,
        concat!("Size of: ", stringify!(yh_algo))
    );
    assert_eq!(
        ::std::mem::align_of::<yh_algo>(),
        8usize,
        concat!("Alignment of ", stringify!(yh_algo))
    );
    let x: *const _ = unsafe { &(*(0 as *const yh_algo)).name };
    assert_eq!(
        x as usize,
        0usize,
        concat!(
            "Alignment of field: ",
            stringify!(yh_algo),
            "::",
            stringify!(name)
        )
    );
    let x: *const _ = unsafe { &(*(0 as *const yh_algo)).algorithm };
    assert_eq!(
        x as usize,
        8usize,
        concat!(
            "Alignment of field: ",
            stringify!(yh_algo),
            "::",
            stringify!(algorithm)
        )
    );
}

extern "C" {
    #[link_name = "yh_algorithms"]
    pub static mut yh_algorithms: [yh_algo; 46usize];
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
/// Object types
pub struct yh_ot {
    /// Name
    pub name: *const c_char,
    /// Object type
    pub type_: yh_object_type,
}

#[test]
fn bindgen_test_layout_yh_ot() {
    assert_eq!(
        ::std::mem::size_of::<yh_ot>(),
        16usize,
        concat!("Size of: ", stringify!(yh_ot))
    );
    assert_eq!(
        ::std::mem::align_of::<yh_ot>(),
        8usize,
        concat!("Alignment of ", stringify!(yh_ot))
    );
    let x: *const _ = unsafe { &(*(0 as *const yh_ot)).name };
    assert_eq!(
        x as usize,
        0usize,
        concat!(
            "Alignment of field: ",
            stringify!(yh_ot),
            "::",
            stringify!(name)
        )
    );
    let x: *const _ = unsafe { &(*(0 as *const yh_ot)).type_ };
    assert_eq!(
        x as usize,
        8usize,
        concat!(
            "Alignment of field: ",
            stringify!(yh_ot),
            "::",
            stringify!(type_)
        )
    );
}

extern "C" {
    #[link_name = "yh_types"]
    pub static mut yh_types: [yh_ot; 7usize];
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
/// Options
pub struct yh_opt {
    /// Name
    pub name: *const c_char,
    /// Option
    pub option: yh_option,
}

#[test]
fn bindgen_test_layout_yh_opt() {
    assert_eq!(
        ::std::mem::size_of::<yh_opt>(),
        16usize,
        concat!("Size of: ", stringify!(yh_opt))
    );
    assert_eq!(
        ::std::mem::align_of::<yh_opt>(),
        8usize,
        concat!("Alignment of ", stringify!(yh_opt))
    );
    let x: *const _ = unsafe { &(*(0 as *const yh_opt)).name };
    assert_eq!(
        x as usize,
        0usize,
        concat!(
            "Alignment of field: ",
            stringify!(yh_opt),
            "::",
            stringify!(name)
        )
    );
    let x: *const _ = unsafe { &(*(0 as *const yh_opt)).option };
    assert_eq!(
        x as usize,
        8usize,
        concat!(
            "Alignment of field: ",
            stringify!(yh_opt),
            "::",
            stringify!(option)
        )
    );
}

extern "C" {
    #[link_name = "yh_options"]
    pub static mut yh_options: [yh_opt; 2usize];
}

extern "C" {
    /**
     * Return a string describing an error condition
     *
     * @param err yh_rc error code
     *
     * @return String with descriptive error
     **/
    pub fn yh_strerror(err: yh_rc) -> *const c_char;
}

extern "C" {
    /**
     * Set verbosity
     * This function may be called prior to global library initialization.
     *
     * @param verbosity
     *
     * @return yh_rc error code
     **/
    pub fn yh_set_verbosity(connector: *const yh_connector, verbosity: u8) -> yh_rc;
}

extern "C" {
    /**
     * Get verbosity
     *
     * @param verbosity
     *
     * @return yh_rc error code
     **/
    pub fn yh_get_verbosity(verbosity: *mut u8) -> yh_rc;
}

extern "C" {
    /**
     * Global library initialization
     *
     * @return yh_rc error code
     **/
    pub fn yh_init() -> yh_rc;
}

extern "C" {
    /**
     * Global library cleanup
     *
     * @return yh_rc error code
     **/
    pub fn yh_exit() -> yh_rc;
}

extern "C" {
    /**
     * Instantiate a new connector
     *
     * @param url URL to associate with this connector
     * @param connector reference to connector
     */
    pub fn yh_init_connector(url: *const c_char, connector: *const *mut yh_connector) -> yh_rc;
}

// TODO(adma): FIXME set_connector_options

extern "C" {
    /**
     * Connect to connector
     *
     * @param connector connector to connect to
     *
     * @return yh_rc error code
     **/
    pub fn yh_connect(connectors: *const yh_connector) -> yh_rc;
}

extern "C" {
    /**
     * Disconnect from connector
     *
     * @param connector connector to disconnect from
     *
     * @return yh_rc error code
     **/
    pub fn yh_disconnect(connector: *const yh_connector) -> yh_rc;
}

extern "C" {
    /**
     * Send a plain message to a connector
     *
     * @param connector connector to send to
     * @param cmd command to send
     * @param data data to send
     * @param data_len data length
     * @param response_cmd response command
     * @param response response data
     * @param response_len response length
     *
     * @return yh_rc error code
     **/
    pub fn yh_send_plain_msg(
        connector: *const yh_connector,
        cmd: yh_cmd,
        data: *const u8,
        data_len: usize,
        response_cmd: *mut yh_cmd,
        response: *mut u8,
        response_len: *mut usize,
    ) -> yh_rc;
}

extern "C" {
    /**
     * Send an encrypted message over a session
     *
     * @param session session to send over
     * @param cmd command to send
     * @param data data to send
     * @param data_len data length
     * @param response_cmd response command
     * @param response response data
     * @param response_len response length
     *
     * @return yh_rc error code
     **/
    pub fn yh_send_secure_msg(
        session: *const yh_session,
        cmd: yh_cmd,
        data: *const u8,
        data_len: usize,
        response_cmd: *mut yh_cmd,
        response: *mut u8,
        response_len: *mut usize,
    ) -> yh_rc;
}
extern "C" {
    /**
     * Create a session with keys derived frm password
     *
     * @param connector connector to create the session with
     * @param authkey_id ID of the authentication key to be used
     * @param password password to derive keys from
     * @param password_len length of the password in bytes
     * @param recreate_session session will be recreated if expired
     * @param session created session
     *
     * @return yh_rc error code
     **/
    pub fn yh_create_session_derived(
        connector: *const yh_connector,
        authkey_id: u16,
        password: *const u8,
        password_len: usize,
        recreate_session: bool,
        session: *const *mut yh_session,
    ) -> yh_rc;
}

extern "C" {
    /**
     * Create a session
     *
     * @param connector connector to create the session with
     * @param authkey_id ID of the authentication key
     * @param key_enc encryption key
     * @param key_enc_len length of encryption key
     * @param key_mac MAC key
     * @param key_mac_len length of MAC key
     * @param recreate_session session will be recreated if expired
     * @param session created session
     *
     * @return yh_rc error code
     **/
    pub fn yh_create_session(
        connector: *const yh_connector,
        authkey_id: u16,
        key_enc: *const u8,
        key_enc_len: usize,
        key_mac: *const u8,
        key_mac_len: usize,
        recreate_session: bool,
        session: *const *mut yh_session,
    ) -> yh_rc;
}

extern "C" {
    /**
     * Begin create extenal session
     *
     * @param connector connector to create the session with
     * @param authkey_id ID of the authentication key
     * @param context context data for the authentication
     * @param card_cryptogram card cryptogram
     * @param card_cryptogram_len catd cryptogram length
     * @param session created session
     *
     * @return yh_rc error code
     **/
    pub fn yh_begin_create_session_ext(
        connector: *const yh_connector,
        authkey_id: u16,
        context: *const *mut u8,
        card_cryptogram: *const u8,
        card_cryptogram_len: usize,
        session: *const *mut yh_session,
    ) -> yh_rc;
}

extern "C" {
    /**
     * Finish creating external session
     *
     * @param connector connector to create the session with
     * @param session session
     * @param key_senc session encryption key
     * @param key_senc_len session encrypt key length
     * @param key_smac session MAC key
     * @param key_smac_len session MAC key length
     * @param key_srmac session return MAC key
     * @param key_srmac_len session return MAC key length
     * @param card_cryptogram card cryptogram
     * @param card_cryptogram_len card cryptogram length
     *
     * @return yh_rc error code
     **/
    pub fn yh_finish_create_session_ext(
        connector: *const yh_connector,
        session: *const yh_session,
        key_senc: *const u8,
        key_senc_len: usize,
        key_smac: *const u8,
        key_smac_len: usize,
        key_srmac: *const u8,
        key_srmac_len: usize,
        card_cryptogram: *const u8,
        card_cryptogram_len: usize,
    ) -> yh_rc;
}

extern "C" {
    /**
     * Free data associated with session
     *
     * @param session session to destroy
     *
     * @return yh_rc error code
     **/
    pub fn yh_destroy_session(session: *const *mut yh_session) -> yh_rc;
}

extern "C" {
    /**
     * Authenticate session
     *
     * @param session session to authenticate
     *
     * @return yh_rc error code
     **/
    pub fn yh_authenticate_session(session: *const yh_session) -> yh_rc;
}

extern "C" {
    /**
     * Get device info
     *
     * @param connector connector to send over
     * @param major version major
     * @param minor version minor
     * @param patch version path
     * @param serial serial number
     * @param log_total total number of log entries
     * @param log_used log entries used
     * @param algorithms algorithms array
     * @param n_algorithms number of algorithms
     *
     * @return yh_rc error code
     **/
    pub fn yh_util_get_device_info(
        connector: *const yh_connector,
        major: *mut u8,
        minor: *mut u8,
        patch: *mut u8,
        serial: *mut u32,
        log_total: *mut u8,
        log_used: *mut u8,
        algorithms: *mut yh_algorithm,
        n_algorithms: *mut usize,
    ) -> yh_rc;
}

extern "C" {
    /**
     * List objects
     *
     * @param session session to use
     * @param id ID to filter by (0 to not filter by ID)
     * @param type Type to filter by (0 to not filter by type) @see yh_object_type
     * @param domains Domains to filter by (0 to not filter by domain)
     * @param capabilities Capabilities to filter by (0 to not filter by
     *capabilities) @see yh_capabilities
     * @param algorithm Algorithm to filter by (0 to not filter by algorithm)
     * @param label Label to filter by
     * @param objects Array of objects returned
     * @param n_objects Max length of objects (will be set to number found on
     *return)
     *
     * @return yh_rc error code
     **/
    pub fn yh_util_list_objects(
        session: *const yh_session,
        id: u16,
        type_: yh_object_type,
        domains: u16,
        capabilities: *const yh_capabilities,
        algorithm: yh_algorithm,
        label: *const c_char,
        objects: *mut yh_object_descriptor,
        n_objects: *mut usize,
    ) -> yh_rc;
}

extern "C" {
    /**
     * Get object info
     *
     * @param session session to use
     * @param id Object ID
     * @param type Object type
     * @param object object information
     *
     * @return yh_rc error code
     **/
    pub fn yh_util_get_object_info(
        session: *const yh_session,
        id: u16,
        type_: yh_object_type,
        object: *mut yh_object_descriptor,
    ) -> yh_rc;
}

extern "C" {
    /**
     * Get Public key
     *
     * @param session session to use
     * @param id Object ID
     * @param data Data out
     * @param data_len Data length
     * @param algorithm Algorithm of object
     *
     * @return yh_rc error code
     **/
    pub fn yh_util_get_public_key(
        session: *const yh_session,
        id: u16,
        data: *mut u8,
        data_len: *mut usize,
        algorithm: *mut yh_algorithm,
    ) -> yh_rc;
}

extern "C" {
    /**
     * Close session
     *
     * @param session session to close
     *
     * @return yh_rc error code
     **/
    pub fn yh_util_close_session(session: *mut yh_session) -> yh_rc;
}

extern "C" {
    /**
     * Sign data using PKCS1 v1.5
     *
     * @param session session to use
     * @param key_id Object ID
     * @param hashed if data is already hashed
     * @param in in data to sign
     * @param in_len length of in
     * @param out signed data
     * @param out_len length of signed data
     *
     * @return yh_rc error code
     **/
    pub fn yh_util_sign_pkcs1v1_5(
        session: *const yh_session,
        key_id: u16,
        hashed: bool,
        in_: *const u8,
        in_len: usize,
        out: *mut u8,
        out_len: *mut usize,
    ) -> yh_rc;
}

extern "C" {
    /**
     * Sign data using RSS
     *
     * @param session session to use
     * @param key_id Object ID
     * @param in data to sign
     * @param in_len length of in
     * @param out signed data
     * @param out_len length of signed data
     * @param salt_len length of salt
     * @param mgf1Algo algorithm for mgf1
     *
     * @return yh_rc error code
     **/
    pub fn yh_util_sign_pss(
        session: *const yh_session,
        key_id: u16,
        in_: *const u8,
        in_len: usize,
        out: *mut u8,
        out_len: *mut usize,
        salt_len: usize,
        mgf1Algo: yh_algorithm,
    ) -> yh_rc;
}

extern "C" {
    /**
     * Sign data using ECDSA
     *
     * @param session session to use
     * @param key_id Object ID
     * @param in data to sign
     * @param in_len length of in
     * @param out signed data
     * @param out_len length of signed data
     *
     * @return yh_rc error code
     **/
    pub fn yh_util_sign_ecdsa(
        session: *const yh_session,
        key_id: u16,
        in_: *const u8,
        in_len: usize,
        out: *mut u8,
        out_len: *mut usize,
    ) -> yh_rc;
}

extern "C" {
    /**
     * Sign data using EDDSA
     *
     * @param session session to use
     * @param key_id Object ID
     * @param in data to sign
     * @param in_len length of in
     * @param out signed data
     * @param out_len length of signed data
     *
     * @return yh_rc error code
     **/
    pub fn yh_util_sign_eddsa(
        session: *const yh_session,
        key_id: u16,
        in_: *const u8,
        in_len: usize,
        out: *mut u8,
        out_len: *mut usize,
    ) -> yh_rc;
}

extern "C" {
    /**
     * Sign data using HMAC
     *
     * @param session session to use
     * @param key_id Object ID
     * @param in data to hmac
     * @param in_len length of in
     * @param out HMAC
     * @param out_len length of HMAC
     *
     * @return yh_rc error code
     **/
    pub fn yh_util_sign_hmac(
        session: *const yh_session,
        key_id: u16,
        in_: *const u8,
        in_len: usize,
        out: *mut u8,
        out_len: *mut usize,
    ) -> yh_rc;
}

extern "C" {
    /**
     * Get pseudo random data
     *
     * @param session session to use
     * @param len length of data to get
     * @param out random data out
     * @param out_len length of random data
     *
     * @return yh_rc error code
     **/
    pub fn yh_util_get_pseudo_random(
        session: *const yh_session,
        len: usize,
        out: *mut u8,
        out_len: *mut usize,
    ) -> yh_rc;
}

extern "C" {
    /**
     * Import RSA key
     *
     * @param session session to use
     * @param key_id Object ID
     * @param label Label
     * @param domains domains
     * @param capabilities capabilities
     * @param algorithm algorithm
     * @param p P
     * @param q Q
     *
     * @return yh_rc error code
     **/
    pub fn yh_util_import_rsa_key(
        session: *const yh_session,
        key_id: *mut u16,
        label: *const c_char,
        domains: u16,
        capabilities: *const yh_capabilities,
        algorithm: yh_algorithm,
        p: *const u8,
        q: *const u8,
    ) -> yh_rc;
}

extern "C" {
    /**
     * Import EC key
     *
     * @param session session to use
     * @param key_id Object ID
     * @param label Label
     * @param domains domains
     * @param capabilities capabilities
     * @param algorithm algorithm
     * @param s S
     *
     * @return yh_rc error code
     **/
    pub fn yh_util_import_ec_key(
        session: *const yh_session,
        key_id: *mut u16,
        label: *const c_char,
        domains: u16,
        capabilities: *const yh_capabilities,
        algorithm: yh_algorithm,
        s: *const u8,
    ) -> yh_rc;
}

extern "C" {
    /**
     * Import ED key
     *
     * @param session session to use
     * @param key_id Object ID
     * @param label Label
     * @param domains domains
     * @param capabilities capabilities
     * @param algorithm algorithm
     * @param k k
     *
     * @return yh_rc error code
     **/
    pub fn yh_util_import_ed_key(
        session: *const yh_session,
        key_id: *mut u16,
        label: *const c_char,
        domains: u16,
        capabilities: *const yh_capabilities,
        algorithm: yh_algorithm,
        k: *const u8,
    ) -> yh_rc;
}

extern "C" {
    /**
     * Import HMAC key
     *
     * @param session session to use
     * @param key_id Object ID
     * @param label Label
     * @param domains domains
     * @param capabilities capabilities
     * @param algorithm algorithm
     * @param key key data
     * @param key_len length of key
     *
     * @return yh_rc error code
     **/
    pub fn yh_util_import_hmac_key(
        session: *const yh_session,
        key_id: *mut u16,
        label: *const c_char,
        domains: u16,
        capabilities: *const yh_capabilities,
        algorithm: yh_algorithm,
        key: *const u8,
        key_len: usize,
    ) -> yh_rc;
}

extern "C" {
    /**
     * Generate RSA key
     *
     * @param session session to use
     * @param key_id Object ID
     * @param label Label
     * @param domains domains
     * @param capabilities capabilities
     * @param algorithm algorithm
     *
     * @return yh_rc error code
     **/
    pub fn yh_util_generate_rsa_key(
        session: *const yh_session,
        key_id: *mut u16,
        label: *const c_char,
        domains: u16,
        capabilities: *const yh_capabilities,
        algorithm: yh_algorithm,
    ) -> yh_rc;
}

extern "C" {
    /**
     * Generate EC key
     *
     * @param session session to use
     * @param key_id Object ID
     * @param label Label
     * @param domains domains
     * @param capabilities capabilities
     * @param algorithm algorithm
     *
     * @return yh_rc error code
     **/
    pub fn yh_util_generate_ec_key(
        session: *const yh_session,
        key_id: *mut u16,
        label: *const c_char,
        domains: u16,
        capabilities: *const yh_capabilities,
        algorithm: yh_algorithm,
    ) -> yh_rc;
}

extern "C" {
    /**
     * Generate ED key
     *
     * @param session session to use
     * @param key_id Object ID
     * @param label Label
     * @param domains domains
     * @param capabilities capabilities
     * @param algorithm algorithm
     *
     * @return yh_rc error code
     **/
    pub fn yh_util_generate_ed_key(
        session: *const yh_session,
        key_id: *mut u16,
        label: *const c_char,
        domains: u16,
        capabilities: *const yh_capabilities,
        algorithm: yh_algorithm,
    ) -> yh_rc;
}

extern "C" {
    /**
     * Verify HMAC data
     *
     * @param session session to use
     * @param key_id Object ID
     * @param signature HMAC
     * @param signature_len HMAC length
     * @param data data to verify
     * @param data_len data length
     * @param verified if verification succeeded
     *
     * @return yh_rc error code
     **/
    pub fn yh_util_verify_hmac(
        session: *const yh_session,
        key_id: u16,
        signature: *const u8,
        signature_len: usize,
        data: *const u8,
        data_len: usize,
        verified: *mut bool,
    ) -> yh_rc;
}

extern "C" {
    /**
     * Generate HMAC key
     *
     * @param session session to use
     * @param key_id Object ID
     * @param label Label
     * @param domains domains
     * @param capabilities capabilities
     * @param algorithm algorithm
     *
     * @return yh_rc error code
     **/
    pub fn yh_util_generate_hmac_key(
        session: *const yh_session,
        key_id: *mut u16,
        label: *const c_char,
        domains: u16,
        capabilities: *const yh_capabilities,
        algorithm: yh_algorithm,
    ) -> yh_rc;
}

extern "C" {
    /**
     * Decrypt PKCS1 v1.5 data
     *
     * @param session session to use
     * @param key_id Object ID
     * @param in Encrypted data
     * @param in_len length of encrypted data
     * @param out Decrypted data
     * @param out_len length of decrypted data
     *
     * @return yh_rc error code
     **/
    pub fn yh_util_decrypt_pkcs1v1_5(
        session: *const yh_session,
        key_id: u16,
        in_: *const u8,
        in_len: usize,
        out: *mut u8,
        out_len: *mut usize,
    ) -> yh_rc;
}

extern "C" {
    /**
     * Decrypt OAEP data
     *
     * @param session session to use
     * @param key_id Object ID
     * @param in Encrypted data
     * @param in_len length of encrypted data
     * @param out Decrypted data
     * @param out_len length of decrypted data
     * @param label OAEP label
     * @param label_len label length
     * @param mgf1Algo MGF1 algorithm
     *
     * @return yh_rc error code
     **/
    pub fn yh_util_decrypt_oaep(
        session: *const yh_session,
        key_id: u16,
        in_: *const u8,
        in_len: usize,
        out: *mut u8,
        out_len: *mut usize,
        label: *const u8,
        label_len: usize,
        mgf1Algo: yh_algorithm,
    ) -> yh_rc;
}

extern "C" {
    /**
     * Perform ECDH key exchange
     *
     * @param session session to use
     * @param key_id Object ID
     * @param in public key
     * @param in_len length of public key
     * @param out Agreed key
     * @param out_len length of agreed key
     *
     * @return yh_rc error code
     **/
    pub fn yh_util_derive_ecdh(
        session: *const yh_session,
        key_id: u16,
        in_: *const u8,
        in_len: usize,
        out: *mut u8,
        out_len: *mut usize,
    ) -> yh_rc;
}

extern "C" {
    /**
     * Delete an object
     *
     * @param session session to use
     * @param id Object ID
     * @param type Object type
     *
     * @return yh_rc error code
     **/
    pub fn yh_util_delete_object(
        session: *const yh_session,
        id: u16,
        type_: yh_object_type,
    ) -> yh_rc;
}

extern "C" {
    /**
     * Export an object under wrap
     *
     * @param session session to use
     * @param wrapping_key_id ID of wrapping key
     * @param target_type Type of object
     * @param target_id ID of object
     * @param out wrapped data
     * @param out_len length of wrapped data
     *
     * @return yh_rc error code
     **/
    pub fn yh_util_export_wrapped(
        session: *const yh_session,
        wrapping_key_id: u16,
        target_type: yh_object_type,
        target_id: u16,
        out: *mut u8,
        out_len: *mut usize,
    ) -> yh_rc;
}

extern "C" {
    /**
     * Import a wrapped object
     *
     * @param session session to use
     * @param wrapping_key_id ID of wrapping key
     * @param in wrapped data
     * @param in_len length of wrapped data
     * @param target_type what type the imported object has
     * @param target_id ID of imported object
     *
     * @return yh_rc error code
     **/
    pub fn yh_util_import_wrapped(
        session: *const yh_session,
        wrapping_key_id: u16,
        in_: *const u8,
        in_len: usize,
        target_type: *mut yh_object_type,
        target_id: *mut u16,
    ) -> yh_rc;
}

extern "C" {
    /**
     * Import a wrap key
     *
     * @param session session to use
     * @param key_id Object ID
     * @param label label
     * @param domains domains
     * @param capabilities capabilities
     * @param algorithm algorithm
     * @param delegated_capabilities delegated capabilities
     * @param in key
     * @param in_len key length
     *
     * @return yh_rc error code
     **/
    pub fn yh_util_import_wrap_key(
        session: *const yh_session,
        key_id: *mut u16,
        label: *const c_char,
        domains: u16,
        capabilities: *const yh_capabilities,
        algorithm: yh_algorithm,
        delegated_capabilities: *const yh_capabilities,
        in_: *const u8,
        in_len: usize,
    ) -> yh_rc;
}

extern "C" {
    /**
     * Generate a wrap key
     *
     * @param session session to use
     * @param key_id Object ID
     * @param label label
     * @param domains domains
     * @param capabilities capabilities
     * @param algorithm algorithm
     * @param delegated_capabilities delegated capabilitites
     *
     * @return yh_rc error code
     **/
    pub fn yh_util_generate_wrap_key(
        session: *const yh_session,
        key_id: *mut u16,
        label: *const c_char,
        domains: u16,
        capabilities: *const yh_capabilities,
        algorithm: yh_algorithm,
        delegated_capabilities: *const yh_capabilities,
    ) -> yh_rc;
}

extern "C" {
    /**
     * Get logs
     *
     * @param session session to use
     * @param unlogged_boot number of unlogged boots
     * @param unlogged_auth number of unlogged authentications
     * @param out array of log entries
     * @param n_items number of items in out
     *
     * @return yh_rc error code
     **/
    pub fn yh_util_get_logs_entries(
        session: *const yh_session,
        unlogged_boot: *mut u16,
        unlogged_auth: *mut u16,
        out: *mut yh_log_entry,
        n_items: *mut usize,
    ) -> yh_rc;
}

extern "C" {
    /**
     * Set the log index
     *
     * @param session session to use
     * @param index index to set
     *
     * @return yh_rc error code
     **/
    pub fn yh_util_set_log_index(session: *const yh_session, index: u16) -> yh_rc;
}

extern "C" {
    /**
     * Get opaque object
     *
     * @param session session to use
     * @param object_id Object ID
     * @param out data
     * @param out_len length of out
     *
     * @return yh_rc error code
     **/
    pub fn yh_util_get_opaque(
        session: *const yh_session,
        object_id: u16,
        out: *mut u8,
        out_len: *mut usize,
    ) -> yh_rc;
}

extern "C" {
    /**
     * Import opaque object
     *
     * @param session session to use
     * @param object_id Object ID
     * @param label label
     * @param domains domains
     * @param capabilities
     * @param algorithm algorithm
     * @param in object data
     * @param in_len length of in
     *
     * @return
     **/
    pub fn yh_util_import_opaque(
        session: *const yh_session,
        object_id: *mut u16,
        label: *const c_char,
        domains: u16,
        capabilities: *const yh_capabilities,
        algorithm: yh_algorithm,
        in_: *const u8,
        in_len: usize,
    ) -> yh_rc;
}

extern "C" {
    /**
     * Sign SSH certificate
     *
     * @param session session to use
     * @param key_id Key ID
     * @param template_id Template ID
     * @param sig_algo signature algorithm
     * @param in Certificate request
     * @param in_len length of in
     * @param out Signature
     * @param out_len length of out
     *
     * @return yh_rc error code
     **/
    pub fn yh_util_sign_ssh_certificate(
        session: *const yh_session,
        key_id: u16,
        template_id: u16,
        sig_algo: yh_algorithm,
        in_: *const u8,
        in_len: usize,
        out: *mut u8,
        out_len: *mut usize,
    ) -> yh_rc;
}

extern "C" {
    /**
     * Import authentication key
     *
     * @param session session to use
     * @param key_id Object ID
     * @param label label
     * @param domains domains
     * @param capabilities capabilities
     * @param key_enc encryption key
     * @param key_enc_len length of encryption key
     * @param key_mac MAC key
     * @param key_mac_len length of MAC key
     *
     * @return yh_rc error code
     **/
    pub fn yh_util_import_authentication_key(
        session: *const yh_session,
        key_id: *mut u16,
        label: *const c_char,
        domains: u16,
        capabilities: *const yh_capabilities,
        delegated_capabilities: *const yh_capabilities,
        key_enc: *const u8,
        key_enc_len: usize,
        key_mac: *const u8,
        key_mac_len: usize,
    ) -> yh_rc;
}

extern "C" {
    /**
     * Import authentication key with keys derived from password
     *
     * @param session session to use
     * @param key_id Object ID
     * @param label label
     * @param domains domains
     * @param capabilities capabilities
     * @param delegated_capabilities delegated capabilities
     * @param password password to derive key from
     * @param password_len password length in bytes
     *
     * @return yh_rc error code
     **/
    pub fn yh_util_import_authentication_key_derived(
        session: *const yh_session,
        key_id: *mut u16,
        label: *const c_char,
        domains: u16,
        capabilities: *const yh_capabilities,
        delegated_capabilities: *const yh_capabilities,
        password: *const u8,
        password_len: usize,
    ) -> yh_rc;
}

// TODO(adma): change_authentication_key{_derived)

extern "C" {
    /**
     * Get template
     *
     * @param session session to use
     * @param object_id Object ID
     * @param out data
     * @param out_len length of out
     *
     * @return yh_rc error code
     **/
    pub fn yh_util_get_template(
        session: *const yh_session,
        object_id: u16,
        out: *mut u8,
        out_len: *mut usize,
    ) -> yh_rc;
}

extern "C" {
    /**
     * Import template
     *
     * @param session session to use
     * @param object_id Object ID
     * @param label label
     * @param domains domains
     * @param capabilities capabilities
     * @param algorithm algorithm
     * @param in data
     * @param in_len length of in
     *
     * @return yh_rc error code
     **/
    pub fn yh_util_import_template(
        session: *const yh_session,
        object_id: *mut u16,
        label: *const c_char,
        domains: u16,
        capabilities: *const yh_capabilities,
        algorithm: yh_algorithm,
        in_: *const u8,
        in_len: usize,
    ) -> yh_rc;
}

extern "C" {
    /**
     * Create OTP AEAD
     *
     * @param session session to use
     * @param key_id Object ID
     * @param key OTP key
     * @param private_id OTP private id
     * @param out AEAD
     * @param out_len length of out
     *
     * @return yh_rc error code
     **/
    pub fn yh_util_create_otp_aead(
        session: *const yh_session,
        key_id: u16,
        key: *const u8,
        private_id: *const u8,
        out: *mut u8,
        out_len: *mut usize,
    ) -> yh_rc;
}

extern "C" {
    /**
     * Create OTP AEAD from random
     *
     * @param session session to use
     * @param key_id Object ID
     * @param out AEAD
     * @param out_len length of out
     *
     * @return yh_rc error code
     **/
    pub fn yh_util_randomize_otp_aead(
        session: *const yh_session,
        key_id: u16,
        out: *mut u8,
        out_len: *mut usize,
    ) -> yh_rc;
}

extern "C" {
    /**
     * Decrypt OTP
     *
     * @param session session to use
     * @param key_id Object ID
     * @param aead AEAD
     * @param aead_len length of AEAD
     * @param otp OTP
     * @param useCtr OTP use counter
     * @param sessionCtr OTP session counter
     * @param tstph OTP timestamp high
     * @param tstpl OTP timestamp low
     *
     * @return yh_rc error code
     **/
    pub fn yh_util_decrypt_otp(
        session: *const yh_session,
        key_id: u16,
        aead: *const u8,
        aead_len: usize,
        otp: *const u8,
        useCtr: *mut u16,
        sessionCtr: *mut u8,
        tstph: *mut u8,
        tstpl: *mut u16,
    ) -> yh_rc;
}

extern "C" {
    /**
     * Import OTP AEAD Key
     *
     * @param session session to use
     * @param key_id Object ID
     * @param label label
     * @param domains domains
     * @param capabilities capabilities
     * @param nonce_id nonce ID
     * @param in key
     * @param in_len length of in
     *
     * @return
     **/
    pub fn yh_util_import_otp_aead_key(
        session: *const yh_session,
        key_id: *mut u16,
        label: *const c_char,
        domains: u16,
        capabilities: *const yh_capabilities,
        nonce_id: u32,
        in_: *const u8,
        in_len: usize,
    ) -> yh_rc;
}

extern "C" {
    /**
     * Generate OTP AEAD Key
     *
     * @param session session to use
     * @param key_id Object ID
     * @param label label
     * @param domains domains
     * @param capabilities capabilities
     * @param algorithm algorithm
     * @param nonce_id nonce ID
     *
     * @return yh_rc error code
     **/
    pub fn yh_util_generate_otp_aead_key(
        session: *const yh_session,
        key_id: *mut u16,
        label: *const c_char,
        domains: u16,
        capabilities: *const yh_capabilities,
        algorithm: yh_algorithm,
        nonce_id: u32,
    ) -> yh_rc;
}

extern "C" {
    /**
     * Sign attestation certificate
     *
     * @param session session to use
     * @param key_id Object ID
     * @param attest_id Attestation key ID
     * @param out Certificate
     * @param out_len length of out
     *
     * @return yh_rc error code
     **/
    pub fn yh_util_sign_attestation_certificate(
        session: *const yh_session,
        key_id: u16,
        attest_id: u16,
        out: *mut u8,
        out_len: *mut usize,
    ) -> yh_rc;
}

extern "C" {
    /**
     * Set global option
     *
     * @param session session to use
     * @param option option
     * @param len length of option data
     * @param val option data
     *
     * @return yh_rc error code
     **/
    pub fn yh_util_set_option(
        session: *const yh_session,
        option: yh_option,
        len: usize,
        val: *mut u8,
    ) -> yh_rc;
}

extern "C" {
    /**
     * Get global option
     *
     * @param session session to use
     * @param option option
     * @param out option data
     * @param out_len length of out
     *
     * @return yh_rc error code
     **/
    pub fn yh_util_get_option(
        session: *const yh_session,
        option: yh_option,
        out: *mut u8,
        out_len: *mut usize,
    ) -> yh_rc;
}

extern "C" {
    /**
     * Get storage information
     *
     * @param session session to use
     * @param total_records total records available
     * @param free_records number of free records
     * @param total_pages total pages available
     * @param free_pages number of free pages
     * @param page_size page size in bytes
     *
     * @return yh_rc error code
     **/
    pub fn yh_util_get_storage_info(
        session: *const yh_session,
        total_records: *mut u16,
        free_records: *mut u16,
        total_pages: *mut u16,
        free_pages: *mut u16,
        page_size: *mut u16,
    ) -> yh_rc;
}

extern "C" {
    /**
     * Wrap data
     *
     * @param session session to use
     * @param key_id Object ID
     * @param in data to wrap
     * @param in_len length of in
     * @param out wrapped data
     * @param out_len length of out
     *
     * @return yh_rc error code
     **/
    pub fn yh_util_wrap_data(
        session: *const yh_session,
        key_id: u16,
        in_: *mut u8,
        in_len: usize,
        out: *mut u8,
        out_len: *mut usize,
    ) -> yh_rc;
}

extern "C" {
    /**
     * Unwrap data
     *
     * @param session session to use
     * @param key_id Object ID
     * @param in wrapped data
     * @param in_len length of in
     * @param out unwrapped data
     * @param out_len length of out
     *
     * @return yh_rc error code
     **/
    pub fn yh_util_unwrap_data(
        session: *const yh_session,
        key_id: u16,
        in_: *mut u8,
        in_len: usize,
        out: *mut u8,
        out_len: *mut usize,
    ) -> yh_rc;
}

extern "C" {
    /**
     * Blink the device
     *
     * @param session session to use
     * @param seconds seconds to blink
     *
     * @return yh_rc error code
     **/
    pub fn yh_util_blink_device(session: *const yh_session, seconds: u8) -> yh_rc;
}

extern "C" {
    /**
     * Reset the device
     *
     * @param session session to use
     *
     * @return yh_rc error code. This function will normally return a network error
     **/
    pub fn yh_util_reset_device(session: *const yh_session) -> yh_rc;
}

extern "C" {
    /**
     * Get session ID
     *
     * @param session session to use
     * @param sid session ID
     *
     * @return yh_rc error code
     **/
    pub fn yh_get_session_id(session: *const yh_session, sid: *mut u8) -> yh_rc;
}

extern "C" {
    /**
     * Check if the connector has a device connected
     *
     * @param connector connector
     *
     * @return true or false
     **/
    pub fn yh_connector_has_device(connector: *mut yh_connector) -> bool;
}

extern "C" {
    /**
     * Get the connector version
     *
     * @param connector connector
     * @param major major version
     * @param minor minor version
     * @param patch patch version
     *
     * @return yh_rc error code
     **/
    pub fn yh_get_connector_version(
        connector: *mut yh_connector,
        major: *mut u8,
        minor: *mut u8,
        patch: *mut u8,
    ) -> yh_rc;
}

extern "C" {
    /**
     * Get connector address
     *
     * @param connector connector
     * @param address pointer to string address
     *
     * @return yh_rc error code
     **/
    pub fn yh_get_connector_address(
        connector: *mut yh_connector,
        address: *const *mut c_char,
    ) -> yh_rc;
}

extern "C" {
    /**
     * Convert capability string to byte array
     *
     * @param capability string of capabilities
     * @param result capabilities
     *
     * @return yh_rc error code
     **/
    pub fn yh_string_to_capabilities(
        capability: *const c_char,
        result: *mut yh_capabilities,
    ) -> yh_rc;
}

extern "C" {
    /**
     * Convert capability byte array to strings
     *
     * @param num capabilities
     * @param result array of string pointers
     * @param n_result number of elements of result
     *
     * @return yh_rc error code
     **/
    pub fn yh_capabilities_to_string(
        num: *const yh_capabilities,
        result: *mut *const c_char,
        n_result: *mut usize,
    ) -> yh_rc;
}

extern "C" {
    /**
     * Check if capability is set
     *
     * @param capabilities capabilities
     * @param capability capability string
     *
     * @return true or false
     **/
    pub fn yh_check_capability(
        capabilities: *const yh_capabilities,
        capability: *const c_char,
    ) -> bool;
}

// TODO(adma): merge_capabilities
// TODO(adma): filter_capabilities

extern "C" {
    /**
     * Check if algorithm is an RSA algorithm
     *
     * @param algorithm algorithm
     *
     * @return true or false
     **/
    pub fn yh_is_rsa(algorithm: yh_algorithm) -> bool;
}

extern "C" {
    /**
     * Check if algorithm is an EC algorithm
     *
     * @param algorithm algorithm
     *
     * @return true or false
     **/
    pub fn yh_is_ec(algorithm: yh_algorithm) -> bool;
}

extern "C" {
    /**
     * Check if algorithm is an ED algorithm
     *
     * @param algorithm algorithm
     *
     * @return true or false
     **/
    pub fn yh_is_ed(algorithm: yh_algorithm) -> bool;
}

extern "C" {
    /**
     * Check if algorithm is a HMAC algorithm
     *
     * @param algorithm algorithm
     *
     * @return true or false
     **/
    pub fn yh_is_hmac(algorithm: yh_algorithm) -> bool;
}

extern "C" {
    /**
     * Get algorithm bitlength
     *
     * @param algorithm algorithm
     * @param result bitlength
     *
     * @return yh_rc error code
     **/
    pub fn yh_get_key_bitlength(algorithm: yh_algorithm, result: *mut usize) -> yh_rc;
}

extern "C" {
    /**
     * Convert algorithm to string
     *
     * @param algo algorithm
     * @param result string
     *
     * @return yh_rc error code
     **/
    pub fn yh_algo_to_string(algo: yh_algorithm, result: *mut *const c_char) -> yh_rc;
}

extern "C" {
    /**
     * Convert string to algorithm
     *
     * @param string algorithm as string
     * @param algo algorithm
     *
     * @return yh_rc error code
     **/
    pub fn yh_string_to_algo(string: *const c_char, algo: *mut yh_algorithm) -> yh_rc;
}

extern "C" {
    /**
     * Convert type to string
     *
     * @param type type
     * @param result string
     *
     * @return yh_rc error code
     **/
    pub fn yh_type_to_string(type_: yh_object_type, result: *mut *const c_char) -> yh_rc;
}

extern "C" {
    /**
     * Convert string to type
     *
     * @param string type as string
     * @param type type
     *
     * @return yh_rc error code
     **/
    pub fn yh_string_to_type(string: *const c_char, type_: *mut yh_object_type) -> yh_rc;
}

extern "C" {
    /**
     * Convert string to option
     *
     * @param string option as string
     * @param option option
     *
     * @return yh_rc error code
     **/
    pub fn yh_string_to_option(string: *const c_char, option: *mut yh_option) -> yh_rc;
}

extern "C" {
    /**
     * Verify an array of log entries
     *
     * @param logs pointer to an array of log entries
     * @param n_items number of items logs
     * @param last_previous_log optional pointer to the entry before the first entry in logs
     *
     * @return true or false
     **/
    pub fn yh_verify_logs(
        logs: *mut yh_log_entry,
        n_items: usize,
        last_previous_log: *mut yh_log_entry,
    ) -> bool;
}

extern "C" {
    /**
     * Parse a string to a domains parameter
     *
     * @param domains string of the format 1,2,3
     * @param result resulting parsed domain parameter
     *
     * @return yh_rc error code
     **/
    pub fn yh_string_to_domains(domains: *const c_char, result: *mut u16) -> yh_rc;
}

extern "C" {
    /**
     * Write out domains to a string.
     *
     * @param domains encoded domains
     * @param string string to hold the result
     * @param max_len maximum length of string
     *
     * @return yh_rc error code
     **/
    pub fn yh_domains_to_string(domains: u16, string: *mut c_char, max_len: usize) -> yh_rc;
}

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

//! Module for handling device objects

use lyh;
use lyh::{yh_algorithm, yh_capabilities, yh_object_descriptor, yh_object_type};

use error::Error;

use std::collections::HashMap;
use std::str::FromStr;
use std::fmt;
use std::fmt::Display;

use Session;

#[derive(Debug, Clone, Copy, PartialEq)]
/// Object types
pub enum ObjectType {
    /// Opaque object
    Opaque,
    /// Authentication key
    AuthenticationKey,
    /// Asymmetric key
    AsymmetricKey,
    /// Wrap key
    WrapKey,
    /// Hmac key
    HmacKey,
    /// Template
    Template,
    /// OTP AEAD key
    OtpAeadKey,
    /// Public key (virtual)
    PublicKey,
    /// Any type
    Any,
}

#[derive(Clone, Copy)]
/// Object capabilities
pub enum ObjectCapability {
    /// Get opaque object
    GetOpaque,
    /// Put opaque object
    PutOpaque,
    /// Put authentication key
    PutAuthenticationKey,
    /// Put asymmetric key
    PutAsymmetricKey,
    /// Generate asymmetric key
    GenerateAsymmetricKey,
    /// Sign data using RSA-PKCS1v1.5
    SignPkcs,
    /// Sign data using RSA-PSS
    SignPss,
    /// Sign data using ECDSA
    SignEcdsa,
    /// Sign data using EDDSA
    SignEddsa,
    /// Decrypt data using RSA-PKCS1v1.5
    DecryptPkcs,
    /// Decrypt data using RSA-OAEP
    DecryptOaep,
    /// Perform ECDH exchange
    DeriveEcdh,
    /// Export an object wrapped
    ExportWrapped,
    /// Import a wrapped object
    ImportWrapped,
    /// Put a wrap key
    PutWrapKey,
    /// Generate a wrap key
    GenerateWrapKey,
    /// Object is exportable under wrap
    ExportableUnderWrap,
    /// Set option
    SetOption,
    /// Get option
    GetOption,
    /// Get pseudo random data
    GetPseudoRandom,
    /// Put HMAC key
    PutHmacKey,
    /// Generate HMAC key
    GenerateHmacKey,
    /// HMAC data
    SignHmac,
    /// Verify HMAC
    VerifyHmac,
    /// Extract audit logs
    GetLogEntries,
    /// SSH certify
    SignSshCertificate,
    /// Get template
    GetTemplate,
    /// Put template
    PutTemplate,
    /// Reset
    ResetDevice,
    /// Decrypt OTP
    DecryptOtp,
    /// Create OTP AEAD
    CreateOtpAead,
    /// Create OTP AEAD from random data
    RandomizeOtpAead,
    /// Rewarap OTP AEAD from a given key
    RewrapFromOtpAeadKey,
    /// Rewrap OTP AEAD to a given key
    RewrapToOtpAeadKey,
    /// Attest an asymmetric key
    SignAttestationCertificate,
    /// Put OTP AEAD key
    PutOtpAeadKey,
    /// Generate OTP AEAD key
    GenerateOtpAeadKey,
    /// Wrap data
    WrapData,
    /// Unwrap data
    UnwrapData,
    /// Delete opaque object
    DeleteOpaque,
    /// Delete authkey
    DeleteAuthenticationKey,
    /// Delete asymmetric key
    DeleteAsymmetricKey,
    /// Delete wrap key
    DeleteWrapKey,
    /// Delete HMAC key
    DeleteHmacKey,
    /// Delete template
    DeleteTemplate,
    /// Delete OTP AEAD key
    DeleteOtpAeadKey,
}

#[derive(Debug, Clone, Copy)]
/// Object domains
pub enum ObjectDomain {
    /// Domain one
    One,
    /// Domain two
    Two,
    /// Domain three
    Three,
    /// Domain four
    Four,
    /// Domain five
    Five,
    /// Domain six
    Six,
    /// Domain seven
    Seven,
    /// Domain eight
    Eight,
    /// Domain ninie
    Nine,
    /// Domain ten
    Ten,
    /// Domain eleve
    Eleven,
    /// Domain twelve
    Twelve,
    /// Domain thirteen
    Thirteen,
    /// Domain fourteen
    Fourteen,
    /// Domain fifteen
    Fifteen,
    /// Domain sixteen
    Sixteen,
}

#[derive(Debug, Clone, Copy, PartialEq)]
/// Object algorithms
pub enum ObjectAlgorithm {
    /// RSA PKCS1v1.5 with SHA1
    RsaPkcs1Sha1,
    /// RSA PKCS1v1.5 with SHA256
    RsaPkcs1Sha256,
    /// RSA PKCS1v1.5 with SHA384
    RsaPkcs1Sha384,
    /// RSA PKCS1v1.5 with SHA512
    RsaPkcs1Sha512,
    /// RSA PSS with SHA1
    RsaPssSha1,
    /// RSA PSS with SHA256
    RsaPssSha256,
    /// RSA PSS with SHA384
    RsaPssSha384,
    /// RSA PSS with SHA512
    RsaPssSha512,
    /// RSA 2048
    Rsa2048,
    /// RSA 3072
    Rsa3072,
    /// RSA 4096
    Rsa4096,
    /// SEC-P256 curve
    EcP256,
    /// SEC-P384 curve
    EcP384,
    /// SEC-P521 curve
    EcP521,
    /// K256 curve
    EcK256,
    /// Brainpool P256 curve
    EcBp256,
    /// Brainpool P384 curve
    EcBp384,
    /// Brainpool P512 curve
    EcBp512,
    /// HMAC-SHA1
    HmacSha1,
    /// HMAC-SHA256
    HmacSha256,
    /// HMAC-SHA384
    HmacSha384,
    /// HMAC-SHA512
    HmacSha512,
    /// ECDSA-SHA1
    EcdsaSha1,
    /// ECDH
    Ecdh,
    /// RSA-OAEP with SHA1
    RsaOaepSha1,
    /// RSA-OAEP with SHA256
    RsaOaepSha256,
    /// RSA-OAEP with SHA384
    RsaOaepSha384,
    /// RSA-OAEP with SHA512
    RsaOaepSha512,
    /// AES-128 CCM wrap
    Aes128CcmWrap,
    /// Opaque data
    OpaqueData,
    /// Opaque X.509
    OpaqueX509Certificate,
    /// MGF1 with SHA1
    Mgf1Sha1,
    /// MGF1 with SHA256
    Mgf1Sha256,
    /// MGF1 with SHA384
    Mgf1Sha384,
    /// MGF1 with SHA512
    Mgf1Sha512,
    /// Template
    TemplateSsh,
    /// Yubico OTP with AES-128
    Aes128YubicoOtp,
    /// Yubico AES auhtentication
    Aes128YubicoAuthentication,
    /// Yubico OTP with AES-192
    Aes192YubicoOtp,
    /// Yubico OTP with AES-256
    Aes256YubicoOtp,
    /// AES-192 CCM wrap
    Aes192CcmWrap,
    /// AES-256 CCM wrap
    Aes256CcmWrap,
    /// ECDSA with SHA256
    EcdsaSha256,
    /// ECDSA with SHA384
    EcdsaSha384,
    /// ECDSA with SHA512
    EcdsaSha512,
    /// ED25519 curve
    Ed25519,
    /// SEC-P224 curve
    EcP224,
    /// RSA PKCS1v1.5 decrypt
    RsaPkcs1Decrypt,
    /// Any algorithms
    ANY,
}

#[derive(Debug, Clone, Copy)]
/// Object origin
pub enum ObjectOrigin {
    /// Generate object
    Generated,
    /// Imported object
    Imported,
    /// Wrapped and generated object
    WrappedGenerated,
    /// Wrapped and imported object
    WrappedImported,
}

#[derive(Debug, Clone)]
/// Object descriptor
pub struct ObjectDescriptor {
    /// Ccapabilities
    pub capabilities: Vec<ObjectCapability>,
    /// Id
    pub id: u16,
    /// Size/Length
    len: u16,
    /// Domains
    pub domains: Vec<ObjectDomain>,
    /// Type
    pub object_type: ObjectType,
    /// Algorithm
    pub algorithm: ObjectAlgorithm,
    /// Sequence
    pub sequence: u8,
    /// Origin
    pub origin: ObjectOrigin,
    /// Label
    pub label: String,
    /// Delegated Capabilities
    pub delegated_capabilities: Option<Vec<ObjectCapability>>,
}

#[derive(Debug, Clone, Copy)]
/// Object Handle
pub struct ObjectHandle {
    /// Type
    pub object_type: ObjectType,
    /// Id
    pub object_id: u16,
}

lazy_static! {
    static ref CAPABILITIES_MAP: HashMap<(u8, u8), ObjectCapability> =
        [((0, 0x01), ObjectCapability::GetOpaque),
         ((0, 0x02), ObjectCapability::PutOpaque),
         ((0, 0x04), ObjectCapability::PutAuthenticationKey),
         ((0, 0x08), ObjectCapability::PutAsymmetricKey),
         ((0, 0x10), ObjectCapability::GenerateAsymmetricKey),
         ((0, 0x20), ObjectCapability::SignPkcs),
         ((0, 0x40), ObjectCapability::SignPss),
         ((0, 0x80), ObjectCapability::SignEcdsa),

         ((1, 0x01), ObjectCapability::SignEddsa),
         ((1, 0x02), ObjectCapability::DecryptPkcs),
         ((1, 0x04), ObjectCapability::DecryptOaep),
         ((1, 0x08), ObjectCapability::DeriveEcdh),
         ((1, 0x10), ObjectCapability::ExportWrapped),
         ((1, 0x20), ObjectCapability::ImportWrapped),
         ((1, 0x40), ObjectCapability::PutWrapKey),
         ((1, 0x80), ObjectCapability::GenerateWrapKey),

         ((2, 0x01), ObjectCapability::ExportableUnderWrap),
         ((2, 0x02), ObjectCapability::SetOption),
         ((2, 0x04), ObjectCapability::GetOption),
         ((2, 0x08), ObjectCapability::GetPseudoRandom),
         ((2, 0x10), ObjectCapability::PutHmacKey),
         ((2, 0x20), ObjectCapability::GenerateHmacKey),
         ((2, 0x40), ObjectCapability::SignHmac),
         ((2, 0x80), ObjectCapability::VerifyHmac),

         ((3, 0x01), ObjectCapability::GetLogEntries),
         ((3, 0x02), ObjectCapability::SignSshCertificate),
         ((3, 0x04), ObjectCapability::GetTemplate),
         ((3, 0x08), ObjectCapability::PutTemplate),
         ((3, 0x10), ObjectCapability::ResetDevice),
         ((3, 0x20), ObjectCapability::DecryptOtp),
         ((3, 0x40), ObjectCapability::CreateOtpAead),
         ((3, 0x80), ObjectCapability::RandomizeOtpAead),

         ((4, 0x01), ObjectCapability::RewrapFromOtpAeadKey),
         ((4, 0x02), ObjectCapability::RewrapToOtpAeadKey),
         ((4, 0x04), ObjectCapability::SignAttestationCertificate),
         ((4, 0x08), ObjectCapability::PutOtpAeadKey),
         ((4, 0x10), ObjectCapability::GenerateOtpAeadKey),
         ((4, 0x20), ObjectCapability::WrapData),
         ((4, 0x40), ObjectCapability::UnwrapData),
         ((4, 0x80), ObjectCapability::DeleteOpaque),

         ((5, 0x01), ObjectCapability::DeleteAuthenticationKey),
         ((5, 0x02), ObjectCapability::DeleteAsymmetricKey),
         ((5, 0x04), ObjectCapability::DeleteWrapKey),
         ((5, 0x08), ObjectCapability::DeleteHmacKey),
         ((5, 0x10), ObjectCapability::DeleteTemplate),
         ((5, 0x20), ObjectCapability::DeleteOtpAeadKey)]
         .iter().cloned().collect();
}

impl fmt::Debug for ObjectCapability {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ObjectCapability::GetOpaque => write!(f, "get-opaque"),
            ObjectCapability::PutOpaque => write!(f, "put-opaque"),
            ObjectCapability::PutAuthenticationKey => write!(f, "put-authentication-key"),
            ObjectCapability::PutAsymmetricKey => write!(f, "put-asymmetric-key"),
            ObjectCapability::GenerateAsymmetricKey => write!(f, "generate-asymmetric-key"),
            ObjectCapability::SignPkcs => write!(f, "sign-pkcs"),
            ObjectCapability::SignPss => write!(f, "sign-pss"),
            ObjectCapability::SignEcdsa => write!(f, "sign-ecdsa"),

            ObjectCapability::SignEddsa => write!(f, "sign-eddsa"),
            ObjectCapability::DecryptPkcs => write!(f, "decrypt-pkcs"),
            ObjectCapability::DecryptOaep => write!(f, "decrypt-oaep"),
            ObjectCapability::DeriveEcdh => write!(f, "derive-ecdh"),
            ObjectCapability::ExportWrapped => write!(f, "export-wrapped"),
            ObjectCapability::ImportWrapped => write!(f, "import-wrapped"),
            ObjectCapability::PutWrapKey => write!(f, "put-wrap-key"),
            ObjectCapability::GenerateWrapKey => write!(f, "generate-wrap-key"),

            ObjectCapability::ExportableUnderWrap => write!(f, "exportable-under-wrap"),
            ObjectCapability::SetOption => write!(f, "set-option"),
            ObjectCapability::GetOption => write!(f, "get-option"),
            ObjectCapability::GetPseudoRandom => write!(f, "get-pseudo-random"),
            ObjectCapability::PutHmacKey => write!(f, "put-mac-key"),
            ObjectCapability::GenerateHmacKey => write!(f, "generate-hmac-key"),
            ObjectCapability::SignHmac => write!(f, "sign-hmac"),
            ObjectCapability::VerifyHmac => write!(f, "verify-hmac"),

            ObjectCapability::GetLogEntries => write!(f, "get-log-entries"),
            ObjectCapability::SignSshCertificate => write!(f, "sign-ssh-certificate"),
            ObjectCapability::GetTemplate => write!(f, "get-template"),
            ObjectCapability::PutTemplate => write!(f, "put-template"),
            ObjectCapability::ResetDevice => write!(f, "reset-device"),
            ObjectCapability::DecryptOtp => write!(f, "decrypt-otp"),
            ObjectCapability::CreateOtpAead => write!(f, "create-otp-aead"),
            ObjectCapability::RandomizeOtpAead => write!(f, "randomize-otp-aead"),

            ObjectCapability::RewrapFromOtpAeadKey => write!(f, "rewrap-from-otp-aead-key"),
            ObjectCapability::RewrapToOtpAeadKey => write!(f, "rewrap-to-otp-aead-key"),
            ObjectCapability::SignAttestationCertificate => write!(f, "sign-attestation-certificate"),
            ObjectCapability::PutOtpAeadKey => write!(f, "put-otp-aead-key"),
            ObjectCapability::GenerateOtpAeadKey => write!(f, "generate-otp-aead-key"),
            ObjectCapability::WrapData => write!(f, "wrap-data"),
            ObjectCapability::UnwrapData => write!(f, "unwrap-data"),
            ObjectCapability::DeleteOpaque => write!(f, "delete-opaque"),

            ObjectCapability::DeleteAuthenticationKey => write!(f, "delete-authentication-key"),
            ObjectCapability::DeleteAsymmetricKey => write!(f, "delete-asymmetric-key"),
            ObjectCapability::DeleteWrapKey => write!(f, "delete-wrap-key"),
            ObjectCapability::DeleteHmacKey => write!(f, "delete-hmac-key"),
            ObjectCapability::DeleteTemplate => write!(f, "delete-template"),
            ObjectCapability::DeleteOtpAeadKey => write!(f, "delete-otp-aead-key"),
        }
    }
}

impl Display for ObjectCapability {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ObjectCapability::GetOpaque => write!(f, "Read Opaque Objects"),
            ObjectCapability::PutOpaque => write!(f, "Write Opaque Objects"),
            ObjectCapability::PutAuthenticationKey => write!(f, "Write Authentication Key Objects"),
            ObjectCapability::PutAsymmetricKey => write!(f, "Write Asymmetric Key Objects"),
            ObjectCapability::GenerateAsymmetricKey => write!(f, "Generate Asymmetric Key Objects"),
            ObjectCapability::SignPkcs => write!(f, "Compute signatures using RSA-PKCS1v1.5"),
            ObjectCapability::SignPss => write!(f, "Compute digital signatures using using RSA-PSS"),
            ObjectCapability::SignEcdsa => write!(f, "Compute digital signatures using ECDSA"),

            ObjectCapability::SignEddsa => write!(f, "Compute digital signatures using EDDSA"),
            ObjectCapability::DecryptPkcs => write!(f, "Decrypt data using RSA-PKCS1v1.5"),
            ObjectCapability::DecryptOaep => write!(f, "Decrypt data using RSA-OAEP"),
            ObjectCapability::DeriveEcdh => write!(f, "Perform ECDH"),
            ObjectCapability::ExportWrapped => write!(f, "Export other Objects under wrap"),
            ObjectCapability::ImportWrapped => write!(f, "Import wrapped Objects"),
            ObjectCapability::PutWrapKey => write!(f, "Write Wrap Key Objects"),
            ObjectCapability::GenerateWrapKey => write!(f, "Generate Wrap Key Objects"),

            ObjectCapability::ExportableUnderWrap => write!(f, "Mark an Object as exportable under wrap"),
            ObjectCapability::SetOption => write!(f, "Write device-global options"),
            ObjectCapability::GetOption => write!(f, "Read device-global options"),
            ObjectCapability::GetPseudoRandom => write!(f, "Extract random bytes"),
            ObjectCapability::PutHmacKey => write!(f, "Write HMAC Key Objects"),
            ObjectCapability::GenerateHmacKey => write!(f, "Generate HMAC Key Objects"),
            ObjectCapability::SignHmac => write!(f, "Compute HMAC of data"),
            ObjectCapability::VerifyHmac => write!(f, "Verify HMAC of data"),

            ObjectCapability::GetLogEntries => write!(f, "Read the Log Store"),
            ObjectCapability::SignSshCertificate => write!(f, "Sign SSH certificates"),
            ObjectCapability::GetTemplate => write!(f, "Read Template Objects"),
            ObjectCapability::PutTemplate => write!(f, "Write Template Objects"),
            ObjectCapability::ResetDevice => write!(f, "Perform a factory reset on the device"),
            ObjectCapability::DecryptOtp => write!(f, "Decrypt OTP"),
            ObjectCapability::CreateOtpAead => write!(f, "Create OTP AEAD"),
            ObjectCapability::RandomizeOtpAead => write!(f, "Create OTP AEAD from random data"),

            ObjectCapability::RewrapFromOtpAeadKey => write!(f, "Rewrap AEADs from one OTP AEAD Key Object to another"),
            ObjectCapability::RewrapToOtpAeadKey => write!(f, "Rewrap AEADs to one OTP AEAD Key Object from another"),
            ObjectCapability::SignAttestationCertificate => write!(f, "Attest properties of Asymmetric Key Objects"),
            ObjectCapability::PutOtpAeadKey => write!(f, "Write OTP AEAD Key Objects"),
            ObjectCapability::GenerateOtpAeadKey => write!(f, "Generate OTP AEAD Key Objects"),
            ObjectCapability::WrapData => write!(f, "Wrap user-provided data"),
            ObjectCapability::UnwrapData => write!(f, "Unwrap user-provided data"),
            ObjectCapability::DeleteOpaque => write!(f, "Delete Opaque Objects"),

            ObjectCapability::DeleteAuthenticationKey => write!(f, "Delete Authentication Key Objects"),
            ObjectCapability::DeleteAsymmetricKey => write!(f, "Delete Asymmetric Key Objects"),
            ObjectCapability::DeleteWrapKey => write!(f, "Delete Wrap Key Objects"),
            ObjectCapability::DeleteHmacKey => write!(f, "Delete HMAC Key Objects"),
            ObjectCapability::DeleteTemplate => write!(f, "Delete Template Objects"),
            ObjectCapability::DeleteOtpAeadKey => write!(f, "Delete OTP AEAD Key Objects"),
        }
    }
}

impl ObjectCapability {
    fn from_primitive(capabilities: yh_capabilities) -> Vec<Self> {
        let mut v = Vec::new();

        for i in 0..capabilities.capabilities.len() {
            for j in 0..8 {
                if let Some(x) = CAPABILITIES_MAP
                    .get(&(i as u8, capabilities.capabilities[7 - i] & (1 << j) as u8)) {
                    v.push(*x);
                }
            }
        }
        v
    }

    pub(crate) fn primitive_from_slice(capabilities: &[Self]) -> yh_capabilities {
        let mut result = yh_capabilities::default();

        for c in capabilities {
            let (byte, mask) = c.into();
            result.capabilities[7 - byte as usize] |= mask;
        }

        result
    }

    /// Create a Vec of Capabilities from a slice
    pub fn bytes_from_slice(capabilities: &[Self]) -> Vec<u8> {
        let mut result = Vec::<u8>::new();
        let primitive = ObjectCapability::primitive_from_slice(capabilities);

        for byte in &primitive.capabilities {
            result.push(*byte);
        }

        result
    }

    /// Create ObjectCapabilitiy from a slice of bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Vec<Self>, Error> {
        if bytes.len() < lyh::YH_CAPABILITIES_LEN {
            return Err(Error::WrongLength(lyh::YH_CAPABILITIES_LEN, bytes.len()));
        }

        let mut capabilities = yh_capabilities::default();

        capabilities
            .capabilities
            .clone_from_slice(&bytes[..lyh::YH_CAPABILITIES_LEN]);

        Ok(ObjectCapability::from_primitive(capabilities))
    }
}

impl ObjectDomain {
    fn from_primitive(domains: u16) -> Vec<Self> {
        let mut v = Vec::new();

        if domains & 1 != 0 {
            v.push(ObjectDomain::One);
        }

        if domains & (1 << 1) != 0 {
            v.push(ObjectDomain::Two);
        }

        if domains & (1 << 2) != 0 {
            v.push(ObjectDomain::Three);
        }

        if domains & (1 << 3) != 0 {
            v.push(ObjectDomain::Four);
        }

        if domains & (1 << 4) != 0 {
            v.push(ObjectDomain::Five);
        }

        if domains & (1 << 5) != 0 {
            v.push(ObjectDomain::Six);
        }

        if domains & (1 << 6) != 0 {
            v.push(ObjectDomain::Seven);
        }

        if domains & (1 << 7) != 0 {
            v.push(ObjectDomain::Eight);
        }

        if domains & (1 << 8) != 0 {
            v.push(ObjectDomain::Nine);
        }

        if domains & (1 << 9) != 0 {
            v.push(ObjectDomain::Ten);
        }

        if domains & (1 << 10) != 0 {
            v.push(ObjectDomain::Eleven);
        }

        if domains & (1 << 11) != 0 {
            v.push(ObjectDomain::Twelve);
        }

        if domains & (1 << 12) != 0 {
            v.push(ObjectDomain::Thirteen);
        }

        if domains & (1 << 13) != 0 {
            v.push(ObjectDomain::Fourteen);
        }

        if domains & (1 << 14) != 0 {
            v.push(ObjectDomain::Fifteen);
        }

        if domains & (1 << 15) != 0 {
            v.push(ObjectDomain::Sixteen);
        }

        v
    }

    /// Create ObjectDomain from a &str
    pub fn vec_from_str(domains: &str) -> Result<Vec<Self>, Error> {
        let mut primitive = 0;

        let c_str = ::std::ffi::CString::new(domains).unwrap();

        try!(::error::result_from_libyh(unsafe {
            lyh::yh_string_to_domains(c_str.as_ptr(), &mut primitive)
        }));

        Ok(ObjectDomain::from_primitive(primitive))
    }

    pub(crate) fn primitive_from_slice(domains: &[Self]) -> u16 {
        domains.iter().fold(0, |acc, d| acc | u16::from(*d))
    }

    /// Create ObjectDomain from a slice
    pub fn bytes_from_slice(domains: &[Self]) -> Vec<u8> {
        let mut result = Vec::<u8>::new();
        let primitive = ObjectDomain::primitive_from_slice(domains);

        result.push(((primitive >> 8) & 0xff) as u8);
        result.push((primitive & 0xff) as u8);

        result
    }

    /// Create ObjectDomain from a slice of bytes
    pub fn from_bytes(domains: &[u8]) -> Result<Vec<Self>, Error> {
        if domains.len() < 2 {
            return Err(Error::WrongLength(2, domains.len()));
        }

        let primitive = (u16::from(domains[0]) << 8) | u16::from(domains[1]);

        Ok(ObjectDomain::from_primitive(primitive))
    }
}

impl Display for ObjectDomain {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            ObjectDomain::One => write!(f, "1"),
            ObjectDomain::Two => write!(f, "2"),
            ObjectDomain::Three => write!(f, "3"),
            ObjectDomain::Four => write!(f, "4"),
            ObjectDomain::Five => write!(f, "5"),
            ObjectDomain::Six => write!(f, "6"),
            ObjectDomain::Seven => write!(f, "7"),
            ObjectDomain::Eight => write!(f, "8"),
            ObjectDomain::Nine => write!(f, "9"),
            ObjectDomain::Ten => write!(f, "10"),
            ObjectDomain::Eleven => write!(f, "11"),
            ObjectDomain::Twelve => write!(f, "12"),
            ObjectDomain::Thirteen => write!(f, "13"),
            ObjectDomain::Fourteen => write!(f, "14"),
            ObjectDomain::Fifteen => write!(f, "15"),
            ObjectDomain::Sixteen => write!(f, "16"),
        }
    }
}

impl From<yh_object_type> for ObjectType {
    fn from(object_type: yh_object_type) -> Self {
        match object_type {
            yh_object_type::YH_ANY => ObjectType::Any,
            yh_object_type::YH_OPAQUE => ObjectType::Opaque,
            yh_object_type::YH_AUTHENTICATION_KEY => ObjectType::AuthenticationKey,
            yh_object_type::YH_ASYMMETRIC_KEY => ObjectType::AsymmetricKey,
            yh_object_type::YH_WRAP_KEY => ObjectType::WrapKey,
            yh_object_type::YH_HMAC_KEY => ObjectType::HmacKey,
            yh_object_type::YH_TEMPLATE => ObjectType::Template,
            yh_object_type::YH_OTP_AEAD_KEY => ObjectType::OtpAeadKey,
            yh_object_type::YH_PUBLIC_KEY => ObjectType::PublicKey,
        }
    }
}

impl<'a> From<&'a yh_object_type> for ObjectType {
    fn from(object_type: &'a yh_object_type) -> Self {
        (*object_type).into()
    }
}

impl From<yh_algorithm> for ObjectAlgorithm {
    fn from(algorithm: yh_algorithm) -> ObjectAlgorithm {
        match algorithm {
            yh_algorithm::YH_ALGO_ANY => ObjectAlgorithm::ANY,
            yh_algorithm::YH_ALGO_RSA_PKCS1_SHA1 => ObjectAlgorithm::RsaPkcs1Sha1,
            yh_algorithm::YH_ALGO_RSA_PKCS1_SHA256 => ObjectAlgorithm::RsaPkcs1Sha256,
            yh_algorithm::YH_ALGO_RSA_PKCS1_SHA384 => ObjectAlgorithm::RsaPkcs1Sha384,
            yh_algorithm::YH_ALGO_RSA_PKCS1_SHA512 => ObjectAlgorithm::RsaPkcs1Sha512,
            yh_algorithm::YH_ALGO_RSA_PSS_SHA1 => ObjectAlgorithm::RsaPssSha1,
            yh_algorithm::YH_ALGO_RSA_PSS_SHA256 => ObjectAlgorithm::RsaPssSha256,
            yh_algorithm::YH_ALGO_RSA_PSS_SHA384 => ObjectAlgorithm::RsaPssSha384,
            yh_algorithm::YH_ALGO_RSA_PSS_SHA512 => ObjectAlgorithm::RsaPssSha512,
            yh_algorithm::YH_ALGO_RSA_2048 => ObjectAlgorithm::Rsa2048,
            yh_algorithm::YH_ALGO_RSA_3072 => ObjectAlgorithm::Rsa3072,
            yh_algorithm::YH_ALGO_RSA_4096 => ObjectAlgorithm::Rsa4096,
            yh_algorithm::YH_ALGO_EC_P256 => ObjectAlgorithm::EcP256,
            yh_algorithm::YH_ALGO_EC_P384 => ObjectAlgorithm::EcP384,
            yh_algorithm::YH_ALGO_EC_P521 => ObjectAlgorithm::EcP521,
            yh_algorithm::YH_ALGO_EC_K256 => ObjectAlgorithm::EcK256,
            yh_algorithm::YH_ALGO_EC_BP256 => ObjectAlgorithm::EcBp256,
            yh_algorithm::YH_ALGO_EC_BP384 => ObjectAlgorithm::EcBp384,
            yh_algorithm::YH_ALGO_EC_BP512 => ObjectAlgorithm::EcBp512,
            yh_algorithm::YH_ALGO_HMAC_SHA1 => ObjectAlgorithm::HmacSha1,
            yh_algorithm::YH_ALGO_HMAC_SHA256 => ObjectAlgorithm::HmacSha256,
            yh_algorithm::YH_ALGO_HMAC_SHA384 => ObjectAlgorithm::HmacSha384,
            yh_algorithm::YH_ALGO_HMAC_SHA512 => ObjectAlgorithm::HmacSha512,
            yh_algorithm::YH_ALGO_EC_ECDSA_SHA1 => ObjectAlgorithm::EcdsaSha1,
            yh_algorithm::YH_ALGO_EC_ECDH => ObjectAlgorithm::Ecdh,
            yh_algorithm::YH_ALGO_RSA_OAEP_SHA1 => ObjectAlgorithm::RsaOaepSha1,
            yh_algorithm::YH_ALGO_RSA_OAEP_SHA256 => ObjectAlgorithm::RsaOaepSha256,
            yh_algorithm::YH_ALGO_RSA_OAEP_SHA384 => ObjectAlgorithm::RsaOaepSha384,
            yh_algorithm::YH_ALGO_RSA_OAEP_SHA512 => ObjectAlgorithm::RsaOaepSha512,
            yh_algorithm::YH_ALGO_AES128_CCM_WRAP => ObjectAlgorithm::Aes128CcmWrap,
            yh_algorithm::YH_ALGO_OPAQUE_DATA => ObjectAlgorithm::OpaqueData,
            yh_algorithm::YH_ALGO_OPAQUE_X509_CERTIFICATE => ObjectAlgorithm::OpaqueX509Certificate,
            yh_algorithm::YH_ALGO_MGF1_SHA1 => ObjectAlgorithm::Mgf1Sha1,
            yh_algorithm::YH_ALGO_MGF1_SHA256 => ObjectAlgorithm::Mgf1Sha256,
            yh_algorithm::YH_ALGO_MGF1_SHA384 => ObjectAlgorithm::Mgf1Sha384,
            yh_algorithm::YH_ALGO_MGF1_SHA512 => ObjectAlgorithm::Mgf1Sha512,
            yh_algorithm::YH_ALGO_TEMPLATE_SSH => ObjectAlgorithm::TemplateSsh,
            yh_algorithm::YH_ALGO_AES128_YUBICO_OTP => ObjectAlgorithm::Aes128YubicoOtp,
            yh_algorithm::YH_ALGO_AES128_YUBICO_AUTHENTICATION => {
                ObjectAlgorithm::Aes128YubicoAuthentication
            }
            yh_algorithm::YH_ALGO_AES192_YUBICO_OTP => ObjectAlgorithm::Aes192YubicoOtp,
            yh_algorithm::YH_ALGO_AES256_YUBICO_OTP => ObjectAlgorithm::Aes256YubicoOtp,
            yh_algorithm::YH_ALGO_AES192_CCM_WRAP => ObjectAlgorithm::Aes192CcmWrap,
            yh_algorithm::YH_ALGO_AES256_CCM_WRAP => ObjectAlgorithm::Aes256CcmWrap,
            yh_algorithm::YH_ALGO_EC_ECDSA_SHA256 => ObjectAlgorithm::EcdsaSha256,
            yh_algorithm::YH_ALGO_EC_ECDSA_SHA384 => ObjectAlgorithm::EcdsaSha384,
            yh_algorithm::YH_ALGO_EC_ECDSA_SHA512 => ObjectAlgorithm::EcdsaSha512,
            yh_algorithm::YH_ALGO_EC_ED25519 => ObjectAlgorithm::Ed25519,
            yh_algorithm::YH_ALGO_EC_P224 => ObjectAlgorithm::EcP224,
            yh_algorithm::YH_ALGO_RSA_PKCS1_DECRYPT => ObjectAlgorithm::RsaPkcs1Decrypt,
        }
    }
}

impl<'a> From<&'a yh_algorithm> for ObjectAlgorithm {
    fn from(algorithm: &'a yh_algorithm) -> ObjectAlgorithm {
        (*algorithm).into()
    }
}

impl From<ObjectAlgorithm> for yh_algorithm {
    fn from(algorithm: ObjectAlgorithm) -> yh_algorithm {
        match algorithm {
            ObjectAlgorithm::RsaPkcs1Sha1 => yh_algorithm::YH_ALGO_RSA_PKCS1_SHA1,
            ObjectAlgorithm::RsaPkcs1Sha256 => yh_algorithm::YH_ALGO_RSA_PKCS1_SHA256,
            ObjectAlgorithm::RsaPkcs1Sha384 => yh_algorithm::YH_ALGO_RSA_PKCS1_SHA384,
            ObjectAlgorithm::RsaPkcs1Sha512 => yh_algorithm::YH_ALGO_RSA_PKCS1_SHA512,
            ObjectAlgorithm::RsaPssSha1 => yh_algorithm::YH_ALGO_RSA_PSS_SHA1,
            ObjectAlgorithm::RsaPssSha256 => yh_algorithm::YH_ALGO_RSA_PSS_SHA256,
            ObjectAlgorithm::RsaPssSha384 => yh_algorithm::YH_ALGO_RSA_PSS_SHA384,
            ObjectAlgorithm::RsaPssSha512 => yh_algorithm::YH_ALGO_RSA_PSS_SHA512,
            ObjectAlgorithm::Rsa2048 => yh_algorithm::YH_ALGO_RSA_2048,
            ObjectAlgorithm::Rsa3072 => yh_algorithm::YH_ALGO_RSA_3072,
            ObjectAlgorithm::Rsa4096 => yh_algorithm::YH_ALGO_RSA_4096,
            ObjectAlgorithm::EcP256 => yh_algorithm::YH_ALGO_EC_P256,
            ObjectAlgorithm::EcP384 => yh_algorithm::YH_ALGO_EC_P384,
            ObjectAlgorithm::EcP521 => yh_algorithm::YH_ALGO_EC_P521,
            ObjectAlgorithm::EcK256 => yh_algorithm::YH_ALGO_EC_K256,
            ObjectAlgorithm::EcBp256 => yh_algorithm::YH_ALGO_EC_BP256,
            ObjectAlgorithm::EcBp384 => yh_algorithm::YH_ALGO_EC_BP384,
            ObjectAlgorithm::EcBp512 => yh_algorithm::YH_ALGO_EC_BP512,
            ObjectAlgorithm::HmacSha1 => yh_algorithm::YH_ALGO_HMAC_SHA1,
            ObjectAlgorithm::HmacSha256 => yh_algorithm::YH_ALGO_HMAC_SHA256,
            ObjectAlgorithm::HmacSha384 => yh_algorithm::YH_ALGO_HMAC_SHA384,
            ObjectAlgorithm::HmacSha512 => yh_algorithm::YH_ALGO_HMAC_SHA512,
            ObjectAlgorithm::EcdsaSha1 => yh_algorithm::YH_ALGO_EC_ECDSA_SHA1,
            ObjectAlgorithm::Ecdh => yh_algorithm::YH_ALGO_EC_ECDH,
            ObjectAlgorithm::RsaOaepSha1 => yh_algorithm::YH_ALGO_RSA_OAEP_SHA1,
            ObjectAlgorithm::RsaOaepSha256 => yh_algorithm::YH_ALGO_RSA_OAEP_SHA256,
            ObjectAlgorithm::RsaOaepSha384 => yh_algorithm::YH_ALGO_RSA_OAEP_SHA384,
            ObjectAlgorithm::RsaOaepSha512 => yh_algorithm::YH_ALGO_RSA_OAEP_SHA512,
            ObjectAlgorithm::Aes128CcmWrap => yh_algorithm::YH_ALGO_AES128_CCM_WRAP,
            ObjectAlgorithm::OpaqueData => yh_algorithm::YH_ALGO_OPAQUE_DATA,
            ObjectAlgorithm::OpaqueX509Certificate => yh_algorithm::YH_ALGO_OPAQUE_X509_CERTIFICATE,
            ObjectAlgorithm::Mgf1Sha1 => yh_algorithm::YH_ALGO_MGF1_SHA1,
            ObjectAlgorithm::Mgf1Sha256 => yh_algorithm::YH_ALGO_MGF1_SHA256,
            ObjectAlgorithm::Mgf1Sha384 => yh_algorithm::YH_ALGO_MGF1_SHA384,
            ObjectAlgorithm::Mgf1Sha512 => yh_algorithm::YH_ALGO_MGF1_SHA512,
            ObjectAlgorithm::TemplateSsh => yh_algorithm::YH_ALGO_TEMPLATE_SSH,
            ObjectAlgorithm::Aes128YubicoOtp => yh_algorithm::YH_ALGO_AES128_YUBICO_OTP,
            ObjectAlgorithm::Aes128YubicoAuthentication => {
                yh_algorithm::YH_ALGO_AES128_YUBICO_AUTHENTICATION
            }
            ObjectAlgorithm::Aes192YubicoOtp => yh_algorithm::YH_ALGO_AES192_YUBICO_OTP,
            ObjectAlgorithm::Aes256YubicoOtp => yh_algorithm::YH_ALGO_AES256_YUBICO_OTP,
            ObjectAlgorithm::Aes192CcmWrap => yh_algorithm::YH_ALGO_AES192_CCM_WRAP,
            ObjectAlgorithm::Aes256CcmWrap => yh_algorithm::YH_ALGO_AES256_CCM_WRAP,
            ObjectAlgorithm::EcdsaSha256 => yh_algorithm::YH_ALGO_EC_ECDSA_SHA256,
            ObjectAlgorithm::EcdsaSha384 => yh_algorithm::YH_ALGO_EC_ECDSA_SHA384,
            ObjectAlgorithm::EcdsaSha512 => yh_algorithm::YH_ALGO_EC_ECDSA_SHA512,
            ObjectAlgorithm::Ed25519 => yh_algorithm::YH_ALGO_EC_ED25519,
            ObjectAlgorithm::EcP224 => yh_algorithm::YH_ALGO_EC_P224,
            ObjectAlgorithm::RsaPkcs1Decrypt => yh_algorithm::YH_ALGO_RSA_PKCS1_DECRYPT,
            ObjectAlgorithm::ANY => yh_algorithm::YH_ALGO_ANY,
        }
    }
}

impl<'a> From<&'a ObjectAlgorithm> for yh_algorithm {
    fn from(algorithm: &'a ObjectAlgorithm) -> yh_algorithm {
        (*algorithm).into()
    }
}

impl Display for ObjectAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let mut ptr: *const std::os::raw::c_char = std::ptr::null();

        let a: yh_algorithm = self.into();

        try!(unsafe {
            ::error::result_from_libyh(lyh::yh_algo_to_string(a, &mut ptr))
                .map_err(|_| std::fmt::Error)
        });

        let cstr = try!(unsafe {
            std::ffi::CStr::from_ptr(ptr)
                .to_str()
                .map_err(|_| std::fmt::Error)
        });

        write!(f, "{}", cstr)
    }
}

impl ObjectOrigin {
    fn from_primitive(origin: u8) -> Self {
        if origin == lyh::YH_ORIGIN_GENERATED as u8 {
            ObjectOrigin::Generated
        } else if origin == lyh::YH_ORIGIN_IMPORTED as u8 {
            ObjectOrigin::Imported
        } else if origin == lyh::YH_ORIGIN_GENERATED as u8 + lyh::YH_ORIGIN_IMPORTED_WRAPPED as u8 {
            ObjectOrigin::WrappedGenerated
        } else {
            ObjectOrigin::WrappedImported
        }
    }
}

impl From<yh_object_descriptor> for ObjectDescriptor {
    fn from(descriptor: yh_object_descriptor) -> Self {
        let delegated = ObjectCapability::from_primitive(descriptor.delegated_capabilities);
        let delegated = if delegated.is_empty() {
            None
        } else {
            Some(delegated)
        };

        ObjectDescriptor {
            capabilities: ObjectCapability::from_primitive(descriptor.capabilities),
            id: descriptor.id,
            len: descriptor.len,
            domains: ObjectDomain::from_primitive(descriptor.domains),
            object_type: ObjectType::from(unsafe { descriptor.type_ }),
            algorithm: ObjectAlgorithm::from(unsafe { descriptor.algorithm }),
            sequence: descriptor.sequence,
            origin: ObjectOrigin::from_primitive(descriptor.origin),
            label: descriptor.label.to_string(),
            delegated_capabilities: delegated,
        }
    }
}

impl Display for ObjectDescriptor {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let mut desc_str = String::new().to_owned();
        desc_str.push_str(format!("id: 0x{:04x?}\t", self.id).as_str());
        desc_str.push_str(format!("label: {:40}\t", self.label).as_str());
        desc_str.push_str(format!("algo: {:24}\t", self.algorithm).as_str());

        desc_str.push_str(format!("seq: {:2}\t", self.sequence).as_str());
        desc_str.push_str(format!("origin: {:17?}\t", self.origin).as_str());
        let mut dom_str = String::new().to_owned();
        self.domains.iter().for_each(|domain| dom_str.push_str(format!("{},", domain).as_str()));
        desc_str.push_str(format!("domains: {:40}\t", dom_str).as_str());
        let mut caps_str = String::new().to_owned();
        self.capabilities.iter().for_each(|cap| caps_str.push_str(format!("{:?},", cap).as_str()));
        desc_str.push_str(format!("capabilities: {}\t", caps_str).as_str());
        if self.object_type==ObjectType::AuthenticationKey || self.object_type==ObjectType::WrapKey {
            caps_str = String::new().to_owned();
            self.delegated_capabilities.iter().for_each(|cap| caps_str.push_str(format!("{:?},", cap).as_str()));
            desc_str.push_str(format!("delegated capabilities: {:?}\t", caps_str).as_str());
        }
        write!(f, "{}", desc_str)
    }
}

impl From<ObjectType> for yh_object_type {
    fn from(object_type: ObjectType) -> Self {
        match object_type {
            ObjectType::Opaque => yh_object_type::YH_OPAQUE,
            ObjectType::AuthenticationKey => yh_object_type::YH_AUTHENTICATION_KEY,
            ObjectType::AsymmetricKey => yh_object_type::YH_ASYMMETRIC_KEY,
            ObjectType::WrapKey => yh_object_type::YH_WRAP_KEY,
            ObjectType::HmacKey => yh_object_type::YH_HMAC_KEY,
            ObjectType::Template => yh_object_type::YH_TEMPLATE,
            ObjectType::OtpAeadKey => yh_object_type::YH_OTP_AEAD_KEY,
            ObjectType::PublicKey => yh_object_type::YH_PUBLIC_KEY,
            ObjectType::Any => yh_object_type::YH_ANY,
        }
    }
}

impl<'a> From<&'a ObjectType> for yh_object_type {
    fn from(object_type: &'a ObjectType) -> Self {
        (*object_type).into()
    }
}

impl Display for ObjectType {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let mut ptr: *const std::os::raw::c_char = std::ptr::null();

        try!(unsafe {
            ::error::result_from_libyh(lyh::yh_type_to_string(self.into(), &mut ptr))
                .map_err(|_| std::fmt::Error)
        });

        let cstr = try!(unsafe {
            std::ffi::CStr::from_ptr(ptr)
                .to_str()
                .map_err(|_| std::fmt::Error)
        });

        write!(f, "{}", cstr)
    }
}

impl<'a> From<&'a yh_object_descriptor> for ObjectHandle {
    fn from(descriptor: &'a yh_object_descriptor) -> Self {
        ObjectHandle {
            object_id: descriptor.id,
            object_type: match descriptor.type_ {
                yh_object_type::YH_OPAQUE => ObjectType::Opaque,
                yh_object_type::YH_AUTHENTICATION_KEY => ObjectType::AuthenticationKey,
                yh_object_type::YH_ASYMMETRIC_KEY => ObjectType::AsymmetricKey,
                yh_object_type::YH_WRAP_KEY => ObjectType::WrapKey,
                yh_object_type::YH_HMAC_KEY => ObjectType::HmacKey,
                yh_object_type::YH_TEMPLATE => ObjectType::Template,
                yh_object_type::YH_OTP_AEAD_KEY => ObjectType::OtpAeadKey,
                yh_object_type::YH_PUBLIC_KEY => ObjectType::PublicKey,
                yh_object_type::YH_ANY => ObjectType::Any,
            },
        }
    }
}

impl Display for ObjectHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "0x{:x}   {}", self.object_id, self.object_type)
    }
}

/*impl From<(u8, u8)> for ObjectCapability {
    fn from(key: (u8, u8)) -> Self {
        CAPABILITIES_MAP[&key]
    }
}*/

impl<'a> From<&'a ObjectCapability> for (u8, u8) {
    fn from(capability: &'a ObjectCapability) -> Self {
        match *capability {
            ObjectCapability::GetOpaque => (0, 0x01),
            ObjectCapability::PutOpaque => (0, 0x02),
            ObjectCapability::PutAuthenticationKey => (0, 0x04),
            ObjectCapability::PutAsymmetricKey => (0, 0x08),
            ObjectCapability::GenerateAsymmetricKey => (0, 0x10),
            ObjectCapability::SignPkcs => (0, 0x20),
            ObjectCapability::SignPss => (0, 0x40),
            ObjectCapability::SignEcdsa => (0, 0x80),

            ObjectCapability::SignEddsa => (1, 0x01),
            ObjectCapability::DecryptPkcs => (1, 0x02),
            ObjectCapability::DecryptOaep => (1, 0x04),
            ObjectCapability::DeriveEcdh => (1, 0x08),
            ObjectCapability::ExportWrapped => (1, 0x10),
            ObjectCapability::ImportWrapped => (1, 0x20),
            ObjectCapability::PutWrapKey => (1, 0x40),
            ObjectCapability::GenerateWrapKey => (1, 0x80),

            ObjectCapability::ExportableUnderWrap => (2, 0x01),
            ObjectCapability::SetOption => (2, 0x02),
            ObjectCapability::GetOption => (2, 0x04),
            ObjectCapability::GetPseudoRandom => (2, 0x08),
            ObjectCapability::PutHmacKey => (2, 0x10),
            ObjectCapability::GenerateHmacKey => (2, 0x20),
            ObjectCapability::SignHmac => (2, 0x40),
            ObjectCapability::VerifyHmac => (2, 0x80),

            ObjectCapability::GetLogEntries => (3, 0x01),
            ObjectCapability::SignSshCertificate => (3, 0x02),
            ObjectCapability::GetTemplate => (3, 0x04),
            ObjectCapability::PutTemplate => (3, 0x08),
            ObjectCapability::ResetDevice => (3, 0x10),
            ObjectCapability::DecryptOtp => (3, 0x20),
            ObjectCapability::CreateOtpAead => (3, 0x40),
            ObjectCapability::RandomizeOtpAead => (3, 0x80),

            ObjectCapability::RewrapFromOtpAeadKey => (4, 0x01),
            ObjectCapability::RewrapToOtpAeadKey => (4, 0x02),
            ObjectCapability::SignAttestationCertificate => (4, 0x04),
            ObjectCapability::PutOtpAeadKey => (4, 0x08),
            ObjectCapability::GenerateOtpAeadKey => (4, 0x10),
            ObjectCapability::WrapData => (4, 0x20),
            ObjectCapability::UnwrapData => (4, 0x40),
            ObjectCapability::DeleteOpaque => (4, 0x80),

            ObjectCapability::DeleteAuthenticationKey => (5, 0x01),
            ObjectCapability::DeleteAsymmetricKey => (5, 0x02),
            ObjectCapability::DeleteWrapKey => (5, 0x04),
            ObjectCapability::DeleteHmacKey => (5, 0x08),
            ObjectCapability::DeleteTemplate => (5, 0x10),
            ObjectCapability::DeleteOtpAeadKey => (5, 0x20),
        }
    }
}

impl From<ObjectDomain> for u16 {
    fn from(domain: ObjectDomain) -> Self {
        match domain {
            ObjectDomain::One => 1,
            ObjectDomain::Two => 1 << 1,
            ObjectDomain::Three => 1 << 2,
            ObjectDomain::Four => 1 << 3,
            ObjectDomain::Five => 1 << 4,
            ObjectDomain::Six => 1 << 5,
            ObjectDomain::Seven => 1 << 6,
            ObjectDomain::Eight => 1 << 7,
            ObjectDomain::Nine => 1 << 8,
            ObjectDomain::Ten => 1 << 9,
            ObjectDomain::Eleven => 1 << 10,
            ObjectDomain::Twelve => 1 << 11,
            ObjectDomain::Thirteen => 1 << 12,
            ObjectDomain::Fourteen => 1 << 13,
            ObjectDomain::Fifteen => 1 << 14,
            ObjectDomain::Sixteen => 1 << 15,
        }
    }
}

impl FromStr for ObjectAlgorithm {
    type Err = Error;
    fn from_str(algorithm: &str) -> Result<Self, Self::Err> {
        let mut algo = yh_algorithm::YH_ALGO_ANY;
        let c_str = ::std::ffi::CString::new(algorithm).unwrap();
        try!(::error::result_from_libyh(unsafe {
            lyh::yh_string_to_algo(c_str.as_ptr(), &mut algo)
        }));
        Ok(ObjectAlgorithm::from(&algo))
    }
}

impl ObjectAlgorithm {
    /// Returns whether the algorithm is an RSA key algorithm or not
    pub fn is_rsa(algorithm: ObjectAlgorithm) -> bool {
        {
            unsafe { lyh::yh_is_rsa(algorithm.into()) }
        }
    }
}

/// struct representing an asymmetric key
#[derive(Debug, Clone)]
pub struct AsymmetricKey {
    key_id: u16,
    label: String,
    algorithm: ObjectAlgorithm,
    capabilities: Vec<ObjectCapability>,
    domains: Vec<ObjectDomain>,
}

impl AsymmetricKey {
    /// Returns the Object ID of the key
    pub fn get_key_id(&self) -> u16 {
        self.key_id
    }

    /// Returns whether the algorithm is an RSA key algorithm or not
    pub fn is_rsa(&self) -> bool {
        unsafe { lyh::yh_is_rsa(self.algorithm.into()) }
    }

    /// Returns whether the algorithm is an EC key algorithm or not
    pub fn is_ec(&self) -> bool {
        unsafe { lyh::yh_is_ec(self.algorithm.into()) }
    }

    /// Returns whether the algorithm is an Ed key algorithm or not
    pub fn is_ed(&self) -> bool {
        unsafe { lyh::yh_is_ed(self.algorithm.into()) }
    }

    /// Creates a new instance of AsymmetricKey
    pub fn new(
        key_id: u16,
        label: String,
        algorithm: ObjectAlgorithm,
        capabilities: Vec<ObjectCapability>,
        domains: Vec<ObjectDomain>,
    ) -> AsymmetricKey {
        AsymmetricKey {
            key_id,
            label,
            algorithm,
            capabilities,
            domains,
        }
    }

    /// Signs an attestation certificate for another asymmetric key
    pub fn sign_attestation_certificate(
        &self,
        keyid_to_attest: u16,
        session: &Session,
    ) -> Result<Vec<u8>, Error> {
        let mut out = vec![0; lyh::YH_MSG_BUF_SIZE as usize].into_boxed_slice();
        let mut out_len = out.len();

        let res = unsafe {
            lyh::yh_util_sign_attestation_certificate(
                session.ptr,
                self.key_id,
                keyid_to_attest,
                out.as_mut_ptr(),
                &mut out_len,
            )
        };
        try!(::error::result_from_libyh(res));

        let mut out_vec = out.into_vec();
        out_vec.truncate(out_len);

        Ok(out_vec)
    }
}

/// struct representing an opaque object
#[derive(Debug)]
pub struct OpaqueObject {
    object_id: u16,
    label: String,
    algorithm: ObjectAlgorithm,
    capabilities: Vec<ObjectCapability>,
    domains: Vec<ObjectDomain>,
}

impl OpaqueObject {
    /// Returns the Object ID of the key
    pub fn get_id(&self) -> u16 {
        self.object_id
    }

    /// Creates a new instance of AsymmetricKey
    pub fn new(
        object_id: u16,
        label: String,
        algorithm: ObjectAlgorithm,
        capabilities: Vec<ObjectCapability>,
        domains: Vec<ObjectDomain>,
    ) -> OpaqueObject {
        OpaqueObject {
            object_id,
            label,
            algorithm,
            capabilities,
            domains,
        }
    }
}

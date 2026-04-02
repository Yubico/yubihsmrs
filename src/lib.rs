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

//! Rust library for the YubiHSM 2

extern crate libyubihsm_sys as lyh;

#[macro_use]
extern crate lazy_static;

#[macro_use]
extern crate log;

extern crate regex;
extern crate rustc_serialize;

extern crate serde;

use std::fmt::Display;
use lyh::{yh_algorithm, yh_connector, YH_EC_P256_PRIVKEY_LEN, YH_EC_P256_PUBKEY_LEN, yh_rc, yh_session};

pub mod error;
use error::Error;

pub mod object;

use object::{AsymmetricKey, ObjectAlgorithm, ObjectCapability, ObjectDescriptor, ObjectDomain, ObjectHandle, ObjectType, OpaqueObject};

pub mod otp;

#[derive(Debug, Clone)]
/// YubiHSM handle
pub struct YubiHsm {
    connector: *const yh_connector,
}

#[derive(Debug, Clone)]
/// Session handle
pub struct Session {
    ptr: *mut yh_session,
}

#[derive(Debug, Clone)]
/// Device information
pub struct DeviceInfo {
    /// Major version
    major: u8,
    /// Minor version
    minor: u8,
    /// Patch version
    patch: u8,
    /// Serial number
    serial: u32,
    /// Available log entries
    log_total: u8,
    /// Used log entries
    log_used: u8,
    /// Supported algorihms
    algorithms: Vec<yh_algorithm>,
}

impl Display for DeviceInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let mut info = String::new().to_owned();
        info.push_str(format!("Version number:\t\t {}.{}.{}\n", self.major, self.minor, self.patch).as_str());
        info.push_str(format!("Serial number:\t\t {}\n", self.serial).as_str());
        info.push_str(format!("Log used:\t\t\t {}/{}\n", self.log_used, self.log_total).as_str());

        let mut algo_str = String::new().to_owned();
        self.algorithms.iter().for_each(|a| algo_str.push_str(format!("{},", ObjectAlgorithm::from(a)).as_str()));
        info.push_str(format!("Supported algorithms:\t {}\t", algo_str).as_str());
        write!(f, "{}", info)
    }
}

impl DeviceInfo {
    /// Firmware major version
    pub fn major(&self) -> u8 {
        self.major
    }
    /// Firmware minor version
    pub fn minor(&self) -> u8 {
        self.minor
    }
    /// Firmware patch version
    pub fn patch(&self) -> u8 {
        self.patch
    }
}

/// Initialize libyubihsm
pub fn init() -> Result<(), Error> {
    // TODO(adma): possibly hide this behind fnOnce
    error::result_from_libyh(unsafe { lyh::yh_init() })
}

/// Finalize libyubihsm
pub fn exit() -> Result<(), Error> {
    // TODO(adma): possibly hide this behind fnOnce
    error::result_from_libyh(unsafe { lyh::yh_exit() })
}

impl YubiHsm {
    /// Create a YubiHSM object using a given connector URL
    pub fn new(url: &str) -> Result<Self, Error> {
        let connector_ptr: *mut yh_connector = ::std::ptr::null_mut();
        let c_url = ::std::ffi::CString::new(url).unwrap();

        error::result_from_libyh(unsafe {
            lyh::yh_init_connector(c_url.as_ptr(), &connector_ptr)
        })?;

        error::result_from_libyh(unsafe { lyh::yh_connect(connector_ptr) }).and(Ok(YubiHsm {
            connector: connector_ptr,
        }))
    }

    /// Open and authenticate a session with the device
    pub fn establish_session(
        &self,
        key_id: u16,
        password: &str,
        reopen: bool,
    ) -> Result<Session, Error> {
        let session_ptr: *mut yh_session = ::std::ptr::null_mut();

        error::result_from_libyh(unsafe {
            lyh::yh_create_session_derived(
                self.connector,
                key_id,
                password.as_ptr(),
                password.len(),
                reopen,
                &session_ptr,
            )
        })
        .and(error::result_from_libyh(unsafe {
            lyh::yh_authenticate_session(session_ptr)
        }))?;

        Ok(Session { ptr: session_ptr })
    }

    /// Open a session with the device authenticated with an asymmetrical authkey
    pub fn establish_session_asym(
        &self,
        key_id: u16,
        privkey: &[u8],
        device_pubkey: &[u8],
    ) -> Result<Session, Error> {
        let session_ptr: *mut yh_session = ::std::ptr::null_mut();

        error::result_from_libyh(unsafe {
            lyh::yh_create_session_asym(
                self.connector,
                key_id,
                privkey.as_ptr(),
                privkey.len(),
                device_pubkey.as_ptr(),
                device_pubkey.len(),
                &session_ptr,
            )
        })
            .and(error::result_from_libyh(unsafe {
                lyh::yh_authenticate_session(session_ptr)
            }))?;

        Ok(Session { ptr: session_ptr })
    }

    /// Obtain device information
    pub fn get_device_info(&self) -> Result<DeviceInfo, Error> {
        let res;
        let mut major = 0;
        let mut minor = 0;
        let mut patch = 0;
        let mut serial = 0;
        let mut log_total = 0;
        let mut log_used = 0;
        let mut algorithms =
            [yh_algorithm::YH_ALGO_RSA_PKCS1_SHA1; lyh::YH_MAX_ALGORITHM_COUNT];
        let mut n_algorithms = lyh::YH_MAX_ALGORITHM_COUNT;

        unsafe {
            res = lyh::yh_util_get_device_info(
                self.connector,
                &mut major,
                &mut minor,
                &mut patch,
                &mut serial,
                &mut log_total,
                &mut log_used,
                algorithms.as_mut_ptr(),
                &mut n_algorithms,
            );
        }

        error::result_from_libyh(res)?;

        Ok(DeviceInfo {
            major,
            minor,
            patch,
            serial,
            log_total,
            log_used,
            algorithms: algorithms[0..n_algorithms].to_vec(),
        })
    }

    /// Obtain device public key
    pub fn get_device_pubkey(&self) -> Result<Vec<u8>, Error> {
        let mut out = vec![0; lyh::YH_MSG_BUF_SIZE as usize].into_boxed_slice();
        let mut out_len = out.len();
        let mut key_algorithm = yh_algorithm::YH_ALGO_ANY;

        let res = unsafe {
            lyh::yh_util_get_device_pubkey (
                self.connector,
                out.as_mut_ptr(),
                &mut out_len,
                &mut key_algorithm,
            )
        };
        error::result_from_libyh(res)?;

        let mut out_vec = out.into_vec();
        out_vec.truncate(out_len);

        Ok(out_vec)
    }

    /// Disconnect from the device
    pub fn disconnect(&self) -> Result<(), Error> {
        error::result_from_libyh(unsafe { lyh::yh_disconnect(self.connector) })
    }

    /// Set verbosity
    pub fn set_verbosity(&self, verbosity: bool) -> Result<(), Error> {
        if verbosity {
            error::result_from_libyh(unsafe { lyh::yh_set_verbosity(self.connector, 0xff) })
        } else {
            error::result_from_libyh(unsafe { lyh::yh_set_verbosity(self.connector, 0x00) })
        }
    }
}

impl Drop for YubiHsm {
    fn drop(&mut self) {
        trace!("Dropping hsm");
        self.disconnect().unwrap_or(()); // NOTE(adma): ignore return value ...
    }
}

unsafe impl Send for Session {}
unsafe impl Sync for Session {}

/// Session handle
impl Session {
    /// Close an open session
    pub fn close(&self) -> Result<(), Error> {
        let mut res;

        debug!("Calling close on {:?}", self.ptr);

        unsafe {
            res = lyh::yh_util_close_session(self.ptr);
        }

        if res != yh_rc::YHR_SUCCESS && res != yh_rc::YHR_DEVICE_INV_SESSION {
            return error::result_from_libyh(res);
        }

        trace!("Destroying session {:?}", self.ptr);
        unsafe {
            res = lyh::yh_destroy_session(&self.ptr);
        }

        if res != yh_rc::YHR_SUCCESS {
            return error::result_from_libyh(res);
        }

        error::result_from_libyh(res)
    }

    /// List objects on the device
    pub fn list_objects(&self) -> Result<Vec<ObjectHandle>, Error> {
        let capabilities:Vec<ObjectCapability> = Vec::new();
        self.list_objects_with_filter(0, ObjectType::Any, "", ObjectAlgorithm::ANY, &capabilities)
    }

    /// List objects on the device
    pub fn list_objects_with_filter(&self, obj_id:u16, obj_type:ObjectType, label:&str, algorithm:ObjectAlgorithm, object_capabilities: &[ObjectCapability]) -> Result<Vec<ObjectHandle>, Error> {
        let c_str = ::std::ffi::CString::new(label).unwrap();
        /*let capa = yh_capabilities {
            capabilities: [0u8; 8],
        };*/
        let descriptor = lyh::yh_object_descriptor::default();
        let mut objects = vec![descriptor; 512].into_boxed_slice();
        let mut n_objects = 512;

        let res = unsafe {
            lyh::yh_util_list_objects(
                self.ptr,
                obj_id,
                lyh::yh_object_type::from(obj_type),
                0,
                &ObjectCapability::primitive_from_slice(object_capabilities),
                yh_algorithm::from(algorithm),
                c_str.as_ptr(),
                objects.as_mut_ptr(),
                &mut n_objects,
            )
        };

        error::result_from_libyh(res)?;

        Ok(objects[0..n_objects]
            .iter()
            .map(ObjectHandle::from)
            .collect())
    }

    /// Get information about a specific object
    pub fn get_object_info(
        &self,
        id: u16,
        object_type: ObjectType,
    ) -> Result<ObjectDescriptor, Error> {
        let mut descriptor = lyh::yh_object_descriptor::default();

        let res = unsafe {
            lyh::yh_util_get_object_info(self.ptr, id, object_type.into(), &mut descriptor)
        };

        error::result_from_libyh(res)?;

        Ok(ObjectDescriptor::from(descriptor))
    }

    /// Delete an object
    pub fn delete_object(&self, id: u16, object_type: ObjectType) -> Result<(), Error> {
        let res = unsafe { lyh::yh_util_delete_object(self.ptr, id, object_type.into()) };

        error::result_from_libyh(res)?;

        Ok(())
    }

    /// Get random data
    pub fn get_random(&self, count: usize) -> Result<Vec<u8>, Error> {
        let mut bytes = vec![0; count].into_boxed_slice();
        let mut returned = count;

        let res = unsafe {
            lyh::yh_util_get_pseudo_random(self.ptr, count, bytes.as_mut_ptr(), &mut returned)
        };

        error::result_from_libyh(res)?;

        if returned != count {
            return Err(Error::WrongLength(count, returned));
        }

        Ok(bytes.into_vec())
    }

    /// Import an authkey
    pub fn import_authentication_key(
        &self,
        id: u16,
        label: &str,
        domains: &[ObjectDomain],
        capabilities: &[ObjectCapability],
        delegated_capabilities: &[ObjectCapability],
        password: &[u8],
    ) -> Result<u16, Error> {
        let mut real_id = id;

        let c_str = ::std::ffi::CString::new(label).unwrap();

        let res = unsafe {
            lyh::yh_util_import_authentication_key_derived(
                self.ptr,
                &mut real_id,
                c_str.as_ptr(),
                ObjectDomain::primitive_from_slice(domains),
                &ObjectCapability::primitive_from_slice(capabilities),
                &ObjectCapability::primitive_from_slice(delegated_capabilities),
                password.as_ptr(),
                password.len(),
            )
        };
        error::result_from_libyh(res)?;

        Ok(real_id)
    }

    /// Import an ECP256 public key as authkey
    pub fn import_authentication_publickey(
        &self,
        id: u16,
        label: &str,
        domains: &[ObjectDomain],
        capabilities: &[ObjectCapability],
        delegated_capabilities: &[ObjectCapability],
        pubkey: &[u8],
    ) -> Result<u16, Error> {
        let mut real_id = id;

        let c_str = ::std::ffi::CString::new(label).unwrap();

        let res = unsafe {
            lyh::yh_util_import_authentication_key(
                self.ptr,
                &mut real_id,
                c_str.as_ptr(),
                ObjectDomain::primitive_from_slice(domains),
                &ObjectCapability::primitive_from_slice(capabilities),
                &ObjectCapability::primitive_from_slice(delegated_capabilities),
                pubkey[1..].as_ptr(),
                pubkey.len() - 1,
                [].as_ptr(),
                0
            )
        };
        error::result_from_libyh(res)?;

        Ok(real_id)
    }

    /// Derive ECP256 key from a password and return the public key portion
    pub fn derive_ec_p256_key_from_password(&self, password: &[u8]) -> Result<Vec<u8>, Error> {

        let privkey:[u8;YH_EC_P256_PRIVKEY_LEN] = [0;YH_EC_P256_PRIVKEY_LEN];
        let pubkey:[u8;YH_EC_P256_PUBKEY_LEN] = [0;YH_EC_P256_PUBKEY_LEN];

        let res = unsafe {
            lyh::yh_util_derive_ec_p256_key(
                password.as_ptr(),
                password.len(),
                privkey.as_ptr(),
                privkey.len(),
                pubkey.as_ptr(),
                pubkey.len(),
            )
        };
        error::result_from_libyh(res)?;
        Ok(pubkey.to_vec())
    }

    /// Generate a wrapkey
    pub fn generate_wrap_key(
        &self,
        id: u16,
        label: &str,
        domains: &[ObjectDomain],
        capabilities: &[ObjectCapability],
        algorithm: ObjectAlgorithm,
        delegated_capabilities: &[ObjectCapability],
    ) -> Result<u16, Error> {
        let mut real_id = id;

        let c_str = ::std::ffi::CString::new(label).unwrap();

        let res = unsafe {
            lyh::yh_util_generate_wrap_key(
                self.ptr,
                &mut real_id,
                c_str.as_ptr(),
                ObjectDomain::primitive_from_slice(domains),
                &ObjectCapability::primitive_from_slice(capabilities),
                algorithm.into(),
                &ObjectCapability::primitive_from_slice(delegated_capabilities),
            )
        };
        error::result_from_libyh(res)?;

        Ok(real_id)
    }


    #[allow(clippy::too_many_arguments)]
    /// Import a wrapkey
    pub fn import_wrap_key(
        &self,
        id: u16,
        label: &str,
        domains: &[ObjectDomain],
        capabilities: &[ObjectCapability],
        algorithm: ObjectAlgorithm,
        delegated_capabilities: &[ObjectCapability],
        wrapkey: &[u8],
    ) -> Result<u16, Error> {
        let mut real_id = id;

        let c_str = ::std::ffi::CString::new(label).unwrap();

        let res = unsafe {
            lyh::yh_util_import_wrap_key(
                self.ptr,
                &mut real_id,
                c_str.as_ptr(),
                ObjectDomain::primitive_from_slice(domains),
                &ObjectCapability::primitive_from_slice(capabilities),
                algorithm.into(),
                &ObjectCapability::primitive_from_slice(delegated_capabilities),
                wrapkey.as_ptr(),
                wrapkey.len(),
            )
        };
        error::result_from_libyh(res)?;

        Ok(real_id)
    }

    #[allow(clippy::too_many_arguments)]
    /// Import an RSA public key as wrapkey
    pub fn import_public_wrap_key(
        &self,
        id: u16,
        label: &str,
        domains: &[ObjectDomain],
        capabilities: &[ObjectCapability],
        algorithm: ObjectAlgorithm,
        delegated_capabilities: &[ObjectCapability],
        wrapkey: &[u8],
    ) -> Result<u16, Error> {
        let mut real_id = id;

        let c_str = ::std::ffi::CString::new(label).unwrap();

        let res = unsafe {
            lyh::yh_util_import_public_wrap_key(
                self.ptr,
                &mut real_id,
                c_str.as_ptr(),
                ObjectDomain::primitive_from_slice(domains),
                &ObjectCapability::primitive_from_slice(capabilities),
                algorithm.into(),
                &ObjectCapability::primitive_from_slice(delegated_capabilities),
                wrapkey.as_ptr(),
                wrapkey.len(),
            )
        };
        error::result_from_libyh(res)?;

        Ok(real_id)
    }


    #[allow(clippy::too_many_arguments)]
    /// Import a RSA key
    pub fn import_rsa_key(
        &self,
        id: u16,
        label: &str,
        domains: &[ObjectDomain],
        capabilities: &[ObjectCapability],
        algorithm: ObjectAlgorithm,
        p: &[u8],
        q: &[u8],
    ) -> Result<u16, Error> {
        let mut real_id = id;

        let c_str = ::std::ffi::CString::new(label).unwrap();

        let res = unsafe {
            lyh::yh_util_import_rsa_key(
                self.ptr,
                &mut real_id,
                c_str.as_ptr(),
                ObjectDomain::primitive_from_slice(domains),
                &ObjectCapability::primitive_from_slice(capabilities),
                algorithm.into(),
                p.as_ptr(),
                q.as_ptr(),
            )
        };
        error::result_from_libyh(res)?;

        Ok(real_id)
    }

    #[allow(clippy::too_many_arguments)]
    /// Import a EC key
    pub fn import_ec_key(
        &self,
        id: u16,
        label: &str,
        domains: &[ObjectDomain],
        capabilities: &[ObjectCapability],
        algorithm: ObjectAlgorithm,
        s: &[u8],
    ) -> Result<u16, Error> {
        let mut real_id = id;

        let c_str = ::std::ffi::CString::new(label).unwrap();

        let res = unsafe {
            lyh::yh_util_import_ec_key(
                self.ptr,
                &mut real_id,
                c_str.as_ptr(),
                ObjectDomain::primitive_from_slice(domains),
                &ObjectCapability::primitive_from_slice(capabilities),
                algorithm.into(),
                s.as_ptr(),
            )
        };
        error::result_from_libyh(res)?;

        Ok(real_id)
    }

    #[allow(clippy::too_many_arguments)]
    /// Import a ED key
    pub fn import_ed_key(
        &self,
        id: u16,
        label: &str,
        domains: &[ObjectDomain],
        capabilities: &[ObjectCapability],
        k: &[u8],
    ) -> Result<u16, Error> {
        let mut real_id = id;

        let c_str = ::std::ffi::CString::new(label).unwrap();

        let res = unsafe {
            lyh::yh_util_import_ed_key(
                self.ptr,
                &mut real_id,
                c_str.as_ptr(),
                ObjectDomain::primitive_from_slice(domains),
                &ObjectCapability::primitive_from_slice(capabilities),
                yh_algorithm::YH_ALGO_EC_ED25519,
                k.as_ptr(),
            )
        };
        error::result_from_libyh(res)?;

        Ok(real_id)
    }

    #[allow(clippy::too_many_arguments)]
    /// Import an AES key
    pub fn import_aes_key(
        &self,
        id: u16,
        label: &str,
        domains: &[ObjectDomain],
        capabilities: &[ObjectCapability],
        algorithm: ObjectAlgorithm,
        k: &[u8],
    ) -> Result<u16, Error> {
        let mut real_id = id;

        let c_str = ::std::ffi::CString::new(label).unwrap();

        let res = unsafe {
            lyh::yh_util_import_aes_key(
                self.ptr,
                &mut real_id,
                c_str.as_ptr(),
                ObjectDomain::primitive_from_slice(domains),
                &ObjectCapability::primitive_from_slice(capabilities),
                algorithm.into(),
                k.as_ptr(),
            )
        };
        error::result_from_libyh(res)?;

        Ok(real_id)
    }

    #[allow(clippy::too_many_arguments)]
    /// Import an X509Certificate
    pub fn import_cert(
        &self,
        id: u16,
        label: &str,
        domains: &[ObjectDomain],
        capabilities: &[ObjectCapability],
        cert: &[u8],
    ) -> Result<u16, Error> {
        let mut real_id = id;

        let c_str = ::std::ffi::CString::new(label).unwrap();

        let res = unsafe {
            lyh::yh_util_import_opaque(
                self.ptr,
                &mut real_id,
                c_str.as_ptr(),
                ObjectDomain::primitive_from_slice(domains),
                &ObjectCapability::primitive_from_slice(&capabilities),
                yh_algorithm::YH_ALGO_OPAQUE_X509_CERTIFICATE,
                cert.as_ptr(),
                cert.len(),
            )
        };
        error::result_from_libyh(res)?;

        Ok(real_id)
    }

    /// Factory reset the device
    pub fn reset(&self) -> Result<(), Error> {
        let res = unsafe { lyh::yh_util_reset_device(self.ptr) };

        match error::result_from_libyh(res) {
            Ok(_) | Err(Error::LibYubiHsm(lyh::error::Error::NetworkError)) => Ok(()),
            Err(e) => Err(e),
        }
    }

    /// Export an object under wrap
    pub fn export_wrapped(
        &self,
        wrapping_key_id: u16,
        target_type: ObjectType,
        target_id: u16,
    ) -> Result<Vec<u8>, Error> {
        let mut out = vec![0; lyh::YH_MSG_BUF_SIZE as usize].into_boxed_slice();
        let mut out_len = out.len();

        let res = unsafe {
            lyh::yh_util_export_wrapped(
                self.ptr,
                wrapping_key_id,
                target_type.into(),
                target_id,
                out.as_mut_ptr(),
                &mut out_len,
            )
        };
        error::result_from_libyh(res)?;

        let mut out_vec = out.into_vec();
        out_vec.truncate(out_len);

        Ok(out_vec)
    }

    /// Export an object under wrap from the device with the option to include the ED25519 seed
    pub fn export_wrapped_ex(
        &self,
        wrapping_key_id: u16,
        target_type: ObjectType,
        target_id: u16,
        format: u8,
    ) -> Result<Vec<u8>, Error> {
        let mut out = vec![0; lyh::YH_MSG_BUF_SIZE as usize].into_boxed_slice();
        let mut out_len = out.len();

        let res = unsafe {
            lyh::yh_util_export_wrapped_ex(
                self.ptr,
                wrapping_key_id,
                target_type.into(),
                target_id,
                if format > 0 { 1 } else { 0 },
                out.as_mut_ptr(),
                &mut out_len,
            )
        };
        error::result_from_libyh(res)?;

        let mut out_vec = out.into_vec();
        out_vec.truncate(out_len);

        Ok(out_vec)
    }

    /// Import a wrapped object
    pub fn import_wrapped(
        &self,
        wrapping_key_id: u16,
        bytes: &[u8],
    ) -> Result<ObjectHandle, Error> {
        let mut object_type: lyh::yh_object_type = lyh::yh_object_type::default();
        let mut id: u16 = 0;

        let res = unsafe {
            lyh::yh_util_import_wrapped(
                self.ptr,
                wrapping_key_id,
                bytes.as_ptr(),
                bytes.len(),
                &mut object_type,
                &mut id,
            )
        };
        error::result_from_libyh(res)?;

        Ok(ObjectHandle {
            object_id: id,
            object_type: (&object_type).into(),
        })
    }

    /// Export a (a)symmetric key material using an RSA wrap key
    pub fn export_rsa_wrapped_key(
        &self,
        wrapping_key_id: u16,
        target_type: ObjectType,
        target_id: u16,
        aes_algorithm: ObjectAlgorithm,
        oaep_algorithm: ObjectAlgorithm,
        mfg1_algorithm: ObjectAlgorithm,
        oaep_label: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let mut out = vec![0; lyh::YH_MSG_BUF_SIZE as usize].into_boxed_slice();
        let mut out_len = out.len();

        let res = unsafe {
            lyh::yh_util_get_rsa_wrapped_key(
                self.ptr,
                wrapping_key_id,
                target_type.into(),
                target_id,
                aes_algorithm.into(),
                oaep_algorithm.into(),
                mfg1_algorithm.into(),
                oaep_label.as_ptr(),
                oaep_label.len(),
                out.as_mut_ptr(),
                &mut out_len,
            )
        };
        error::result_from_libyh(res)?;

        let mut out_vec = out.into_vec();
        out_vec.truncate(out_len);

        Ok(out_vec)
    }

    /// Import an (a)symmetric key using an RSA wrap key.
    pub fn import_rsa_wrapped_key(
        &self,
        wrapping_key_id: u16,
        object_type: ObjectType,
        object_id: u16,
        object_algorithm: ObjectAlgorithm,
        object_label: &str,
        object_domains: &[ObjectDomain],
        object_capabilities: &[ObjectCapability],
        oaep_algorithm: ObjectAlgorithm,
        mgf1_algorithm: ObjectAlgorithm,
        oaep_label: &[u8],
        bytes: &[u8],
    ) -> Result<ObjectHandle, Error> {
        let c_str = ::std::ffi::CString::new(object_label).unwrap();
        let mut id: u16 = object_id;

        let res = unsafe {
            lyh::yh_util_put_rsa_wrapped_key(
                self.ptr,
                wrapping_key_id,
                object_type.into(),
                &mut id,
                object_algorithm.into(),
                c_str.as_ptr(),
                ObjectDomain::primitive_from_slice(object_domains),
                &ObjectCapability::primitive_from_slice(object_capabilities),
                oaep_algorithm.into(),
                mgf1_algorithm.into(),
                oaep_label.as_ptr(),
                oaep_label.len(),
                bytes.as_ptr(),
                bytes.len(),
            )
        };
        error::result_from_libyh(res)?;

        Ok(ObjectHandle {
            object_id: id,
            object_type,
        })
    }

    /// Export an object using an RSA wrap key
    pub fn export_rsa_wrapped_object(
        &self,
        wrapping_key_id: u16,
        target_type: ObjectType,
        target_id: u16,
        aes_algorithm: ObjectAlgorithm,
        oaep_algorithm: ObjectAlgorithm,
        mfg1_algorithm: ObjectAlgorithm,
        oaep_label: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let mut out = vec![0; lyh::YH_MSG_BUF_SIZE as usize].into_boxed_slice();
        let mut out_len = out.len();

        let res = unsafe {
            lyh::yh_util_export_rsa_wrapped(
                self.ptr,
                wrapping_key_id,
                target_type.into(),
                target_id,
                aes_algorithm.into(),
                oaep_algorithm.into(),
                mfg1_algorithm.into(),
                oaep_label.as_ptr(),
                oaep_label.len(),
                out.as_mut_ptr(),
                &mut out_len,
            )
        };
        error::result_from_libyh(res)?;

        let mut out_vec = out.into_vec();
        out_vec.truncate(out_len);

        Ok(out_vec)
    }

    /// Import an object using an RSA wrap key
    pub fn import_rsa_wrapped_object(
        &self,
        wrapping_key_id: u16,
        oaep_algorithm: ObjectAlgorithm,
        mgf1_algorithm: ObjectAlgorithm,
        oaep_label: &[u8],
        bytes: &[u8],
    ) -> Result<ObjectHandle, Error> {
        let mut object_type: lyh::yh_object_type = lyh::yh_object_type::default();
        let mut id: u16 = 0;

        let res = unsafe {
            lyh::yh_util_import_rsa_wrapped(
                self.ptr,
                wrapping_key_id,
                oaep_algorithm.into(),
                mgf1_algorithm.into(),
                oaep_label.as_ptr(),
                oaep_label.len(),
                bytes.as_ptr(),
                bytes.len(),
                &mut object_type,
                &mut id,
            )
        };
        error::result_from_libyh(res)?;

        Ok(ObjectHandle {
            object_id: id,
            object_type: (&object_type).into(),
        })
    }

    /// Import an opaque object
    pub fn import_opaque(
        &self,
        object_id: u16,
        label: &str,
        domains: &[ObjectDomain],
        capabilities: &[ObjectCapability],
        algorithm: ObjectAlgorithm,
        bytes: &[u8],
    ) -> Result<OpaqueObject, Error> {
        let c_str = ::std::ffi::CString::new(label).unwrap();

        let mut id: u16 = object_id;

        let res = unsafe {
            lyh::yh_util_import_opaque(
                self.ptr,
                &mut id,
                c_str.as_ptr(),
                ObjectDomain::primitive_from_slice(domains),
                &ObjectCapability::primitive_from_slice(capabilities),
                algorithm.into(),
                bytes.as_ptr(),
                bytes.len(),
            )
        };
        error::result_from_libyh(res)?;

        Ok(OpaqueObject::new(
            id,
            label.to_string(),
            algorithm,
            capabilities.to_vec(),
            domains.to_vec(),
        ))
    }

    /// Generate a new asymmetric key
    pub fn generate_asymmetric_key(
        &self,
        label: &str,
        capabilities: &[ObjectCapability],
        domains: &[ObjectDomain],
        key_algorithm: ObjectAlgorithm,
    ) -> Result<AsymmetricKey, Error> {
        let key_id: u16 = 0;
        self.generate_asymmetric_key_with_keyid(key_id, label, capabilities, domains, key_algorithm)
    }

    /// Generate a new asymmetric key with set ID
    pub fn generate_asymmetric_key_with_keyid(
        &self,
        mut key_id: u16,
        label: &str,
        capabilities: &[ObjectCapability],
        domains: &[ObjectDomain],
        key_algorithm: ObjectAlgorithm,
    ) -> Result<AsymmetricKey, Error> {
        let c_str = ::std::ffi::CString::new(label).unwrap();

        if unsafe { lyh::yh_is_rsa(key_algorithm.into()) } {
            let res = unsafe {
                lyh::yh_util_generate_rsa_key(
                    self.ptr,
                    &mut key_id,
                    c_str.as_ptr(),
                    ObjectDomain::primitive_from_slice(domains),
                    &ObjectCapability::primitive_from_slice(capabilities),
                    key_algorithm.into(),
                )
            };
            error::result_from_libyh(res)?;
        } else if unsafe { lyh::yh_is_ec(key_algorithm.into()) } {
            let res = unsafe {
                lyh::yh_util_generate_ec_key(
                    self.ptr,
                    &mut key_id,
                    c_str.as_ptr(),
                    ObjectDomain::primitive_from_slice(domains),
                    &ObjectCapability::primitive_from_slice(capabilities),
                    key_algorithm.into(),
                )
            };
            error::result_from_libyh(res)?;
        } else if unsafe { lyh::yh_is_ed(key_algorithm.into()) } {
            let res = unsafe {
                lyh::yh_util_generate_ed_key(
                    self.ptr,
                    &mut key_id,
                    c_str.as_ptr(),
                    ObjectDomain::primitive_from_slice(domains),
                    &ObjectCapability::primitive_from_slice(capabilities),
                    key_algorithm.into(),
                )
            };
            error::result_from_libyh(res)?;
        } else {
            return Err(Error::InvalidParameter("Key algorithm".to_string()));
        }

        Ok(AsymmetricKey::new(
            key_id,
            label.to_string(),
            key_algorithm,
            capabilities.to_vec(),
            domains.to_vec(),
        ))
    }

    /// Generate a new AES key
    pub fn generate_aes_key (
        &self,
        key_id: u16,
        label: &str,
        capabilities: &[ObjectCapability],
        domains: &[ObjectDomain],
        key_algorithm: ObjectAlgorithm,
    ) -> Result<u16, Error> {


        let mut real_id = key_id;

        let c_str = ::std::ffi::CString::new(label).unwrap();

        let res = unsafe {
            lyh::yh_util_generate_aes_key(
                self.ptr,
                &mut real_id,
                c_str.as_ptr(),
                ObjectDomain::primitive_from_slice(domains),
                &ObjectCapability::primitive_from_slice(capabilities),
                key_algorithm.into())
        };
        error::result_from_libyh(res)?;

        Ok(real_id)
    }

    /// Get the public key
    pub fn get_pubkey(
        &self,
        key_id: u16,
        key_type: ObjectType,
    ) -> Result<(Vec<u8>, ObjectAlgorithm), Error> {
        let mut out = vec![0; lyh::YH_MSG_BUF_SIZE as usize].into_boxed_slice();
        let mut out_len = out.len();
        let mut key_algorithm = yh_algorithm::YH_ALGO_ANY;

        let res = unsafe {
            lyh::yh_util_get_public_key_ex(
                self.ptr,
                key_type.into(),
                key_id,
                out.as_mut_ptr(),
                &mut out_len,
                &mut key_algorithm,
            )
        };
        error::result_from_libyh(res)?;

        let mut out_vec = out.into_vec();
        out_vec.truncate(out_len);

        Ok((out_vec, key_algorithm.into()))
    }

    /// Get the opaque object value
    pub fn get_opaque(
        &self,
        key_id: u16,
    ) -> Result<Vec<u8>, Error> {
        let mut out = vec![0; lyh::YH_MSG_BUF_SIZE as usize].into_boxed_slice();
        let mut out_len = out.len();

        let res = unsafe {
            lyh::yh_util_get_opaque(
                self.ptr,
                key_id,
                out.as_mut_ptr(),
                &mut out_len,
            )
        };
        error::result_from_libyh(res)?;

        let mut out_vec = out.into_vec();
        out_vec.truncate(out_len);

        Ok(out_vec)
    }

    /// Sign data using RSA-PKCS#1v1.5
    pub fn sign_pkcs1v1_5(
        &self,
        key_id: u16,
        hashed: bool,
        data: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let mut out = vec![0; lyh::YH_MSG_BUF_SIZE as usize].into_boxed_slice();
        let mut out_len = out.len();

        let res = unsafe {
            lyh::yh_util_sign_pkcs1v1_5(
                self.ptr,
                key_id,
                hashed,
                data.as_ptr(),
                data.len(),
                out.as_mut_ptr(),
                &mut out_len,
            )
        };
        error::result_from_libyh(res)?;

        let mut out_vec = out.into_vec();
        out_vec.truncate(out_len);

        Ok(out_vec)
    }

    /// Sign data using RSA-PSS
    pub fn sign_pss(
        &self,
        key_id: u16,
        salt_len: usize,
        mgf1algo: ObjectAlgorithm,
        data: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let mut out = vec![0; lyh::YH_MSG_BUF_SIZE as usize].into_boxed_slice();
        let mut out_len = out.len();

        let res = unsafe {
            lyh::yh_util_sign_pss(
                self.ptr,
                key_id,
                data.as_ptr(),
                data.len(),
                out.as_mut_ptr(),
                &mut out_len,
                salt_len,
                mgf1algo.into(),
            )
        };
        error::result_from_libyh(res)?;

        let mut out_vec = out.into_vec();
        out_vec.truncate(out_len);

        Ok(out_vec)
    }

    /// Sign data using ECDSA
    pub fn sign_ecdsa(
        &self,
        key_id: u16,
        data: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let mut out = vec![0; lyh::YH_MSG_BUF_SIZE as usize].into_boxed_slice();
        let mut out_len = out.len();

        let res = unsafe {
            lyh::yh_util_sign_ecdsa(
                self.ptr,
                key_id,
                data.as_ptr(),
                data.len(),
                out.as_mut_ptr(),
                &mut out_len,
            )
        };
        error::result_from_libyh(res)?;

        let mut out_vec = out.into_vec();
        out_vec.truncate(out_len);

        Ok(out_vec)
    }

    /// Sign data using EDDSA
    pub fn sign_eddsa(
        &self,
        key_id: u16,
        data: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let mut out = vec![0; lyh::YH_MSG_BUF_SIZE as usize].into_boxed_slice();
        let mut out_len = out.len();

        let res = unsafe {
            lyh::yh_util_sign_eddsa(
                self.ptr,
                key_id,
                data.as_ptr(),
                data.len(),
                out.as_mut_ptr(),
                &mut out_len,
            )
        };
        error::result_from_libyh(res)?;

        let mut out_vec = out.into_vec();
        out_vec.truncate(out_len);

        Ok(out_vec)
    }

    /// Sign attestation certificate
    pub fn sign_attestation_certificate(
        &self,
        keyid_attested: u16,
        keyid_attesting: u16,
    ) -> Result<Vec<u8>, Error> {
        let mut out = vec![0; lyh::YH_MSG_BUF_SIZE as usize].into_boxed_slice();
        let mut out_len = out.len();

        let res = unsafe {
            lyh::yh_util_sign_attestation_certificate(
                self.ptr,
                keyid_attested,
                keyid_attesting,
                out.as_mut_ptr(),
                &mut out_len,
            )
        };
        error::result_from_libyh(res)?;

        let mut out_vec = out.into_vec();
        out_vec.truncate(out_len);

        Ok(out_vec)
    }

    /// Encrypt data using AES ECB
    pub fn encrypt_aes_ecb(
        &self,
        key_id: u16,
        data: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let mut out = vec![0; lyh::YH_MSG_BUF_SIZE as usize].into_boxed_slice();
        let mut out_len = out.len();

        let res = unsafe {
            lyh::yh_util_encrypt_aes_ecb(
                self.ptr,
                key_id,
                data.as_ptr(),
                data.len(),
                out.as_mut_ptr(),
                &mut out_len,
            )
        };
        error::result_from_libyh(res)?;

        let mut out_vec = out.into_vec();
        out_vec.truncate(out_len);

        Ok(out_vec)
    }

    /// Encrypt data using AES CBC
    pub fn encrypt_aes_cbc(
        &self,
        key_id: u16,
        iv: &[u8],
        data: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let mut out = vec![0; lyh::YH_MSG_BUF_SIZE as usize].into_boxed_slice();
        let mut out_len = out.len();

        let res = unsafe {
            lyh::yh_util_encrypt_aes_cbc(
                self.ptr,
                key_id,
                iv.as_ptr(),
                data.as_ptr(),
                data.len(),
                out.as_mut_ptr(),
                &mut out_len,
            )
        };
        error::result_from_libyh(res)?;

        let mut out_vec = out.into_vec();
        out_vec.truncate(out_len);

        Ok(out_vec)
    }

    /// Decrypt data using AES ECB
    pub fn decrypt_aes_ecb(
        &self,
        key_id: u16,
        data: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let mut out = vec![0; lyh::YH_MSG_BUF_SIZE as usize].into_boxed_slice();
        let mut out_len = out.len();

        let res = unsafe {
            lyh::yh_util_decrypt_aes_ecb(
                self.ptr,
                key_id,
                data.as_ptr(),
                data.len(),
                out.as_mut_ptr(),
                &mut out_len,
            )
        };
        error::result_from_libyh(res)?;

        let mut out_vec = out.into_vec();
        out_vec.truncate(out_len);

        Ok(out_vec)
    }

    /// Decrypt data using AES CBC
    pub fn decrypt_aes_cbc(
        &self,
        key_id: u16,
        iv: &[u8],
        data: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let mut out = vec![0; lyh::YH_MSG_BUF_SIZE as usize].into_boxed_slice();
        let mut out_len = out.len();

        let res = unsafe {
            lyh::yh_util_decrypt_aes_cbc(
                self.ptr,
                key_id,
                iv.as_ptr(),
                data.as_ptr(),
                data.len(),
                out.as_mut_ptr(),
                &mut out_len,
            )
        };
        error::result_from_libyh(res)?;

        let mut out_vec = out.into_vec();
        out_vec.truncate(out_len);

        Ok(out_vec)
    }

    /// Decrypt data using RSA-PKCS#1v1.5
    pub fn decrypt_pkcs1v1_5(
        &self,
        key_id: u16,
        data: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let mut out = vec![0; lyh::YH_MSG_BUF_SIZE as usize].into_boxed_slice();
        let mut out_len = out.len();

        let res = unsafe {
            lyh::yh_util_decrypt_pkcs1v1_5(
                self.ptr,
                key_id,
                data.as_ptr(),
                data.len(),
                out.as_mut_ptr(),
                &mut out_len,
            )
        };
        error::result_from_libyh(res)?;

        let mut out_vec = out.into_vec();
        out_vec.truncate(out_len);

        Ok(out_vec)
    }

    /// Decrypt data using RSA-OAEP
    pub fn decrypt_oaep(
        &self,
        key_id: u16,
        data: &[u8],
        label: &[u8],
        mgf1algo: ObjectAlgorithm,
    ) -> Result<Vec<u8>, Error> {
        let mut out = vec![0; lyh::YH_MSG_BUF_SIZE as usize].into_boxed_slice();
        let mut out_len = out.len();

        let res = unsafe {
            lyh::yh_util_decrypt_oaep(
                self.ptr,
                key_id,
                data.as_ptr(),
                data.len(),
                out.as_mut_ptr(),
                &mut out_len,
                label.as_ptr(),
                label.len(),
                mgf1algo.into(),
            )
        };
        error::result_from_libyh(res)?;

        let mut out_vec = out.into_vec();
        out_vec.truncate(out_len);

        Ok(out_vec)
    }

    /// Derive ECDH
    pub fn derive_ecdh(
        &self,
        key_id: u16,
        data: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let mut out = vec![0; lyh::YH_MSG_BUF_SIZE as usize].into_boxed_slice();
        let mut out_len = out.len();

        let res = unsafe {
            lyh::yh_util_derive_ecdh(
                self.ptr,
                key_id,
                data.as_ptr(),
                data.len(),
                out.as_mut_ptr(),
                &mut out_len,
            )
        };
        error::result_from_libyh(res)?;

        let mut out_vec = out.into_vec();
        out_vec.truncate(out_len);

        Ok(out_vec)
    }

}

impl Drop for Session {
    fn drop(&mut self) {
        trace!("Dropping session");
        self.close().unwrap_or(()); // NOTE(adma): ignore return value ...
    }
}

#[cfg(test)]
mod test {

    use super::object::{ObjectAlgorithm, ObjectCapability, ObjectDomain, ObjectType};
    use super::YubiHsm;

    use std::env;
    use std::thread;
    use std::time::Duration;

    const ENV_VAR: &str = "YUBIHSM_CONNECTOR_URL";
    const CONNECTOR_URL: &str = "http://127.0.0.1:12345";
    const PASSWORD: &str = "password";
    const AESKEY: [u8; 32] = [
        0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e,
        0x4f, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d,
        0x4e, 0x4f,
    ];
    const RSA2048_PRIVKEY: [u8; 256] = [
        0xdc, 0x5d, 0xc3, 0x1f, 0xb9, 0x9f, 0x1d, 0x71, 0x55, 0x44, 0xea, 0xd4, 0xf5, 0xd3, 0xeb, 0x6e, 0xda,
        0xb7, 0x45, 0x33, 0xad, 0x1f, 0x05, 0xd8, 0x35, 0x37, 0xef, 0x17, 0xd5, 0x6d, 0x6f, 0x47, 0xcb, 0x96,
        0x91, 0x5f, 0xd6, 0xcd, 0xbb, 0x4d, 0xda, 0x8d, 0x9e, 0x85, 0x3c, 0xd5, 0xbe, 0xdc, 0x73, 0x4b, 0x8e,
        0x33, 0x8d, 0xb4, 0xab, 0x9f, 0xcb, 0x16, 0x92, 0x06, 0xc8, 0xb3, 0xf2, 0x4f, 0x59, 0x6f, 0xf5, 0xc8,
        0x8d, 0x0a, 0x8d, 0x23, 0x98, 0xfe, 0x7f, 0xc2, 0x81, 0x62, 0xbd, 0x7d, 0x12, 0x2a, 0x29, 0x11, 0x38,
        0xd4, 0x0f, 0x7b, 0xb8, 0x45, 0xf2, 0x51, 0x4d, 0x76, 0xa7, 0xc7, 0x5a, 0xae, 0xe0, 0xfe, 0x83, 0x36,
        0x5e, 0x42, 0xc1, 0x23, 0xc4, 0xf4, 0x05, 0x94, 0x9b, 0x2d, 0xdc, 0x46, 0x7d, 0x2d, 0xa8, 0x62, 0xd0,
        0x51, 0x85, 0x88, 0xa3, 0xbf, 0x10, 0x24, 0x36, 0x4b, 0xb5, 0x8e, 0x74, 0xcc, 0x7e, 0x4c, 0xdc, 0x39,
        0x0c, 0x46, 0xdf, 0xac, 0xaf, 0x8b, 0x76, 0xe1, 0xde, 0x6c, 0xf4, 0xd3, 0x75, 0x25, 0xd5, 0xa6, 0xe7,
        0xe8, 0x89, 0x06, 0x92, 0x1d, 0xea, 0xd5, 0x92, 0x62, 0xca, 0x3e, 0x47, 0x33, 0x6d, 0x85, 0x3a, 0xb0,
        0xc2, 0x47, 0xbe, 0x58, 0xac, 0xda, 0xd8, 0xfc, 0xed, 0xa9, 0xed, 0x3b, 0xfd, 0xa7, 0x05, 0xea, 0x20,
        0x2f, 0xcb, 0x54, 0x5b, 0x4e, 0xd3, 0x05, 0x94, 0x35, 0x93, 0x7c, 0xf9, 0x83, 0x8a, 0x54, 0x19, 0x27,
        0xf0, 0x87, 0x54, 0x2e, 0x15, 0xbe, 0xe0, 0x19, 0xac, 0xf3, 0xe6, 0xd7, 0xc5, 0x0a, 0xfa, 0xee, 0xc2,
        0x16, 0xf5, 0x47, 0x1f, 0xed, 0xde, 0xcd, 0xe2, 0xf4, 0x62, 0x99, 0xa0, 0x73, 0x77, 0x36, 0xf5, 0x5d,
        0xe1, 0x01, 0xcc, 0x64, 0x8f, 0xc5, 0xd6, 0x10, 0xc0, 0x9f, 0x9c, 0x88, 0x89, 0xc4, 0xd4, 0x20, 0xb9,
        0xcb,
    ];
    const ECP256_PUBKEY: [u8; 65] = [
        0x04, 0x9d, 0x60, 0xd3, 0x2a, 0x2b, 0x90, 0xbe, 0x57, 0xdf, 0x56, 0x19, 0xe6, 0xba, 0x28, 0x3e, 0x73,
        0x29, 0xa1, 0xab, 0x1c, 0xe2, 0xf2, 0xed, 0x17, 0xc1, 0x44, 0x46, 0xf1, 0xc2, 0xe6, 0x0b, 0x39, 0x2e,
        0x96, 0x8c, 0x10, 0xea, 0xb9, 0x41, 0xbc, 0x7c, 0x38, 0x27, 0x90, 0x62, 0x6b, 0xf2, 0x6d, 0x28, 0x31,
        0x56, 0x25, 0xf1, 0xfb, 0x30, 0xef, 0x52, 0x31, 0x88, 0x61, 0x18, 0x40, 0xa6, 0xcf,
    ];

    const CERT: &str = "MIIC+jCCAeKgAwIBAgIGAWbt9mc3MA0GCSqGSIb3DQEBBQUAMD4xPDA6BgNVBAMM\
                        M0R1bW15IGNlcnRpZmljYXRlIGNyZWF0ZWQgYnkgYSBDRVNlQ29yZSBhcHBsaWNh\
                        dGlvbjAeFw0xODExMDcxMTM3MjBaFw00ODEwMzExMTM3MjBaMD4xPDA6BgNVBAMM\
                        M0R1bW15IGNlcnRpZmljYXRlIGNyZWF0ZWQgYnkgYSBDRVNlQ29yZSBhcHBsaWNh\
                        dGlvbjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMTxMBMtwHJCzNHi\
                        d0GszdXM49jQdEZOuaLK1hyIjpuhRImJYbdvmF5cYa2suR2yw6DygWGFLafqVEuL\
                        dXvnib3r0jBX2w7ZSrPWuJ592QUgNllHCvNG/dNgwLfCVOr9fs1ifJaa09gtQ2EG\
                        3iV7j3AMxb7rc8x4d3nsJad+UPCyqB3HXGDRLbOT38zI72zhXm4BqiCMt6+2rcPE\
                        +nneNiTMVjrGwzbZkCak6xnwq8/tLTtvD0+yPLQdKb4NaQfXPmYNTrzTmvYmVD8P\
                        0bIUo/CoXIh0BkJXwHzX7J9nDW9Qd7BR2Q2vbUaou/STlWQooqoTnVnEK8zvAXkl\
                        ubqSUPMCAwEAATANBgkqhkiG9w0BAQUFAAOCAQEAGXwmRWewOcbPV/Jx6wkNDOvE\
                        oo4bieBqeRyU/XfDYbuevfNSBnbQktThl1pR21hrJ2l9qV3D1AJDKck/x74hyjl9\
                        mh37eqbPAdfx3yY7vN03RYWr12fW0kLJA9bsm0jYdJN4BHV/zCXlSqPS0The+Zfg\
                        eVCiQCnEZx/z1jfxwIIg6N8Y7luPWIi36XsGqI75IhkJFw8Jup5HIB4p4P0txinm\
                        hxzAwAjKm7yCiBA5oxX1fvSPdlwMb9mcO7qC5wKrsMyuzIpllBbGaCRFCcAtu9Zu\
                        MvBJNrMLPK3bz4QvT5dYW/cXcjJbnIDqQKqSVV6feYk3iyS07HkaPGP3rxGpdQ==";

    macro_rules! create_hsm {
        () => {
            if let Ok(url) = env::var(ENV_VAR) {
                YubiHsm::new(&url).expect(&format!("Unable to create HSM with connector {}", url))
            } else {
                YubiHsm::new(CONNECTOR_URL).expect(&format!(
                    "Unable to create HSM with connector {}",
                    CONNECTOR_URL
                ))
            }
        };
    }

    #[test]
    fn device_info() {
        super::init().unwrap();
        let hsm = create_hsm!();

        println!("{:?}", hsm.get_device_info().unwrap());

        super::exit().unwrap();
    }

    #[test]
    fn device_pubkey() {
        super::init().unwrap();
        let hsm = create_hsm!();

        println!("{:?}", hsm.get_device_pubkey().unwrap());

        super::exit().unwrap();
    }

    #[test]
    #[ignore]
    fn simple_session_expiration() {
        super::init().unwrap();
        let hsm = create_hsm!();

        let session = hsm.establish_session(1, PASSWORD, false).unwrap();

        thread::sleep(Duration::from_millis(40000));

        assert!(session.list_objects().is_err());

        session.close().unwrap();

        super::exit().unwrap();
    }

    #[test]
    #[ignore]
    fn retried_session_expiration() {
        super::init().unwrap();
        let hsm = create_hsm!();

        let session = hsm.establish_session(1, PASSWORD, true).unwrap();

        thread::sleep(Duration::from_millis(40000));

        println!("{:#?} ", session.list_objects().unwrap());

        session.close().unwrap();

        super::exit().unwrap();
    }

    #[test]
    fn list_objects() {
        super::init().unwrap();
        let hsm = create_hsm!();

        let session = hsm.establish_session(1, PASSWORD, true).unwrap();

        println!("{:#?} ", session.list_objects().unwrap());

        session.close().unwrap();

        super::exit().unwrap();
    }

    #[test]
    fn get_object_info() {
        super::init().unwrap();
        let hsm = create_hsm!();
        let mut res;

        let session = hsm.establish_session(1, PASSWORD, true).unwrap();

        res = session.get_object_info(1, ObjectType::AuthenticationKey);

        assert!(res.is_ok());

        println!("{:#?} ", res.unwrap());

        res = session.get_object_info(99, ObjectType::Template);

        match res {
            Err(super::Error::LibYubiHsm(lyh::Error::DeviceObjectNotFound)) => (),
            Err(e) => panic!(
                "Wrong error. Expected {}, found {}",
                super::Error::LibYubiHsm(lyh::Error::DeviceObjectNotFound),
                e
            ),
            _ => unreachable!(),
        }

        session.close().unwrap();

        super::exit().unwrap();
    }

    #[test]
    fn delete_object() {
        super::init().unwrap();
        let hsm = create_hsm!();

        let session = hsm.establish_session(1, PASSWORD, true).unwrap();

        let id = session
            .import_authentication_key(
                0,
                "Test authkey",
                &ObjectDomain::vec_from_str("all").unwrap(),
                &vec![],
                &vec![],
                "PASSWORD".as_bytes(),
            )
            .unwrap();

        session
            .delete_object(id, ObjectType::AuthenticationKey)
            .unwrap();

        session.close().unwrap();

        super::exit().unwrap();
    }

    #[test]
    fn delete_object_twice() {
        super::init().unwrap();
        let hsm = create_hsm!();

        let session = hsm.establish_session(1, PASSWORD, true).unwrap();

        let id = session
            .import_authentication_key(
                0,
                "Test authkey",
                &ObjectDomain::vec_from_str("all").unwrap(),
                &vec![],
                &vec![],
                "PASSWORD".as_bytes(),
            )
            .unwrap();

        assert!(session
            .delete_object(id, ObjectType::AuthenticationKey)
            .is_ok());

        assert!(session
            .delete_object(id, ObjectType::AuthenticationKey)
            .is_err());

        session.close().unwrap();

        super::exit().unwrap();
    }

    #[test]
    fn establish_seventeen_sessions() {
        super::init().unwrap();
        let hsm = create_hsm!();

        for i in 0..18 {
            println!("i is {}", i);
            hsm.establish_session(1, PASSWORD, true).unwrap();
        }

        super::exit().unwrap();
    }

    #[test]
    fn import_authkey() {
        super::init().unwrap();
        let hsm = create_hsm!();

        let session = hsm.establish_session(1, PASSWORD, true).unwrap();

        let id = session
            .import_authentication_key(
                0,
                "Test authkey",
                &ObjectDomain::vec_from_str("all").unwrap(),
                &vec![ObjectCapability::DeleteAuthenticationKey],
                &vec![],
                "PASSWORD".as_bytes(),
            )
            .unwrap();

        session.close().unwrap();

        let session = hsm.establish_session(id, "PASSWORD", true).unwrap();

        let info = session.get_object_info(id, ObjectType::AuthenticationKey);

        assert!(info.is_ok());

        println!("{:#?} ", info.unwrap());

        session
            .delete_object(id, ObjectType::AuthenticationKey)
            .unwrap();

        session.close().unwrap();

        super::exit().unwrap();
    }

    #[test]
    fn generate_wrap_key() {
        super::init().unwrap();
        let hsm = create_hsm!();

        let session = hsm.establish_session(1, PASSWORD, true).unwrap();

        let id = session
            .generate_wrap_key(
                0,
                "Test wrapkey",
                &ObjectDomain::vec_from_str("all").unwrap(),
                &[ObjectCapability::ImportWrapped],
                ObjectAlgorithm::Aes256CcmWrap,
                &[],
            )
            .unwrap();

        let info = session.get_object_info(id, ObjectType::WrapKey);

        assert!(info.is_ok());

        println!("{:#?} ", info.unwrap());

        session.delete_object(id, ObjectType::WrapKey).unwrap();

        session.close().unwrap();

        super::exit().unwrap();
    }

    #[test]
    fn generate_rsa_wrap_key() {
        super::init().unwrap();
        let hsm = create_hsm!();

        let session = hsm.establish_session(1, PASSWORD, true).unwrap();

        let id = session
            .generate_wrap_key(
                0,
                "Test wrapkey",
                &ObjectDomain::vec_from_str("all").unwrap(),
                &[ObjectCapability::ImportWrapped],
                ObjectAlgorithm::Rsa3072,
                &[],
            )
            .unwrap();

        let info = session.get_object_info(id, ObjectType::WrapKey);

        assert!(info.is_ok());

        println!("{:#?} ", info.unwrap());

        session.delete_object(id, ObjectType::WrapKey).unwrap();

        session.close().unwrap();

        super::exit().unwrap();
    }

    #[test]
    fn import_wrap_key() {
        super::init().unwrap();
        let hsm = create_hsm!();

        let session = hsm.establish_session(1, PASSWORD, true).unwrap();

        let id = session
            .import_wrap_key(
                0,
                "Test wrapkey",
                &ObjectDomain::vec_from_str("all").unwrap(),
                &[ObjectCapability::ImportWrapped],
                ObjectAlgorithm::Aes256CcmWrap,
                &[],
                &AESKEY,
            )
            .unwrap();

        let info = session.get_object_info(id, ObjectType::WrapKey);

        assert!(info.is_ok());

        println!("{:#?} ", info.unwrap());

        session.delete_object(id, ObjectType::WrapKey).unwrap();

        session.close().unwrap();

        super::exit().unwrap();
    }

    #[test]
    fn import_rsa_wrap_key() {
        super::init().unwrap();
        let hsm = create_hsm!();

        let session = hsm.establish_session(1, PASSWORD, true).unwrap();

        let id = session
            .import_wrap_key(
                0,
                "Test wrapkey",
                &ObjectDomain::vec_from_str("all").unwrap(),
                &[ObjectCapability::ImportWrapped],
                ObjectAlgorithm::Rsa2048,
                &[],
                &RSA2048_PRIVKEY,
            )
            .unwrap();

        let info = session.get_object_info(id, ObjectType::WrapKey);

        assert!(info.is_ok());

        println!("{:#?} ", info.unwrap());

        let (pubkey, algo) = session.get_pubkey(id, ObjectType::WrapKey).unwrap();

        let pub_id = session
            .import_public_wrap_key(
                id,
                "Test public wrapkey",
                &ObjectDomain::vec_from_str("all").unwrap(),
                &[ObjectCapability::ExportWrapped],
                algo,
                &[],
                &pubkey,
            )
            .unwrap();

        let info = session.get_object_info(pub_id, ObjectType::PublicWrapKey);

        assert!(info.is_ok());

        println!("{:#?} ", info.unwrap());


        session.delete_object(id, ObjectType::WrapKey).unwrap();
        session.delete_object(pub_id, ObjectType::PublicWrapKey).unwrap();

        session.close().unwrap();

        super::exit().unwrap();
    }

    #[test]
    fn export_wrapped() {
        super::init().unwrap();
        let hsm = create_hsm!();

        let session = hsm.establish_session(1, PASSWORD, true).unwrap();

        let id = session
            .import_wrap_key(
                0,
                "Test wrapkey",
                &ObjectDomain::vec_from_str("all").unwrap(),
                &[
                    ObjectCapability::ExportWrapped,
                    ObjectCapability::ExportableUnderWrap,
                ],
                ObjectAlgorithm::Aes256CcmWrap,
                &[
                    ObjectCapability::ExportWrapped,
                    ObjectCapability::ExportableUnderWrap,
                ],
                &AESKEY,
            )
            .unwrap();

        let wrap = session.export_wrapped(id, ObjectType::WrapKey, id);

        assert!(wrap.is_ok());

        println!("{:?} ", wrap.unwrap());

        session.delete_object(id, ObjectType::WrapKey).unwrap();

        session.close().unwrap();

        super::exit().unwrap();
    }

    #[test]
    fn import_wrapped() {
        super::init().unwrap();
        let hsm = create_hsm!();

        let session = hsm.establish_session(1, PASSWORD, true).unwrap();

        let wrap_id = session
            .import_wrap_key(
                0,
                "Test wrapkey",
                &ObjectDomain::vec_from_str("all").unwrap(),
                &[
                    ObjectCapability::ExportWrapped,
                    ObjectCapability::ImportWrapped,
                ],
                ObjectAlgorithm::Aes256CcmWrap,
                &[
                    ObjectCapability::ExportWrapped,
                    ObjectCapability::ExportableUnderWrap,
                    ObjectCapability::DeleteAuthenticationKey,
                    ObjectCapability::DeleteWrapKey,
                ],
                &AESKEY,
            )
            .unwrap();

        let auth_id = session
            .import_authentication_key(
                0,
                "Test authkey",
                &ObjectDomain::vec_from_str("all").unwrap(),
                &vec![
                    ObjectCapability::DeleteAuthenticationKey,
                    ObjectCapability::DeleteWrapKey,
                    ObjectCapability::ExportableUnderWrap,
                ],
                &vec![],
                "PASSWORD".as_bytes(),
            )
            .unwrap();

        let wrap = session
            .export_wrapped(wrap_id, ObjectType::AuthenticationKey, auth_id)
            .unwrap();

        println!("{:?} ", wrap);

        session
            .delete_object(auth_id, ObjectType::AuthenticationKey)
            .unwrap();

        session.import_wrapped(wrap_id, &wrap).unwrap();

        session.close().unwrap();

        let session = hsm.establish_session(auth_id, "PASSWORD", true).unwrap();

        session
            .delete_object(auth_id, ObjectType::AuthenticationKey)
            .unwrap();

        session.delete_object(wrap_id, ObjectType::WrapKey).unwrap();

        session.close().unwrap();

        super::exit().unwrap();
    }

    #[test]
    fn import_rsa_wrapped_object() {
        super::init().unwrap();
        let hsm = create_hsm!();

        let session = hsm.establish_session(1, PASSWORD, true).unwrap();

        let auth_id = session
            .import_authentication_key(
                0,
                "Test authkey",
                &ObjectDomain::vec_from_str("all").unwrap(),
                &vec![
                    ObjectCapability::DeleteAuthenticationKey,
                    ObjectCapability::DeleteWrapKey,
                    ObjectCapability::DeletePublicWrapKey,
                    ObjectCapability::ExportableUnderWrap,
                ],
                &vec![],
                "PASSWORD".as_bytes(),
            )
            .unwrap();

        let wrap_id = session
            .import_wrap_key(
                0,
                "Test RSA wrap object",
                &ObjectDomain::vec_from_str("all").unwrap(),
                &[
                    ObjectCapability::ImportWrapped,
                ],
                ObjectAlgorithm::Rsa2048,
                &[
                    ObjectCapability::ExportWrapped,
                    ObjectCapability::ExportableUnderWrap,
                    ObjectCapability::DeleteAuthenticationKey,
                    ObjectCapability::DeletePublicWrapKey,
                    ObjectCapability::DeleteWrapKey,
                ],
                &RSA2048_PRIVKEY,
            ).unwrap();

        let (pubkey, algo) = session.get_pubkey(wrap_id, ObjectType::WrapKey).unwrap();

        let pub_wrap_id = session
            .import_public_wrap_key(
                wrap_id,
                "Test RSA wrap object",
                &ObjectDomain::vec_from_str("all").unwrap(),
                &[
                    ObjectCapability::ExportWrapped,
                ],
                algo,
                &[
                    ObjectCapability::ExportWrapped,
                    ObjectCapability::ExportableUnderWrap,
                    ObjectCapability::DeleteAuthenticationKey,
                    ObjectCapability::DeletePublicWrapKey,
                    ObjectCapability::DeleteWrapKey,
                ],
                &pubkey,
            ).unwrap();

        let oaep_label = session.get_random(32).unwrap();

        let wrapped = session.export_rsa_wrapped_object(
            pub_wrap_id,
            ObjectType::AuthenticationKey,
            auth_id,
            ObjectAlgorithm::Aes256,
            ObjectAlgorithm::RsaOaepSha256,
            ObjectAlgorithm::Mgf1Sha256,
            &oaep_label,
        ).unwrap();

        println!("{:?} ", wrapped);

        session
            .delete_object(auth_id, ObjectType::AuthenticationKey)
            .unwrap();

        session.import_rsa_wrapped_object(
            wrap_id,
            ObjectAlgorithm::RsaOaepSha256,
            ObjectAlgorithm::Mgf1Sha256,
            &oaep_label,
            &wrapped
        ).unwrap();

        session.close().unwrap();

        let session = hsm.establish_session(auth_id, "PASSWORD", true).unwrap();

        session
            .delete_object(auth_id, ObjectType::AuthenticationKey)
            .unwrap();

        session.delete_object(wrap_id, ObjectType::WrapKey).unwrap();
        session.delete_object(pub_wrap_id, ObjectType::PublicWrapKey).unwrap();

        session.close().unwrap();

        super::exit().unwrap();
    }

    #[test]
    fn import_rsa_wrapped_key() {
        super::init().unwrap();
        let hsm = create_hsm!();

        let session = hsm.establish_session(1, PASSWORD, true).unwrap();

        let sym_id = session
            .import_aes_key(
                0,
                "Test symkey",
                &ObjectDomain::vec_from_str("all").unwrap(),
                &vec![
                    ObjectCapability::EncryptEcb,
                    ObjectCapability::DecryptEcb,
                    ObjectCapability::ExportableUnderWrap,
                ],
                ObjectAlgorithm::Aes256,
                &AESKEY,
            )
            .unwrap();

        let data = session.get_random(16).unwrap();
        let encrypted = session.encrypt_aes_ecb(sym_id, &data).unwrap();

        let wrap_id = session
            .import_wrap_key(
                0,
                "Test RSA wrap key",
                &ObjectDomain::vec_from_str("all").unwrap(),
                &[
                    ObjectCapability::ImportWrapped,
                ],
                ObjectAlgorithm::Rsa2048,
                &[
                    ObjectCapability::ExportableUnderWrap,
                    ObjectCapability::EncryptEcb,
                    ObjectCapability::DecryptEcb,
                ],
                &RSA2048_PRIVKEY,
            ).unwrap();

        let (pubkey, algo) = session.get_pubkey(wrap_id, ObjectType::WrapKey).unwrap();

        let pub_wrap_id = session
            .import_public_wrap_key(
                wrap_id,
                "Test RSA wrap key",
                &ObjectDomain::vec_from_str("all").unwrap(),
                &[
                    ObjectCapability::ExportWrapped,
                ],
                algo,
                &[
                    ObjectCapability::ExportableUnderWrap,
                    ObjectCapability::EncryptEcb,
                    ObjectCapability::DecryptEcb,
                ],
                &pubkey,
            ).unwrap();

        // let oaep_label: &[u8] = &[];
        let oaep_label = session.get_random(32).unwrap();

        let wrapped = session.export_rsa_wrapped_key(
            pub_wrap_id,
            ObjectType::SymmetricKey,
            sym_id,
            ObjectAlgorithm::Aes256,
            ObjectAlgorithm::RsaOaepSha256,
            ObjectAlgorithm::Mgf1Sha256,
            &oaep_label,
        ).unwrap();

        println!("{:?} ", wrapped);

        session
            .delete_object(sym_id, ObjectType::SymmetricKey)
            .unwrap();

        let imported_handle = session.import_rsa_wrapped_key(
            wrap_id,
            ObjectType::SymmetricKey,
            0,
            ObjectAlgorithm::Aes256,
            "Test RSA wrapped key",
            &ObjectDomain::vec_from_str("all").unwrap(),
            &[ObjectCapability::EncryptEcb, ObjectCapability::DecryptEcb, ObjectCapability::ExportableUnderWrap],
            ObjectAlgorithm::RsaOaepSha256,
            ObjectAlgorithm::Mgf1Sha256,
            &oaep_label,
            &wrapped).unwrap();

        session.close().unwrap();

        let session = hsm.establish_session(1, PASSWORD, true).unwrap();

        let decrypted = session.decrypt_aes_ecb(imported_handle.object_id, &encrypted).unwrap();
        assert_eq!(data, decrypted);

        session.delete_object(imported_handle.object_id, imported_handle.object_type).unwrap();

        session.delete_object(wrap_id, ObjectType::WrapKey).unwrap();
        session.delete_object(pub_wrap_id, ObjectType::PublicWrapKey).unwrap();

        session.close().unwrap();

        super::exit().unwrap();
    }


    #[test]
    fn generate_symmetric_key() {
        super::init().unwrap();
        let hsm = create_hsm!();

        let session = hsm.establish_session(1, PASSWORD, true).unwrap();

        let capabilities = vec![
            ObjectCapability::EncryptCbc,
            ObjectCapability::DecryptCbc,
            ObjectCapability::ExportableUnderWrap,
        ];

        let key_id = session
            .generate_aes_key(
                0,
                "Test symmetric key generation",
                &capabilities,
                &ObjectDomain::vec_from_str("all").unwrap(),
                ObjectAlgorithm::Aes192,
            )
            .unwrap();

        session.close().unwrap();

        let session = hsm.establish_session(1, PASSWORD, true).unwrap();

        let info = session.get_object_info(key_id, ObjectType::SymmetricKey);

        assert!(info.is_ok());

        println!("{:#?} ", info.unwrap());

        session
            .delete_object(key_id, ObjectType::SymmetricKey)
            .unwrap();

        session.close().unwrap();

        super::exit().unwrap();
    }

    #[test]
    fn import_symmetric_key() {
        super::init().unwrap();
        let hsm = create_hsm!();

        let session = hsm.establish_session(1, PASSWORD, true).unwrap();

        let id = session
            .import_aes_key(
                0,
                "Test aeskey",
                &ObjectDomain::vec_from_str("all").unwrap(),
                &[ObjectCapability::EncryptEcb, ObjectCapability::DecryptEcb],
                ObjectAlgorithm::Aes256,
                &AESKEY,
            )
            .unwrap();

        let info = session.get_object_info(id, ObjectType::SymmetricKey);

        assert!(info.is_ok());

        println!("{:#?} ", info.unwrap());

        session.delete_object(id, ObjectType::SymmetricKey).unwrap();

        session.close().unwrap();

        super::exit().unwrap();
    }


    #[test]
    fn encrypt_ecb() {
        super::init().unwrap();
        let hsm = create_hsm!();

        let session = hsm.establish_session(1, PASSWORD, true).unwrap();

        let key_id = session
            .generate_aes_key(
                0,
                "aeskey",
                &[ObjectCapability::EncryptEcb, ObjectCapability::DecryptEcb],
                &ObjectDomain::vec_from_str("all").unwrap(),
                ObjectAlgorithm::Aes128,
            )
            .unwrap();

        let data = session.get_random(16).unwrap();

        let encrypted = session.encrypt_aes_ecb(key_id, &data).unwrap();
        assert_ne!(data, encrypted);
        let decrypted = session.decrypt_aes_ecb(key_id, &encrypted).unwrap();
        assert_eq!(data, decrypted);

        session.delete_object(key_id, ObjectType::SymmetricKey).unwrap();

        session.close().unwrap();

        super::exit().unwrap();
    }

    #[test]
    fn encrypt_cbc() {
        super::init().unwrap();
        let hsm = create_hsm!();

        let session = hsm.establish_session(1, PASSWORD, true).unwrap();

        let key_id = session
            .import_aes_key(
                0,
                "aeskey",
                &ObjectDomain::vec_from_str("all").unwrap(),
                &[ObjectCapability::EncryptCbc, ObjectCapability::DecryptCbc],
                ObjectAlgorithm::Aes256,
                &AESKEY,
            )
            .unwrap();

        let data = session.get_random(32).unwrap();
        let iv = session.get_random(16).unwrap();

        let encrypted = session.encrypt_aes_cbc(key_id, &iv, &data).unwrap();
        assert_ne!(data, encrypted);
        let decrypted = session.decrypt_aes_cbc(key_id, &iv, &encrypted).unwrap();
        assert_eq!(data, decrypted);

        session.delete_object(key_id, ObjectType::SymmetricKey).unwrap();

        session.close().unwrap();

        super::exit().unwrap();
    }

    #[test]
    fn import_opaque() {
        super::init().unwrap();
        let hsm = create_hsm!();

        let session = hsm.establish_session(1, PASSWORD, true).unwrap();

        let cert = base64::decode(CERT).unwrap();

        let opaque = session
            .import_opaque(
                0,
                "Test certificate",
                &ObjectDomain::vec_from_str("all").unwrap(),
                &vec![],
                ObjectAlgorithm::OpaqueX509Certificate,
                &cert,
            )
            .unwrap();

        session.close().unwrap();

        let session = hsm.establish_session(1, PASSWORD, true).unwrap();

        let info = session.get_object_info(opaque.get_id(), ObjectType::Opaque);

        assert!(info.is_ok());

        println!("{:#?} ", info.unwrap());

        session
            .delete_object(opaque.get_id(), ObjectType::Opaque)
            .unwrap();

        session.close().unwrap();

        super::exit().unwrap();
    }

    #[test]
    fn generate_asymmetric_key() {
        super::init().unwrap();
        let hsm = create_hsm!();

        let session = hsm.establish_session(1, PASSWORD, true).unwrap();

        let capabilities = vec![
            ObjectCapability::SignPkcs,
            ObjectCapability::SignPss,
            ObjectCapability::SignAttestationCertificate,
        ];

        let key = session
            .generate_asymmetric_key(
                "Test key generation",
                &capabilities,
                &ObjectDomain::vec_from_str("all").unwrap(),
                ObjectAlgorithm::Rsa2048,
            )
            .unwrap();

        session.close().unwrap();

        let session = hsm.establish_session(1, PASSWORD, true).unwrap();

        let info = session.get_object_info(key.get_key_id(), ObjectType::AsymmetricKey);

        assert!(info.is_ok());

        println!("{:#?} ", info.unwrap());

        session
            .delete_object(key.get_key_id(), ObjectType::AsymmetricKey)
            .unwrap();

        session.close().unwrap();

        super::exit().unwrap();
    }

    #[test]
    fn generate_asymmetric_key_with_keyid() {
        super::init().unwrap();
        let hsm = create_hsm!();

        let session = hsm.establish_session(1, PASSWORD, true).unwrap();

        let capabilities = vec![
            ObjectCapability::SignPkcs,
            ObjectCapability::SignPss,
            ObjectCapability::SignAttestationCertificate,
        ];

        let key = session
            .generate_asymmetric_key_with_keyid(
                0,
                "Test key generation",
                &capabilities,
                &ObjectDomain::vec_from_str("all").unwrap(),
                ObjectAlgorithm::Rsa2048,
            )
            .unwrap();

        session.close().unwrap();

        let session = hsm.establish_session(1, PASSWORD, true).unwrap();

        let info = session.get_object_info(key.get_key_id(), ObjectType::AsymmetricKey);

        assert!(info.is_ok());

        println!("{:#?} ", info.unwrap());

        session
            .delete_object(key.get_key_id(), ObjectType::AsymmetricKey)
            .unwrap();

        session.close().unwrap();

        super::exit().unwrap();
    }

    #[test]
    fn derive_ecdh() {
        super::init().unwrap();
        let hsm = create_hsm!();

        let session = hsm.establish_session(1, PASSWORD, true).unwrap();

        let key = session
            .generate_asymmetric_key(
                "Test ecdh",
                &[ObjectCapability::DeriveEcdh],
                &ObjectDomain::vec_from_str("all").unwrap(),
                ObjectAlgorithm::EcP256,
            )
            .unwrap();

        let ecdh = session.derive_ecdh(key.get_key_id(), &ECP256_PUBKEY).unwrap();
        println!("{:#?} ", ecdh);

        session.delete_object(key.get_key_id(), ObjectType::AsymmetricKey).unwrap();

        session.close().unwrap();

        super::exit().unwrap();
    }

    #[test]
    fn string_conversions() {
        let types = vec![
            (ObjectType::AsymmetricKey, "asymmetric-key"),
            (ObjectType::AuthenticationKey, "authentication-key"),
            (ObjectType::HmacKey, "hmac-key"),
            (ObjectType::Opaque, "opaque"),
            (ObjectType::OtpAeadKey, "otp-aead-key"),
            (ObjectType::Template, "template"),
            (ObjectType::WrapKey, "wrap-key"),
            (ObjectType::PublicWrapKey, "public-wrap-key"),
        ];

        for t in types {
            assert_eq!(&t.0.to_string(), t.1);
        }
    }

}

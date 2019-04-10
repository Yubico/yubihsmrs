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

use lyh::{yh_connector, yh_rc, yh_session};

mod error;
use error::Error;

pub mod object;

use object::{
    AsymmetricKey, ObjectAlgorithm, ObjectCapability, ObjectDescriptor, ObjectDomain, ObjectHandle,
    OpaqueObject,
};

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
    algorithms: Vec<lyh::yh_algorithm>,
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

        try!(error::result_from_libyh(unsafe {
            lyh::yh_init_connector(c_url.as_ptr(), &connector_ptr)
        }));

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

        try!(error::result_from_libyh(unsafe {
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
        })));

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
            [lyh::yh_algorithm::YH_ALGO_RSA_PKCS1_SHA1; lyh::YH_MAX_ALGORITHM_COUNT];
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

        try!(error::result_from_libyh(res));

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
        let capa = lyh::yh_capabilities {
            capabilities: [0u8; 8],
        };
        let descriptor = lyh::yh_object_descriptor::default();
        let mut objects = vec![descriptor; 512].into_boxed_slice();
        let mut n_objects = 512;

        let res = unsafe {
            lyh::yh_util_list_objects(
                self.ptr,
                0,
                lyh::yh_object_type::YH_ANY,
                0,
                &capa,
                lyh::yh_algorithm::YH_ALGO_ANY,
                std::ptr::null(),
                objects.as_mut_ptr(),
                &mut n_objects,
            )
        };

        try!(error::result_from_libyh(res));

        Ok(objects[0..n_objects]
            .iter()
            .map(ObjectHandle::from)
            .collect())
    }

    /// Get information about a specific object
    pub fn get_object_info(
        &self,
        id: u16,
        object_type: object::ObjectType,
    ) -> Result<ObjectDescriptor, Error> {
        let mut descriptor = lyh::yh_object_descriptor::default();

        let res = unsafe {
            lyh::yh_util_get_object_info(self.ptr, id, object_type.into(), &mut descriptor)
        };

        try!(error::result_from_libyh(res));

        Ok(ObjectDescriptor::from(descriptor))
    }

    /// Delete an object
    pub fn delete_object(&self, id: u16, object_type: object::ObjectType) -> Result<(), Error> {
        let res = unsafe { lyh::yh_util_delete_object(self.ptr, id, object_type.into()) };

        try!(error::result_from_libyh(res));

        Ok(())
    }

    /// Get random data
    pub fn get_random(&self, count: usize) -> Result<Vec<u8>, Error> {
        let mut bytes = vec![0; count].into_boxed_slice();
        let mut returned = count;

        let res = unsafe {
            lyh::yh_util_get_pseudo_random(self.ptr, count, bytes.as_mut_ptr(), &mut returned)
        };

        try!(error::result_from_libyh(res));

        Ok(bytes.into_vec())
    }

    /// Import an authkey
    pub fn import_authentication_key(
        &self,
        id: u16,
        label: &str,
        domains: &[ObjectDomain],
        object_capabilities: &[ObjectCapability],
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
                &ObjectCapability::primitive_from_slice(object_capabilities),
                &ObjectCapability::primitive_from_slice(delegated_capabilities),
                password.as_ptr(),
                password.len(),
            )
        };
        try!(error::result_from_libyh(res));

        Ok(real_id)
    }

    #[allow(clippy::too_many_arguments)]
    /// Import a wrapkey
    pub fn import_wrap_key(
        &self,
        id: u16,
        label: &str,
        domains: &[ObjectDomain],
        object_capabilities: &[ObjectCapability],
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
                &ObjectCapability::primitive_from_slice(object_capabilities),
                algorithm.into(),
                &ObjectCapability::primitive_from_slice(delegated_capabilities),
                wrapkey.as_ptr(),
                wrapkey.len(),
            )
        };
        try!(error::result_from_libyh(res));

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
        target_type: object::ObjectType,
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
        try!(error::result_from_libyh(res));

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
        try!(error::result_from_libyh(res));

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
        try!(error::result_from_libyh(res));

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
        let c_str = ::std::ffi::CString::new(label).unwrap();

        let mut key_id: u16 = 0;
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
            try!(::error::result_from_libyh(res));
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
            try!(::error::result_from_libyh(res));
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
            try!(error::result_from_libyh(res));
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

    extern crate base64;

    const ENV_VAR: &str = "YUBIHSM_CONNECTOR_URL";
    const CONNECTOR_URL: &str = "http://127.0.0.1:12345";
    const PASSWORD: &str = "password";
    const WRAPKEY: [u8; 32] = [
        0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e,
        0x4f, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d,
        0x4e, 0x4f,
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
            Err(super::Error::LibYubiHsm(super::lyh::Error::DeviceObjectNotFound)) => (),
            Err(e) => panic!(
                "Wrong error. Expected {}, found {}",
                super::Error::LibYubiHsm(super::lyh::Error::DeviceObjectNotFound),
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
                &WRAPKEY,
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
                &WRAPKEY,
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
                &WRAPKEY,
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
    fn string_conversions() {
        let types = vec![
            (ObjectType::AsymmetricKey, "asymmetric-key"),
            (ObjectType::AuthenticationKey, "authentication-key"),
            (ObjectType::HmacKey, "hmac-key"),
            (ObjectType::Opaque, "opaque"),
            (ObjectType::OtpAeadKey, "otp-aead-key"),
            (ObjectType::Template, "template"),
            (ObjectType::WrapKey, "wrap-key"),
        ];

        for t in types {
            assert_eq!(&t.0.to_string(), t.1);
        }
    }

}

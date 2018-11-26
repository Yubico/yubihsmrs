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

fn main() {
    build::main();
}

#[cfg(feature = "buildlib")]
mod build {
    extern crate cmake;
    extern crate pkg_config;

    pub fn main() {
        let mut dst = cmake::Config::new("yubihsm")
            .define("WITHOUT_YKYH", "1")
            .define("RELEASE_BUILD", "1")
            .build_target("yubihsm")
            .build();

        dst.push("build");
        dst.push("lib");

        println!("cargo:rustc-link-search=native={}", dst.display());
        pkg_config::Config::new()
            .atleast_version("1.0.0")
            .probe("libcurl")
            .expect("Unable to find libcurl");
        pkg_config::Config::new()
            .atleast_version("1.0.0")
            .probe("libcrypto")
            .expect("Unable to find libcrypto");
        println!("cargo:rustc-link-lib=yubihsm");
    }
}

#[cfg(not(feature = "buildlib"))]
mod build {
    extern crate pkg_config;

    use std::env;

    pub fn main() {
        if let Ok(lib_dir) = env::var("YUBIHSM_LIB_DIR") {
            //.expect("Environment variable YUBIHSM_LIB_DIR not defined");
            println!("cargo:rustc-link-lib=yubihsm");
            println!("cargo:rustc-link-search={}", lib_dir);
        } else {
            pkg_config::Config::new()
                .atleast_version("1.1.0")
                .probe("yubihsm")
                .expect("Environment variable YUBIHSM_LIB_DIR not defined and pkg-config failed:");
        }
    }
}

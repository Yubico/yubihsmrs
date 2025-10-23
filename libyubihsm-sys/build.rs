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
    use std::path::Path;

    pub fn main() {

        // Directory override
        if let Ok(lib_dir) = env::var("YUBIHSM_LIB_DIR") {
            // 1. If YUBIHSM_LIB_NAME provided -> use it.
            // 2. Else if Windows MSVC -> prefer "libyubihsm" (matches to libyubihsm.lib).
            // 3. Else default to "yubihsm".
            let lib_name = match env::var("YUBIHSM_LIB_NAME") {
                Ok(name) => name,
                Err(_) => {
                    if cfg!(all(target_os = "windows", target_env = "msvc")) {
                        "libyubihsm".to_string()
                    } else {
                        "yubihsm".to_string()
                    }
                }
            };

            // Emit native search path
            println!("cargo:rustc-link-search=native={}", lib_dir);

            // Informational (can be seen in build output with --verbose)
            println!("cargo:warning=Linking against '{}' from '{}'", lib_name, lib_dir);

            // Sanity check: if MSVC and we chose libyubihsm, verify file exists (non-fatal warning)
            if cfg!(all(target_os = "windows", target_env = "msvc")) {
                let lib_path = Path::new(&lib_dir).join(format!("{}.lib", lib_name));
                if !lib_path.exists() {
                    println!("cargo:warning=Expected library file '{}' was not found; build may fail", lib_path.display());
                }
            }

            println!("cargo:rustc-link-lib={}", lib_name);
        } else {
            pkg_config::Config::new()
                .atleast_version("1.1.0")
                .probe("yubihsm")
                .expect("Environment variable YUBIHSM_LIB_DIR not defined and pkg-config failed:");
        }
    }
}
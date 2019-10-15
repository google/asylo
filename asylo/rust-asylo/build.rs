/*
 * Copyright 2018 Asylo authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

extern crate protoc_rust;

use std::env;
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;

fn main() {
    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("cargo should set OUT_DIR"));

    protoc_rust::run(protoc_rust::Args {
        out_dir: out_dir.to_str().expect("OUT_DIR must be valid UTF-8"),
        input: &[
            "proto/asylo/identity/identity.proto",
            "proto/asylo/identity/enclave_assertion_authority_config.proto",
            "proto/asylo/util/status.proto",
            "proto/asylo/enclave.proto"
        ],
        includes: &["proto"],
        customize: Default::default(),
    }).expect("protoc");

    // Because of https://github.com/rust-lang/rfcs/issues/752, we can't `include!` the generated
    // protobufs directly. Instead, we generate a second generated file that can be `include!`-ed.
    // This trick borrowed from rust-mbedtls.

    let mod_identity = out_dir.join("mod_identity.rs");
    File::create(&mod_identity)
        .and_then(|mut f| f.write_all(b"pub mod identity;\n"))
        .expect("mod_identity.rs I/O error");

    let mod_enclave_assertion_authority_config = out_dir.join("mod_enclave_assertion_authority_config.rs");
    File::create(&mod_enclave_assertion_authority_config)
        .and_then(|mut f| f.write_all(b"pub mod enclave_assertion_authority_config;\n"))
        .expect("mod_enclave_assertion_authority_config.rs I/O error");

    let mod_status = out_dir.join("mod_status.rs");
    File::create(&mod_status)
        .and_then(|mut f| f.write_all(b"pub mod status;\n"))
        .expect("mod_status.rs I/O error");

    let mod_enclave = out_dir.join("mod_enclave.rs");
    File::create(&mod_enclave)
        .and_then(|mut f| f.write_all(b"pub mod enclave;\n"))
        .expect("mod_enclave.rs I/O error");
}

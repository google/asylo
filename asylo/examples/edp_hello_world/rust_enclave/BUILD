#
# Copyright 2018 Asylo authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

package(
    default_visibility = ["//visibility:public"],
)

# Build Rust enclave using cargo

genrule(
    name = "rust_enclave",
    srcs = glob([
        "src/**/*.rs",
        "proto/**/*",
        "Cargo.*",
        "build.rs",
    ]),
    outs = [
        "hello_world.sgxs",
    ],
    cmd = """
        cwd=`pwd`;
        mode="debug";
        cargo_opts="";
        elf2sgxs_opts="--debug";
        if [ "$(COMPILATION_MODE)" == "opt" ]; then
            mode="release";
            cargo_opts="--release";
            elf2sgxs_opts="";
        fi;
        cd `dirname $(execpath Cargo.toml)`;
        cargo build --target x86_64-fortanix-unknown-sgx $$cargo_opts;
        TARGET="target/x86_64-fortanix-unknown-sgx/$$mode/hello_world";
        ftxsgx-elf2sgxs $$TARGET --heap-size 0x40000 --stack-size 0x20000 --threads 10 $$elf2sgxs_opts;
        cp $$TARGET.sgxs $$cwd/$@;
    """,
    executable = True,
    local = True,
)


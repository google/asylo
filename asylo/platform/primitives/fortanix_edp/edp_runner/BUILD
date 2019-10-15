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

licenses(["notice"])  # Apache v2.0

package(
    default_visibility = ["//asylo:implementation"],
)

genrule(
    name = "edp_runner_rust",
    srcs = [
        "src/lib.rs",
        "Cargo.toml",
        "Cargo.lock",
    ],
    outs = [
        "libedp_runner.a",
    ],
    cmd = """
        cwd=`pwd`;
        mode="debug";
        cargo_opts="";
        if [ "$(COMPILATION_MODE)" == "opt" ]; then
            mode="release";
            cargo_opts="--release";
        fi;
        cd `dirname $(execpath Cargo.toml)`;
        cargo build $$cargo_opts;
        cp target/$$mode/libedp_runner.a $$cwd/$@;
    """,
    local = True,
)

cc_library(
    name = "edp_runner",
    srcs = ["libedp_runner.a"],
    deps = [
        "//asylo/crypto:fortanix_edp_crypto",
    ]
)


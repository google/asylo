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

load(
    "@com_google_asylo_toolchain//toolchain:crosstool.bzl",
    "cc_toolchain_config_rule",
)
load(
    "@rules_cc//cc:defs.bzl",
    "cc_library",
    "cc_toolchain",
    "cc_toolchain_suite",
)

licenses(["notice"])

package(default_visibility = ["//visibility:public"])


ASYLO_TOOLCHAINS = [
    ("k8", "gcc"),
    ("sgx_x86_64", "gcc"),
]

[
    cc_toolchain_config_rule(
        name = x[0] + "_config",
        compiler = x[1],
        cpu = x[0],
    )
    for x in ASYLO_TOOLCHAINS
]

cc_library(name = "malloc")

filegroup(
    name = "everything",
    srcs = glob(["**"]) + [
        "@com_google_asylo//asylo/platform/posix:posix_headers",
        "@com_google_asylo//asylo/platform/system:system_headers",
    ],
)

[
    cc_toolchain(
        name = "cc-compiler-" + x[0] + "-" + x[1],
        all_files = ":everything",
        ar_files = ":everything",
        as_files = ":everything",
        compiler_files = ":everything",
        dwp_files = ":everything",
        linker_files = ":everything",
        objcopy_files = ":everything",
        strip_files = ":everything",
        supports_param_files = 0,
        toolchain_config = ":" + x[0] + "_config",
        toolchain_identifier = "asylo_" + x[0],
    )
    for x in ASYLO_TOOLCHAINS
]

CC_TOOLCHAINS = [(
    x[0],
    ":cc-compiler-" + x[0] + "-" + x[1],
) for x in ASYLO_TOOLCHAINS] + [(
    x[0] + "|" + x[1],
    ":cc-compiler-" + x[0] + "-" + x[1],
) for x in ASYLO_TOOLCHAINS]

cc_toolchain_suite(
    name = "crosstool",
    toolchains = dict(CC_TOOLCHAINS),
)



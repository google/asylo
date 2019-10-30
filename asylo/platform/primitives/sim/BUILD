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

load("//asylo/bazel:copts.bzl", "ASYLO_DEFAULT_COPTS")
load("//asylo/bazel:sim_enclave.bzl", "asylo_sim_backend")

licenses(["notice"])

package(
    default_visibility = ["//asylo:implementation"],
)

asylo_sim_backend(name = "sim")

_TRUSTED_SIM_SRCS = [
    "malloc_lock.cc",
    "runtime_stubs.c",
    "runtime_syscalls.c",
    "shared_sim.h",
    "trusted_runtime.cc",
    "trusted_sim.cc",
]

# Trusted simulator components.
cc_library(
    name = "trusted_sim",
    srcs = select(
        {
            "//asylo/platform/primitives:asylo_sim": _TRUSTED_SIM_SRCS,
        },
        no_match_error = "Trusted simulation components must be built with the backend selected",
    ),
    copts = ASYLO_DEFAULT_COPTS,
    tags = [
        "asylo-dlopen",
        "asylo-sim",
        "manual",
    ],
    deps = select(
        {
            "@com_google_asylo//asylo": [
                "//asylo/platform/primitives",
                "//asylo/platform/primitives/util:primitive_locks",
                "//asylo/platform/primitives/x86:spin_lock",
                "//asylo/platform/primitives/util:message_reader_writer",
                "//asylo/platform/primitives/util:trusted_runtime_helper",
                "//asylo/platform/primitives:trusted_primitives",
                "//asylo/platform/primitives:trusted_runtime",
                "//asylo/util:status_macros",
                "//asylo/platform/posix:backend_agnostic_posix",
            ],
        },
        "Trusted simulation components must be built with Asylo toolchain",
    ) + ["//asylo/util:cleanup"],
    alwayslink = 1,
)

cc_library(
    name = "untrusted_sim",
    srcs = [
        "shared_sim.h",
        "untrusted_sim.cc",
    ],
    hdrs = ["untrusted_sim.h"],
    copts = ASYLO_DEFAULT_COPTS,
    linkopts = ["-ldl"],
    deps = [
        "//asylo/platform/primitives",
        "//asylo/platform/primitives:untrusted_primitives",
        "//asylo/platform/primitives/util:message_reader_writer",
        "//asylo/platform/primitives/util:status_conversions",
        "//asylo/util:status",
        "@com_google_absl//absl/base",
        "@com_google_absl//absl/container:flat_hash_map",
        "@com_google_absl//absl/debugging:leak_check",
        "@com_google_absl//absl/memory",
        "@com_google_absl//absl/strings",
    ],
)

cc_library(
    name = "sim_remote_proxy_lib",
    srcs = ["sim_remote_proxy.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":loader_cc_proto",
        ":untrusted_sim",
        "//asylo:enclave_cc_proto",
        "//asylo/platform/primitives",
        "//asylo/platform/primitives:untrusted_primitives",
        "//asylo/platform/primitives/remote/util:remote_proxy_lib",
        "//asylo/platform/primitives/util:message_reader_writer",
        "//asylo/util:error_codes",
        "//asylo/util:logging",
        "//asylo/util:status",
        "//asylo/util/remote:remote_loader_cc_proto",
        "@com_google_absl//absl/memory",
        "@com_google_absl//absl/strings",
    ],
    # Required to prevent the linker from dropping the flag symbol.
    alwayslink = 1,
)

# Message definitions for simulator enclave load configuration.
proto_library(
    name = "loader_proto",
    srcs = ["loader.proto"],
    visibility = ["//visibility:public"],
    deps = [
        "//asylo:enclave_proto",
    ],
)

cc_proto_library(
    name = "loader_cc_proto",
    visibility = ["//visibility:public"],
    deps = [":loader_proto"],
)

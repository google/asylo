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

load("@rules_cc//cc:defs.bzl", "cc_library", "cc_proto_library")
load("@rules_proto//proto:defs.bzl", "proto_library")
load("//asylo/bazel:copts.bzl", "ASYLO_DEFAULT_COPTS")
load("//asylo/bazel:dlopen_enclave.bzl", "asylo_dlopen_backend")

licenses(["notice"])

package(
    default_visibility = ["//asylo:implementation"],
)

asylo_dlopen_backend(name = "dlopen")

_TRUSTED_DLOPEN_SRCS = [
    "runtime_stubs.c",
    "runtime_syscalls.c",
    "shared_dlopen.h",
    "trusted_runtime.cc",
    "trusted_dlopen.cc",
]

# Trusted dlopen components.
cc_library(
    name = "trusted_dlopen",
    srcs = select(
        {
            "//asylo/platform/primitives:asylo_dlopen": _TRUSTED_DLOPEN_SRCS,
        },
        no_match_error = "Trusted dlopen components must be built with the backend selected",
    ),
    copts = ASYLO_DEFAULT_COPTS,
    tags = [
        "asylo-dlopen",
        "manual",
    ],
    deps = select(
        {
            "@com_google_asylo//asylo": [
                "//asylo/platform/core:trusted_spin_lock",
                "//asylo/platform/primitives",
                "//asylo/platform/primitives/util:message_reader_writer",
                "//asylo/platform/primitives/util:trusted_runtime_helper",
                "//asylo/platform/primitives:trusted_primitives",
                "//asylo/platform/primitives:trusted_runtime",
                "//asylo/platform/posix:backend_independent_posix",
            ],
        },
        "Trusted dlopen components must be built with Asylo toolchain",
    ) + [
        "@com_google_absl//absl/status",
        "//asylo/util:cleanup",
    ],
    alwayslink = 1,
)

# Allow backend mismatches for trusted_dlopen when it's used as an implicit
# dependency to a backend-generic rule. All implicits have to be available at
# rule definition time, but they will only be used by the appropriate backend.
alias(
    name = "trusted_dlopen_generic",
    actual = select({
        "//asylo/platform/primitives:asylo_dlopen": ":trusted_dlopen",
        "//conditions:default": "@com_google_asylo_backend_provider//:nothing",
    }),
    visibility = ["//visibility:public"],
)

cc_library(
    name = "untrusted_dlopen",
    srcs = [
        "shared_dlopen.h",
        "untrusted_dlopen.cc",
    ],
    hdrs = ["untrusted_dlopen.h"],
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
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/strings",
    ],
)

cc_library(
    name = "dlopen_remote_proxy_lib",
    srcs = ["dlopen_remote_proxy.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":loader_cc_proto",
        ":untrusted_dlopen",
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
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/strings",
    ],
    # Required to prevent the linker from dropping the flag symbol.
    alwayslink = 1,
)

# Message definitions for dlopen enclave load configuration.
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

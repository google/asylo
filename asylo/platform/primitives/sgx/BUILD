#
# Copyright 2019 Asylo authors
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

exports_files([
    "bridge.edl",
    "errno.edl",
])

load("//asylo/bazel:copts.bzl", "ASYLO_DEFAULT_COPTS")

cc_library(
    name = "sgx_params",
    hdrs = ["sgx_params.h"],
    copts = ASYLO_DEFAULT_COPTS,
)

# Trusted runtime components for SGX.
cc_library(
    name = "trusted_sgx",
    srcs = [
        "trusted_runtime.cc",
        "trusted_sgx.cc",
        "trusted_sgx.h",
    ],
    copts = ASYLO_DEFAULT_COPTS,
    tags = [
        "asylo-sgx",
        "manual",
    ],
    deps = select(
        {
            "//asylo/platform/primitives:asylo_sgx": [
                "//asylo/platform/primitives",
                "//asylo/util:logging",
                "//asylo/platform/primitives:trusted_primitives",
                "//asylo/platform/primitives:trusted_runtime",
                "//asylo/platform/primitives/util:primitive_locks",
                "//asylo/platform/primitives/util:trusted_runtime_helper",
                "//asylo/platform/primitives/x86:spin_lock",
                "//asylo/util:error_codes",
                "//asylo/platform/arch:trusted_sgx_bridge",
                "//asylo/util:status",
                "//asylo/platform/primitives/sgx:sgx_error_space",
                "@linux_sgx//:public",
                "@linux_sgx//:trts",
            ],
        },
        no_match_error = "Trusted SGX components must be built with --define=ASYLO_SGX=1",
    ) + [
        ":sgx_params",
        "@com_google_absl//absl/strings",
        "//asylo/platform/primitives/util:message_reader_writer",
        "//asylo/util:cleanup",
    ],
)

cc_library(
    name = "untrusted_sgx",
    srcs = ["untrusted_sgx.cc"],
    hdrs = ["untrusted_sgx.h"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":sgx_error_space",
        ":sgx_params",
        "//asylo:enclave_cc_proto",
        "//asylo/platform/arch:fork_cc_proto",
        "//asylo/platform/common:bridge_types",
        "//asylo/platform/primitives:untrusted_primitives",
        "//asylo/platform/primitives/util:message_reader_writer",
        "//asylo/util:cleanup",
        "//asylo/util:elf_reader",
        "//asylo/util:file_mapping",
        "//asylo/util:status",
        "@linux_sgx//:public",
        "@linux_sgx//:urts",
    ],
)

# An error space for SGX.
cc_library(
    name = "sgx_error_space",
    srcs = ["sgx_error_space.cc"],
    hdrs = ["sgx_error_space.h"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        "//asylo/util:status",
        "@linux_sgx//:public",
    ],
)

# Message definitions for SGX enclave loader.
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

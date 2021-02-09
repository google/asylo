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

load("@rules_cc//cc:defs.bzl", "cc_library")
load("//asylo/bazel:copts.bzl", "ASYLO_DEFAULT_COPTS")

licenses(["notice"])

# Architecture abstraction layer.
#

package(
    default_visibility = ["//asylo:implementation"],
)

# Target exposing trusted architecture-dependent components for the build
# configuration.
cc_library(
    name = "trusted_arch",
    copts = ASYLO_DEFAULT_COPTS,
    deps = select({
        "@linux_sgx//:sgx_hw": ["//asylo/platform/primitives/sgx:trusted_sgx_ecalls"],
        "@linux_sgx//:sgx_sim": ["//asylo/platform/primitives/sgx:trusted_sgx_ecalls"],
        "//conditions:default": [":trusted_build_only"],
    }) + [
        "//asylo:enclave_cc_proto",
        "//asylo/platform/core:shared_name",
        "//asylo/util:status",
    ],
)

# Target exposing untrusted client components for all backends.
cc_library(
    name = "untrusted_arch",
    srcs = ["sgx/untrusted/sgx_client.cc"],
    hdrs = [
        "sgx/untrusted/sgx_client.h",
    ],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        "//asylo:enclave_cc_proto",
        "//asylo/platform/core:untrusted_core",
        "//asylo/platform/primitives/sgx:fork_cc_proto",
        "//asylo/platform/primitives/sgx:loader_cc_proto",
        "//asylo/platform/primitives/sgx:untrusted_sgx",
        "//asylo/util:status",
        "@com_google_absl//absl/base:core_headers",
        "@com_google_absl//absl/types:span",
    ],
)

# This target supports building trusted targets with the system native compiler,
# which provides a very basic coherence check for Asylo clients in contexts
# where pulling in the cross-compiler toolchain is inconvenient or tricky.
# Attempting to load a dynamic library linked against this target will fail
# since no actual implementation is provided.
cc_library(
    name = "trusted_build_only",
    visibility = ["//visibility:private"],
    deps = ["//asylo/platform/core:shared_name"],
)

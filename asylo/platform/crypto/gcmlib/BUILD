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

# GCM library for secure storage.

load("@linux_sgx//:sgx_sdk.bzl", "sgx_enclave")
load("//asylo/bazel:asylo.bzl", "cc_enclave_test")

package(
    default_visibility = ["//asylo:implementation"],
)

cc_library(
    name = "trusted_gcmlib",
    deps = select({
        "@com_google_asylo//asylo": ["gcm_cryptor"],
        "//conditions:default": [],
    }),
)

cc_library(
    name = "gcm_cryptor",
    srcs = ["gcm_cryptor.cc"],
    hdrs = ["gcm_cryptor.h"],
    deps = [
        "//asylo/crypto/util:bssl_util",
        "//asylo/identity/util:byte_container_view",
        "//asylo/identity/util:bytes",
        "@boringssl//:crypto",
        "@com_google_absl//absl/memory",
        "@com_google_absl//absl/synchronization",
        "@com_google_asylo//asylo/util:logging",
    ],
)

# GCM cryptor test in enclave.
cc_enclave_test(
    name = "gcm_cryptor_test",
    srcs = ["gcm_cryptor_test.cc"],
    tags = ["regression"],
    deps = [
        "@com_google_googletest//:gtest",
    ],
)

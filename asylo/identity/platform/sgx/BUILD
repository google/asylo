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

# This package contains libraries that define constants, types, and utilities
# that are specific to the SGX platform.

# Used to enable gtest tests to run inside an enclave.
load("//asylo/bazel:asylo.bzl", "cc_test_and_cc_enclave_test")
load("//asylo/bazel:copts.bzl", "ASYLO_DEFAULT_COPTS")
load("@linux_sgx//:sgx_sdk.bzl", "sgx")

licenses(["notice"])

package(default_visibility = ["//visibility:public"])

proto_library(
    name = "attributes_proto",
    srcs = ["attributes.proto"],
)

cc_proto_library(
    name = "attributes_cc_proto",
    deps = [":attributes_proto"],
)

cc_library(
    name = "attributes_util",
    srcs = ["attributes_util.cc"],
    hdrs = ["attributes_util.h"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":architecture_bits",
        ":attributes_cc_proto",
        "//asylo/util:status",
        "//asylo/util:status_macros",
        "@com_google_absl//absl/strings",
    ],
)

cc_test_and_cc_enclave_test(
    name = "attributes_util_test",
    srcs = ["attributes_util_test.cc"],
    backends = sgx.backend_labels,
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":architecture_bits",
        ":attributes_cc_proto",
        ":attributes_util",
        "//asylo/test/util:status_matchers",
        "//asylo/test/util:test_main",
        "@com_google_googletest//:gtest",
    ],
)

cc_library(
    name = "architecture_bits",
    srcs = ["architecture_bits.cc"],
    hdrs = ["architecture_bits.h"],
    copts = ASYLO_DEFAULT_COPTS,
)

cc_library(
    name = "miscselect_util",
    srcs = ["miscselect_util.cc"],
    hdrs = ["miscselect_util.h"],
    copts = ASYLO_DEFAULT_COPTS,
    visibility = ["//asylo:implementation"],
    deps = [
        ":architecture_bits",
        "//asylo/identity/sgx:miscselect_cc_proto",
        "//asylo/util:status",
        "@com_google_absl//absl/strings",
    ],
)

cc_test_and_cc_enclave_test(
    name = "miscselect_util_test",
    srcs = ["miscselect_util_test.cc"],
    backends = sgx.backend_labels,
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":architecture_bits",
        ":miscselect_util",
        "//asylo/identity/sgx:hardware_types",
        "//asylo/identity/sgx:miscselect_cc_proto",
        "//asylo/test/util:status_matchers",
        "//asylo/test/util:test_main",
        "@com_google_googletest//:gtest",
    ],
)

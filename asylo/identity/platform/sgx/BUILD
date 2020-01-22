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
load("@rules_proto//proto:defs.bzl", "proto_library")
load("@linux_sgx//:sgx_sdk.bzl", "sgx")
load("@rules_cc//cc:defs.bzl", "cc_proto_library")

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

proto_library(
    name = "code_identity_proto",
    srcs = ["code_identity.proto"],
    deps = [
        ":attributes_proto",
        "//asylo/crypto:sha256_hash_proto",
    ],
)

cc_proto_library(
    name = "code_identity_cc_proto",
    deps = [":code_identity_proto"],
)

proto_library(
    name = "machine_configuration_proto",
    srcs = ["machine_configuration.proto"],
)

cc_proto_library(
    name = "machine_configuration_cc_proto",
    deps = [":machine_configuration_proto"],
)

proto_library(
    name = "miscselect_proto",
    srcs = ["miscselect.proto"],
)

cc_proto_library(
    name = "miscselect_cc_proto",
    deps = [":miscselect_proto"],
)

proto_library(
    name = "sgx_identity_proto",
    srcs = ["sgx_identity.proto"],
    deps = [
        ":code_identity_proto",
        ":machine_configuration_proto",
    ],
)

cc_proto_library(
    name = "sgx_identity_cc_proto",
    deps = [":sgx_identity_proto"],
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

cc_test_and_cc_enclave_test(
    name = "architecture_bits_test",
    srcs = ["architecture_bits_test.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":architecture_bits",
        "//asylo/test/util:test_main",
        "@com_google_googletest//:gtest",
    ],
)

cc_library(
    name = "miscselect_util",
    srcs = ["miscselect_util.cc"],
    hdrs = ["miscselect_util.h"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":architecture_bits",
        ":miscselect_cc_proto",
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
        ":miscselect_cc_proto",
        ":miscselect_util",
        "//asylo/identity/sgx:hardware_types",
        "//asylo/test/util:status_matchers",
        "//asylo/test/util:test_main",
        "@com_google_googletest//:gtest",
    ],
)

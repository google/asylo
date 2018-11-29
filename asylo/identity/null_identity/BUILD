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

# Contains libraries related to null identity and null assertion.

load("//asylo/bazel:asylo.bzl", "cc_test")
load("//asylo/bazel:proto.bzl", "asylo_proto_library")
load("//asylo/bazel:copts.bzl", "ASYLO_DEFAULT_COPTS")

# Definition of a null assertion.
asylo_proto_library(
    name = "null_assertion_proto",
    srcs = ["null_assertion.proto"],
)

# Implementation of the EnclaveAssertionGenerator interface for null
# assertions. This library is provided by default with the enclave gRPC stack.
cc_library(
    name = "null_assertion_generator",
    srcs = [
        "null_assertion_generator.cc",
        "null_assertion_generator.h",
    ],
    copts = ASYLO_DEFAULT_COPTS,
    visibility = ["//visibility:public"],
    deps = [
        ":null_assertion_proto_cc",
        ":null_identity_constants",
        "//asylo/identity:enclave_assertion_generator",
        "//asylo/platform/common:static_map",
        "//asylo/util:logging",
        "@com_google_absl//absl/synchronization",
    ],
    alwayslink = 1,
)

# Implementation of the EnclaveAssertionVerifier interface for null assertions.
# This library is provided by default with the enclave gRPC stack.
cc_library(
    name = "null_assertion_verifier",
    srcs = [
        "null_assertion_verifier.cc",
        "null_assertion_verifier.h",
    ],
    copts = ASYLO_DEFAULT_COPTS,
    visibility = ["//visibility:public"],
    deps = [
        ":null_assertion_proto_cc",
        ":null_identity_constants",
        ":null_identity_util",
        "//asylo/identity:enclave_assertion_verifier",
        "//asylo/platform/common:static_map",
        "//asylo/util:logging",
        "@com_google_absl//absl/synchronization",
    ],
    alwayslink = 1,
)

# Tests for NullAssertionGenerator and NullAssertionVerifier.
cc_test(
    name = "null_assertion_authority_test",
    srcs = [
        "null_assertion_authority_test.cc",
        "null_assertion_generator.h",
        "null_assertion_verifier.h",
    ],
    copts = ASYLO_DEFAULT_COPTS,
    enclave_test_name = "null_assertion_authority_enclave_test",
    deps = [
        ":null_assertion_generator",
        ":null_assertion_verifier",
        ":null_identity_constants",
        "//asylo/identity:enclave_assertion_authority",
        "//asylo/identity:enclave_assertion_authority_config_proto_cc",
        "//asylo/identity:enclave_assertion_generator",
        "//asylo/identity:enclave_assertion_verifier",
        "//asylo/identity:init",
        "//asylo/test/util:status_matchers",
        "//asylo/test/util:test_main",
        "@com_google_absl//absl/synchronization",
        "@com_google_googletest//:gtest",
    ],
)

# Implementation of the MappableIdentityExpectationMatcher interface for the
# null identity.
cc_library(
    name = "null_identity_expectation_matcher",
    srcs = [
        "null_identity_expectation_matcher.cc",
        "null_identity_expectation_matcher.h",
    ],
    copts = ASYLO_DEFAULT_COPTS,
    visibility = ["//visibility:public"],
    deps = [
        ":null_identity_util",
        "//asylo/identity:identity_expectation_matcher",
        "//asylo/identity:identity_proto_cc",
        "@com_google_protobuf//:protobuf",
    ],
    alwayslink = 1,
)

# Tests for NullIdentityExpectationMatcher.
cc_test(
    name = "null_identity_expectation_matcher_test",
    srcs = [
        "null_identity_expectation_matcher.h",
        "null_identity_expectation_matcher_test.cc",
    ],
    copts = ASYLO_DEFAULT_COPTS,
    enclave_test_name = "null_identity_expectation_matcher_enclave_test",
    deps = [
        ":null_identity_constants",
        ":null_identity_expectation_matcher",
        "//asylo/identity:identity_expectation_matcher",
        "//asylo/identity:identity_proto_cc",
        "//asylo/test/util:status_matchers",
        "//asylo/test/util:test_main",
        "//asylo/util:status",
        "@com_google_googletest//:gtest",
    ],
)

# String constants related to null identity and assertions.
cc_library(
    name = "null_identity_constants",
    srcs = ["null_identity_constants.cc"],
    hdrs = ["null_identity_constants.h"],
    copts = ASYLO_DEFAULT_COPTS,
)

# Utility functions for operating on null identities and assertions.
cc_library(
    name = "null_identity_util",
    hdrs = ["null_identity_util.h"],
    copts = ASYLO_DEFAULT_COPTS,
    visibility = ["//asylo:implementation"],
    deps = [
        ":null_identity_constants",
        "//asylo/identity:identity_proto_cc",
    ],
)

cc_test(
    name = "null_identity_util_test",
    srcs = ["null_identity_util_test.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    enclave_test_name = "null_identity_util_enclave_test",
    deps = [
        ":null_identity_constants",
        ":null_identity_util",
        "//asylo/identity:identity_proto_cc",
        "//asylo/test/util:test_main",
        "@com_google_googletest//:gtest",
    ],
)

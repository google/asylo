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

# Build targets for the whole-application wrapper and its tests.

load(
    "//asylo/bazel:asylo.bzl",
    "cc_test",
    "enclave_test",
)
load("//asylo/bazel:proto.bzl", "asylo_proto_library")
load("//asylo/bazel:copts.bzl", "ASYLO_DEFAULT_COPTS")
load(
    "@linux_sgx//:sgx_sdk.bzl",
    "sgx_enclave",
    "sgx_enclave_configuration",
)

# A utility for converting various representations of argv.
cc_library(
    name = "argv",
    srcs = ["argv.cc"],
    hdrs = ["argv.h"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        "@com_google_absl//absl/strings",
        "@com_google_protobuf//:protobuf_lite",
    ],
)

# The whole-application wrapper's extensions to the enclave proto messages.
asylo_proto_library(
    name = "application_wrapper_proto",
    srcs = ["application_wrapper.proto"],
    deps = ["//asylo:enclave_proto"],
)

# The core of the whole-application wrapper's enclave. Intended to be included
# as a dep in a *_enclave rule.
cc_library(
    name = "application_wrapper_enclave_core",
    srcs = ["application_wrapper_enclave.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    visibility = ["//visibility:public"],
    deps = [
        ":application_wrapper_proto_cc",
        ":argv",
        "//asylo:enclave_runtime",
        "//asylo/util:logging",
        "//asylo/util:status",
        "@com_google_absl//absl/strings",
    ],
)

# A test of Argv.
cc_test(
    name = "argv_test",
    srcs = ["argv_test.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    enclave_test_name = "argv_enclave_test",
    deps = [
        ":argv",
        "//asylo/test/util:test_main",
        "@com_google_absl//absl/base:core_headers",
        "@com_google_googletest//:gtest",
        "@com_google_protobuf//:protobuf_lite",
    ],
)

# The section name to use for testing.
TEST_SECTION_NAME = "test_enclave"

# A test application (with a main() function).
cc_library(
    name = "test_application_library",
    testonly = 1,
    srcs = ["test_application.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = ["//asylo/util:logging"],
)

# An SGX enclave configuration with a TCS number high enough for the
# multi-threaded entry test.
sgx_enclave_configuration(
    name = "application_wrapper_enclave_test_configuration",
    tcs_num = "300",
)

# An application enclave wrapping :test_application.
sgx_enclave(
    name = "application_wrapper_enclave_test_enclave.so",
    testonly = 1,
    config = ":application_wrapper_enclave_test_configuration",
    deps = [
        ":application_wrapper_enclave_core",
        ":test_application_library",
    ],
)

# A test of ApplicationWrapperEnclave.
enclave_test(
    name = "application_wrapper_enclave_test",
    srcs = ["application_wrapper_enclave_test.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    embedded_enclaves = {TEST_SECTION_NAME: ":application_wrapper_enclave_test_enclave.so"},
    test_args = [
        "--enclave_section",
        TEST_SECTION_NAME,
    ],
    deps = [
        ":application_wrapper_proto_cc",
        ":argv",
        "//asylo:enclave_client",
        "//asylo/test/util:pipe",
        "//asylo/test/util:status_matchers",
        "//asylo/test/util:test_main",
        "//asylo/util:logging",
        "//asylo/util:status",
        "@com_github_gflags_gflags//:gflags_nothreads",
        "@com_google_absl//absl/strings",
        "@com_google_googletest//:gtest",
    ],
)

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

# Enclave test infrastructure.

package(default_visibility = ["//asylo:implementation"])

load("//asylo/bazel:asylo.bzl", "cc_test")
load("//asylo/bazel:copts.bzl", "ASYLO_DEFAULT_COPTS")
load("//asylo/bazel:proto.bzl", "asylo_proto_library")
load("@linux_sgx//:sgx_sdk.bzl", "sgx_enclave")

# Test helper that runs a subprocess and checks output.
cc_library(
    name = "exec_tester",
    testonly = 1,
    srcs = ["exec_tester.cc"],
    hdrs = ["exec_tester.h"],
    copts = ASYLO_DEFAULT_COPTS,
    visibility = ["//visibility:public"],
    deps = [
        "@com_google_absl//absl/strings",
        "@com_google_googletest//:gtest",
    ],
)

# Miscallaneous helper functions for tests.
cc_library(
    name = "test_util",
    testonly = 1,
    srcs = ["test_util.cc"],
    hdrs = ["test_util.h"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        "//asylo/crypto/util:bytes",
        "//asylo/util:logging",
        "//asylo/util:status",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/synchronization",
    ],
)

# Subprocess used to test exec_tester.
cc_binary(
    name = "exit_app",
    testonly = 1,
    srcs = ["exit_app.cc"],
    copts = ASYLO_DEFAULT_COPTS,
)

# Who tests the tester? This.
cc_test(
    name = "exec_tester_test",
    srcs = ["exec_tester_test.cc"],
    args = ["--binary_path=$(location :exit_app)"],
    copts = ASYLO_DEFAULT_COPTS,
    data = [":exit_app"],
    deps = [
        ":exec_tester",
        ":test_main",
        "@com_github_gflags_gflags//:gflags_nothreads",
        "@com_google_googletest//:gtest",
    ],
)

# A single string input extension for EnclaveTest to communicate test data to
# an EnclaveTestCase.
asylo_proto_library(
    name = "test_string_proto",
    srcs = ["test_string.proto"],
    deps = ["//asylo:enclave_proto"],
)

# Simple enclave launcher for testing.
cc_library(
    name = "enclave_test_launcher",
    testonly = 1,
    srcs = ["enclave_test_launcher.cc"],
    hdrs = ["enclave_test_launcher.h"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":test_string_proto_cc",
        "//asylo:enclave_client",
        "//asylo:enclave_proto_cc",
        "//asylo/util:logging",
        "//asylo/util:status",
        "@com_google_absl//absl/memory",
    ],
)

# This defines the enclave test class that all test codes inside enclave should
# be derived from.
cc_library(
    name = "enclave_test_application",
    srcs = ["enclave_test_application.cc"],
    hdrs = ["enclave_test_application.h"],
    copts = ASYLO_DEFAULT_COPTS,
    visibility = ["//asylo:implementation"],
    deps = [
        ":test_string_proto_cc",
        "//asylo:enclave_proto_cc",
        "//asylo:enclave_runtime",
    ],
)

# Program entry to parse flags and run all gtest tests.
cc_library(
    name = "test_main_impl",
    testonly = 1,
    srcs = ["test_main.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    visibility = ["//visibility:private"],
    deps = [
        ":test_flags",
        "@com_github_gflags_gflags//:gflags_nothreads",
        "@com_google_googletest//:gtest",
    ],
)

# Provides a suitable program main function for running gtest tests.
# When inside of an enclave, a main function is not used to trigger tests, so
# this target results in no added code in that case. When outside of an
# enclave, this target includes an appropriate main function that runs all
# tests.
cc_library(
    name = "test_main",
    testonly = 1,
    copts = ASYLO_DEFAULT_COPTS,
    visibility = ["//visibility:public"],
    deps = select({
        "@com_google_asylo//asylo": [],
        "//conditions:default": [
            ":test_main_impl",
        ],
    }),
)

# Provides common command line flags for tests.
cc_library(
    name = "test_flags",
    testonly = 1,
    srcs = ["test_flags.cc"],
    hdrs = ["test_flags.h"],
    copts = ASYLO_DEFAULT_COPTS,
    visibility = ["//visibility:public"],
    deps = [
        "@com_github_gflags_gflags//:gflags_nothreads",
    ],
)

# Gtest wrapper around enclave_test_launcher.
cc_library(
    name = "enclave_test",
    testonly = 1,
    srcs = ["enclave_test.cc"],
    hdrs = ["enclave_test.h"],
    copts = ASYLO_DEFAULT_COPTS,
    visibility = ["//visibility:public"],
    deps = [
        ":enclave_test_launcher",
        ":status_matchers",
        ":test_flags",
        ":test_main",
        "//asylo:enclave_proto_cc",
        "//asylo/util:status",
        "@com_github_gflags_gflags//:gflags_nothreads",
        "@com_google_googletest//:gtest",
    ],
)

# A utility for POSIX pipes. Intended to be used to read enclave stdout and
# stderr.
cc_library(
    name = "pipe",
    testonly = 1,
    srcs = ["pipe.cc"],
    hdrs = ["pipe.h"],
    copts = ASYLO_DEFAULT_COPTS,
    visibility = ["//asylo:implementation"],
    deps = [
        "//asylo/util:logging",
        "//asylo/util:status",
        "@com_google_absl//absl/strings",
    ],
)

# gMock matchers for Protocol Buffers.
cc_library(
    name = "proto_matchers",
    testonly = 1,
    hdrs = ["proto_matchers.h"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        "@com_google_googletest//:gtest",
        "@com_google_protobuf//:protobuf",
    ],
)

# gMock matchers for asylo::Status and asylo::StatusOr<T> and a gtest
# printer extension for asylo::StatusOr<T>.
cc_library(
    name = "status_matchers",
    testonly = 1,
    hdrs = ["status_matchers.h"],
    copts = ASYLO_DEFAULT_COPTS,
    visibility = ["//visibility:public"],
    deps = [
        "//asylo/crypto/util:bytes",
        "//asylo/util:status",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/types:optional",
        "@com_google_googletest//:gtest",
    ],
)

# A test for the Status matchers.
cc_test(
    name = "status_matchers_test",
    srcs = ["status_matchers_test.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    enclave_test_name = "status_matchers_enclave_test",
    tags = ["regression"],
    deps = [
        ":status_matchers",
        ":test_main",
        "//asylo/util:status",
        "@com_google_absl//absl/strings",
        "@com_google_googletest//:gtest",
    ],
)

cc_library(
    name = "fake_local_enclave_client",
    testonly = 1,
    hdrs = ["fake_local_enclave_client.h"],
    copts = ASYLO_DEFAULT_COPTS,
    visibility = ["//visibility:public"],
    deps = [
        "//asylo:enclave_client",
        "//asylo/util:status",
    ],
)

# A fake EnclaveClient that can pass EnterAndRun calls directly to enclave code.
# This is useful for testing enclaves that can be built by the native compiler,
# since it lets them be tested without any special configuration.
cc_test(
    name = "fake_local_enclave_client_test",
    size = "small",
    srcs = ["fake_local_enclave_client_test.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":fake_local_enclave_client",
        ":test_main",
        "//asylo/test/util:status_matchers",
        "@com_google_googletest//:gtest",
    ],
)

cc_test(
    name = "mock_test",
    srcs = ["mock_test.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":mock_enclave_client",
        ":mock_enclave_loader",
        ":test_main",
        "@com_google_googletest//:gtest",
    ],
)

# A mock EnclaveClient that can be used in tests in the native compiler.
# This allows tests to simulate calling into an enclave and getting responses.
# In particular, it is useful for programming EnterAndRun using ON_CALL to give
# simple responses for extensions to EnclaveInput.
cc_library(
    name = "mock_enclave_client",
    testonly = 1,
    hdrs = ["mock_enclave_client.h"],
    copts = ASYLO_DEFAULT_COPTS,
    visibility = ["//visibility:public"],
    deps = [
        "//asylo:enclave_client",
        "//asylo/util:status",
        "@com_google_googletest//:gtest",
    ],
)

cc_library(
    name = "mock_enclave_loader",
    testonly = 1,
    hdrs = ["mock_enclave_loader.h"],
    copts = ASYLO_DEFAULT_COPTS,
    visibility = ["//visibility:public"],
    deps = [
        "//asylo:enclave_client",
        "//asylo/util:status",
        "@com_google_googletest//:gtest",
    ],
)

# A FakeEnclaveLoader that loads a given EnclaveClient.
cc_library(
    name = "fake_enclave_loader",
    testonly = 1,
    srcs = ["fake_enclave_loader.cc"],
    hdrs = ["fake_enclave_loader.h"],
    copts = ASYLO_DEFAULT_COPTS,
    visibility = ["//visibility:public"],
    deps = [
        "//asylo:enclave_client",
        "//asylo/util:status",
    ],
)

cc_library(
    name = "grpc_debug_config",
    srcs = ["grpc_debug_config.cc"],
    hdrs = ["grpc_debug_config.h"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        "//asylo:enclave_proto_cc",
        "@com_google_absl//absl/strings",
    ],
)

# An enclave for testing purposes. All entry points use the default
# implementations.
sgx_enclave(
    name = "do_nothing_enclave.so",
    srcs = ["do_nothing_enclave.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = ["//asylo:enclave_runtime"],
)

# Sample text for testing purposes.
filegroup(
    name = "sample_text",
    srcs = ["lorem_ipsum.txt"],
)

# A binary for testing purposes. Not intended to be run.
cc_binary(
    name = "test_binary",
    srcs = ["test_binary.cc"],
    copts = ASYLO_DEFAULT_COPTS,
)

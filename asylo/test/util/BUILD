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

load("@linux_sgx//:sgx_sdk.bzl", "sgx")
load("@rules_cc//cc:defs.bzl", "cc_binary", "cc_library", "cc_proto_library")
load("@rules_proto//proto:defs.bzl", "proto_library")
load(
    "//asylo/bazel:asylo.bzl",
    "ASYLO_ALL_BACKEND_TAGS",
    "cc_test",
    "cc_unsigned_enclave",
    "debug_sign_enclave",
)
load("//asylo/bazel:copts.bzl", "ASYLO_DEFAULT_COPTS")

licenses(["notice"])  # Apache v2.0

# Enclave test infrastructure.

package(default_visibility = ["//asylo:implementation"])

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
        "@com_google_absl//absl/types:span",
        "@com_google_googletest//:gtest",
    ],
)

# Functions for stress-testing pthreads.
cc_library(
    name = "pthread_test_util",
    testonly = 1,
    srcs = ["pthread_test_util.cc"],
    hdrs = ["pthread_test_util.h"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        "//asylo/util:status",
        "@boringssl//:crypto",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/strings",
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
        "@com_google_absl//absl/flags:flag",
        "@com_google_googletest//:gtest",
    ],
)

# A single string input extension for EnclaveTest to communicate test data to
# an EnclaveTestCase.
proto_library(
    name = "test_string_proto",
    srcs = ["test_string.proto"],
    deps = ["//asylo:enclave_proto"],
)

cc_proto_library(
    name = "test_string_cc_proto",
    deps = [":test_string_proto"],
)

# Simple enclave launcher for testing.
cc_library(
    name = "enclave_test_launcher",
    testonly = 1,
    srcs = ["enclave_test_launcher.cc"],
    hdrs = ["enclave_test_launcher.h"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":test_string_cc_proto",
        "//asylo:enclave_cc_proto",
        "//asylo:enclave_client",
        "//asylo/platform/primitives/sgx:loader_cc_proto",
        "//asylo/util:logging",
        "//asylo/util:posix_errors",
        "//asylo/util:status",
        "@com_google_absl//absl/memory",
        "@com_google_absl//absl/status",
    ],
)

# This defines the enclave test class that all test codes inside enclave should
# be derived from.
cc_library(
    name = "enclave_test_application",
    srcs = ["enclave_test_application.cc"],
    hdrs = ["enclave_test_application.h"],
    copts = ASYLO_DEFAULT_COPTS,
    tags = ASYLO_ALL_BACKEND_TAGS,
    visibility = ["//asylo:implementation"],
    deps = [
        ":test_string_cc_proto",
        "//asylo:enclave_cc_proto",
        "//asylo:enclave_runtime",
    ],
)

# Boundary values of integral types.
cc_library(
    name = "integral_type_test_data",
    testonly = 1,
    hdrs = ["integral_type_test_data.h"],
    copts = ASYLO_DEFAULT_COPTS,
    visibility = ["//asylo:implementation"],
    deps = ["@com_google_googletest//:gtest"],
)

# Program entry to parse flags and run all gtest tests.
cc_library(
    name = "test_main_impl",
    testonly = 1,
    srcs = ["test_main.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    visibility = ["//visibility:private"],
    deps = [
        "@com_google_absl//absl/flags:parse",
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
    deps = ["@com_google_absl//absl/flags:flag"],
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
        "//asylo:enclave_cc_proto",
        "//asylo/util:status",
        "@com_google_absl//absl/flags:flag",
        "@com_google_googletest//:gtest",
    ],
)

# A utility for collecting writes from file descriptors.
cc_library(
    name = "output_collector",
    testonly = 1,
    srcs = ["output_collector.cc"],
    hdrs = ["output_collector.h"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        "//asylo/util:fd_utils",
        "//asylo/util:logging",
        "//asylo/util:status",
    ],
)

# gMock matchers for Protocol Buffers.
cc_library(
    name = "proto_matchers",
    testonly = 1,
    hdrs = ["proto_matchers.h"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        "@com_google_absl//absl/strings",
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
        "//asylo/util:status",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/status:statusor",
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
    deps = [
        ":status_matchers",
        ":test_main",
        "//asylo/util:status",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/status:statusor",
        "@com_google_absl//absl/strings",
        "@com_google_googletest//:gtest",
    ],
)

cc_library(
    name = "string_matchers",
    testonly = 1,
    hdrs = ["string_matchers.h"],
    copts = ASYLO_DEFAULT_COPTS,
    visibility = ["//asylo:implementation"],
    deps = [
        "@com_google_absl//absl/strings",
        "@com_google_googletest//:gtest",
    ],
)

cc_test(
    name = "string_matchers_test",
    srcs = ["string_matchers_test.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    enclave_test_name = "string_matchers_enclave_test",
    deps = [
        ":string_matchers",
        ":test_main",
        "@com_google_absl//absl/strings",
        "@com_google_googletest//:gtest",
    ],
)

cc_library(
    name = "memory_matchers",
    testonly = 1,
    hdrs = ["memory_matchers.h"],
    copts = ASYLO_DEFAULT_COPTS,
    visibility = ["//asylo:implementation"],
    deps = [
        "@com_google_absl//absl/strings:str_format",
        "@com_google_googletest//:gtest",
    ],
)

cc_test(
    name = "memory_matchers_test",
    srcs = ["memory_matchers_test.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    enclave_test_name = "memory_matchers_enclave_test",
    deps = [
        ":memory_matchers",
        ":test_main",
        "//asylo/crypto/util:bytes",
        "//asylo/crypto/util:trivial_object_util",
        "@com_google_absl//absl/base:core_headers",
        "@com_google_googletest//:gtest",
    ],
)

cc_library(
    name = "finite_domain_fuzz",
    testonly = 1,
    srcs = ["finite_domain_fuzz.cc"],
    hdrs = ["finite_domain_fuzz.h"],
    copts = ASYLO_DEFAULT_COPTS,
    visibility = ["//visibility:public"],
    deps = [
        "//asylo/util:logging",
        "@com_google_absl//absl/random",
        "@com_google_absl//absl/strings:str_format",
        "@com_google_absl//absl/types:optional",
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
        "@com_google_absl//absl/strings",
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
        "//asylo:enclave_cc_proto",
        "//asylo:enclave_client",
        "//asylo/util:status",
        "@com_google_absl//absl/strings",
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
        "//asylo:enclave_cc_proto",
        "//asylo:enclave_client",
        "//asylo/util:status",
        "@com_google_absl//absl/strings",
    ],
)

cc_library(
    name = "grpc_debug_config",
    srcs = ["grpc_debug_config.cc"],
    hdrs = ["grpc_debug_config.h"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        "//asylo:enclave_cc_proto",
        "@com_google_absl//absl/strings",
    ],
)

# Provides configurations suitable for use in tests.
cc_library(
    name = "enclave_assertion_authority_configs",
    testonly = 1,
    srcs = ["enclave_assertion_authority_configs.cc"],
    hdrs = ["enclave_assertion_authority_configs.h"],
    copts = ASYLO_DEFAULT_COPTS,
    visibility = ["//asylo:implementation"],
    deps = [
        "//asylo/crypto:certificate_cc_proto",
        "//asylo/crypto:sha256_hash_cc_proto",
        "//asylo/identity:enclave_assertion_authority_config_cc_proto",
        "//asylo/identity:enclave_assertion_authority_configs",
        "//asylo/identity:identity_acl_cc_proto",
        "//asylo/identity/platform/sgx:attributes_cc_proto",
        "//asylo/identity/platform/sgx:code_identity_cc_proto",
        "//asylo/identity/platform/sgx:sgx_identity_cc_proto",
        "//asylo/identity/platform/sgx:sgx_identity_util",
        "//asylo/identity/platform/sgx/internal:hardware_types",
        "//asylo/identity/provisioning/sgx/internal:fake_sgx_pki",
        "//asylo/util:proto_parse_util",
        "@linux_sgx//:debug_key_mrsigner",
    ],
)

cc_test(
    name = "enclave_assertion_authority_configs_test",
    srcs = ["enclave_assertion_authority_configs_test.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":enclave_assertion_authority_configs",
        ":proto_matchers",
        ":status_matchers",
        ":test_main",
        "//asylo/identity:descriptions",
        "//asylo/identity:enclave_assertion_authority_config_cc_proto",
        "//asylo/identity:identity_acl_cc_proto",
        "//asylo/identity/attestation/sgx:sgx_age_remote_assertion_authority_config_cc_proto",
        "//asylo/identity/platform/sgx:sgx_identity_cc_proto",
        "//asylo/identity/platform/sgx:sgx_identity_expectation_matcher",
        "//asylo/identity/platform/sgx:sgx_identity_util",
        "//asylo/identity/provisioning/sgx/internal:fake_sgx_pki",
        "//asylo/util:proto_parse_util",
        "@com_google_googletest//:gtest",
    ],
)

# A library of shell test utilities.
sh_library(
    name = "shell_testing",
    testonly = 1,
    srcs = ["shell_testing.sh"],
)

# An enclave for testing purposes. All entry points use the default
# implementations.
cc_unsigned_enclave(
    name = "do_nothing_enclave_unsigned.so",
    srcs = ["do_nothing_enclave.cc"],
    backends = sgx.backend_labels,
    copts = ASYLO_DEFAULT_COPTS,
    deps = ["//asylo:enclave_runtime"],
)

debug_sign_enclave(
    name = "do_nothing_enclave.so",
    backends = sgx.backend_labels,
    unsigned = "do_nothing_enclave_unsigned.so",
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

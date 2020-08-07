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

load("@bazel_skylib//:bzl_library.bzl", "bzl_library")
load("@rules_cc//cc:defs.bzl", "cc_binary", "cc_library")
load("//asylo/bazel:copts.bzl", "ASYLO_DEFAULT_COPTS")
load(":generate_end2end_tests.bzl", "grpc_end2end_tests")

licenses(["notice"])  # Apache v2.0

# Description:
#  End-to-end tests for the enclave gRPC stack.

package(
    default_visibility = ["//asylo/grpc/auth/test:__subpackages__"],
)

# A binary that packages a test fixture for the enclave gRPC stack with the
# gRPC end2end tests library.
cc_binary(
    name = "h2_enclave_security_test",
    testonly = 1,
    srcs = ["h2_enclave_security_test.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        "//asylo/grpc/auth:enclave_credentials_options",
        "//asylo/grpc/auth:null_credentials_options",
        "//asylo/grpc/auth:sgx_local_credentials_options",
        "//asylo/grpc/auth/core:grpc_security_enclave",
        "//asylo/identity:enclave_assertion_authority_config_cc_proto",
        "//asylo/identity:identity_acl_cc_proto",
        "//asylo/identity:init",
        "//asylo/identity/platform/sgx:sgx_identity_cc_proto",
        "//asylo/identity/platform/sgx:sgx_identity_util",
        "//asylo/identity/platform/sgx/internal:fake_enclave",
        "//asylo/test/util:enclave_assertion_authority_configs",
        "@com_github_grpc_grpc//:gpr_base",
        "@com_github_grpc_grpc//:grpc_codegen",
        "@com_github_grpc_grpc//:ref_counted_ptr",
        "@com_github_grpc_grpc//test/core/end2end:end2end_tests",
        "@com_github_grpc_grpc//test/core/util:grpc_test_util_base",
    ],
)

cc_library(
    name = "mock_enclave_auth_context",
    testonly = 1,
    hdrs = ["mock_enclave_auth_context.h"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        "//asylo/grpc/auth:enclave_auth_context",
        "//asylo/identity:identity_acl_cc_proto",
        "//asylo/identity:identity_cc_proto",
        "//asylo/util:status",
        "@com_google_googletest//:gtest",
    ],
)

# Generates rules for gRPC end2end tests.
#
# An end2end test target looks like this:
#   h2_enclave_security_test@<TEST_NAME>
#
# See END2END_TESTS in generate_end2end_tests.bzl for the test names that are
# supported.
grpc_end2end_tests()

bzl_library(
    name = "generate_end2end_tests_bzl",
    srcs = ["generate_end2end_tests.bzl"],
    visibility = ["//asylo:implementation"],
)

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
load("@rules_cc//cc:defs.bzl", "cc_library")
load(
    "//asylo/bazel:asylo.bzl",
    "cc_test",
)
load("//asylo/bazel:copts.bzl", "ASYLO_DEFAULT_COPTS")

licenses(["notice"])

# Description:
#   This package contains C++ components provided for users of the enclave gRPC
#   stack, including:
#     * Channel and server credentials objects
#     * Assertion generator and verifier interfaces
#     * Null assertion libraries
package(default_visibility = ["//asylo:__subpackages__"])

# gRPC channel and server credentials objects.
cc_library(
    name = "grpc++_security_enclave",
    srcs = [
        "enclave_channel_credentials.cc",
        "enclave_server_credentials.cc",
    ],
    hdrs = [
        "enclave_channel_credentials.h",
        "enclave_credentials_options.h",
        "enclave_server_credentials.h",
    ],
    copts = ASYLO_DEFAULT_COPTS,
    visibility = ["//visibility:public"],
    deps = [
        "//asylo/grpc/auth/core:grpc_security_enclave",
        "//asylo/identity:assertion_description_util",
        "//asylo/identity:identity_acl_cc_proto",
        "//asylo/identity:identity_cc_proto",
        "@com_github_grpc_grpc//:grpc++",
        "@com_google_absl//absl/types:optional",
    ],
)

cc_library(
    name = "enclave_credentials_options",
    srcs = ["enclave_credentials_options.cc"],
    hdrs = ["enclave_credentials_options.h"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        "//asylo/identity:assertion_description_util",
        "//asylo/identity:identity_acl_cc_proto",
        "//asylo/identity:identity_cc_proto",
        "@com_google_absl//absl/types:optional",
    ],
)

# Configuration for building null enclave credentials (used for unauthenticated gRPC
# connections).
cc_library(
    name = "null_credentials_options",
    srcs = ["null_credentials_options.cc"],
    hdrs = ["null_credentials_options.h"],
    copts = ASYLO_DEFAULT_COPTS,
    visibility = ["//visibility:public"],
    deps = [
        ":grpc++_security_enclave",
        "//asylo/identity:descriptions",
        "//asylo/identity/attestation/null:null_assertion_generator",  # alwayslink = 1
        "//asylo/identity/attestation/null:null_assertion_verifier",  # alwayslink = 1
        "//asylo/identity/attestation/null:null_identity_expectation_matcher",  # alwayslink = 1
    ],
)

# Configuration for building SGX local credentials (used for local gRPC
# connections between SGX enclaves).
cc_library(
    name = "sgx_local_credentials_options",
    srcs = ["sgx_local_credentials_options.cc"],
    hdrs = ["sgx_local_credentials_options.h"],
    copts = ASYLO_DEFAULT_COPTS,
    visibility = ["//visibility:public"],
    deps = [
        ":grpc++_security_enclave",
        "//asylo/identity:descriptions",
        "//asylo/identity/attestation/sgx:sgx_local_assertion_generator",  # alwayslink = 1
        "//asylo/identity/attestation/sgx:sgx_local_assertion_verifier",  # alwayslink = 1
        "//asylo/identity/platform/sgx:sgx_identity_expectation_matcher",  # alwayslink = 1
    ],
)

# Configurations for building remote SGX credentials based on
# Asylo's AGE.
cc_library(
    name = "peer_sgx_age_remote_credentials_options",
    srcs = ["peer_sgx_age_remote_credentials_options.cc"],
    hdrs = ["peer_sgx_age_remote_credentials_options.h"],
    copts = ASYLO_DEFAULT_COPTS,
    visibility = ["//visibility:public"],
    deps = [
        ":grpc++_security_enclave",
        "//asylo/identity:descriptions",
        "//asylo/identity/attestation/sgx:sgx_age_remote_assertion_verifier",  # alwayslink = 1
        "//asylo/identity/platform/sgx:sgx_identity_expectation_matcher",  # alwayslink = 1
    ],
)

# Configuration for building SGX AGE remote credentials (used for gRPC
# connections between SGX enclaves).
cc_library(
    name = "sgx_age_remote_credentials_options",
    srcs = [
        "peer_sgx_age_remote_credentials_options.cc",
        "sgx_age_remote_credentials_options.cc",
    ],
    hdrs = [
        "peer_sgx_age_remote_credentials_options.h",
        "sgx_age_remote_credentials_options.h",
    ],
    copts = ASYLO_DEFAULT_COPTS,
    visibility = ["//visibility:public"],
    deps = [
        ":grpc++_security_enclave",
        "//asylo/identity:descriptions",
        "//asylo/identity/attestation/sgx:sgx_age_remote_assertion_generator",  # alwayslink = 1
        "//asylo/identity/attestation/sgx:sgx_age_remote_assertion_verifier",  # alwayslink = 1
        "//asylo/identity/platform/sgx:sgx_identity_expectation_matcher",  # alwayslink = 1
    ],
)

cc_library(
    name = "enclave_auth_context",
    srcs = ["enclave_auth_context.cc"],
    hdrs = ["enclave_auth_context.h"],
    copts = ASYLO_DEFAULT_COPTS,
    visibility = ["//visibility:public"],
    deps = [
        "//asylo/grpc/auth/core:grpc_security_enclave",
        "//asylo/grpc/auth/core:handshake_cc_proto",
        "//asylo/identity:identity_acl_cc_proto",
        "//asylo/identity:identity_acl_evaluator",
        "//asylo/identity:identity_cc_proto",
        "//asylo/identity:identity_expectation_matcher",
        "//asylo/util:status",
        "@com_github_grpc_grpc//:grpc++",
        "@com_github_grpc_grpc//:grpc_secure",
        "@com_github_grpc_grpc//:tsi_interface",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/strings",
        "@com_google_protobuf//:protobuf_lite",
    ],
)

cc_test(
    name = "enclave_auth_context_test",
    srcs = ["enclave_auth_context_test.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":enclave_auth_context",
        "//asylo/grpc/auth/core:grpc_security_enclave",
        "//asylo/grpc/auth/core:handshake_cc_proto",
        "//asylo/identity:identity_cc_proto",
        "//asylo/identity:identity_expectation_matcher",
        "//asylo/platform/common:static_map",
        "//asylo/test/util:proto_matchers",
        "//asylo/test/util:status_matchers",
        "//asylo/test/util:test_main",
        "//asylo/util:status",
        "@com_github_grpc_grpc//:grpc++",
        "@com_github_grpc_grpc//:grpc_secure",
        "@com_github_grpc_grpc//:ref_counted_ptr",
        "@com_google_absl//absl/memory",
        "@com_google_absl//absl/status",
        "@com_google_googletest//:gtest",
        "@com_google_protobuf//:protobuf",
        "@com_google_protobuf//:protobuf_lite",
    ],
)

cc_test(
    name = "enclave_sgx_credentials_options_test",
    srcs = ["enclave_credentials_options_test.cc"],
    backends = sgx.backend_labels,
    copts = ASYLO_DEFAULT_COPTS,
    enclave_test_name = "enclave_sgx_credentials_options_enclave_test",
    deps = [
        ":enclave_credentials_options",
        ":null_credentials_options",
        ":sgx_local_credentials_options",
        "//asylo/identity:descriptions",
        "//asylo/identity:identity_acl_cc_proto",
        "//asylo/identity:identity_cc_proto",
        "//asylo/test/util:proto_matchers",
        "//asylo/test/util:test_main",
        "@com_google_googletest//:gtest",
    ],
)

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

# Description:
#   This package contains C++ components provided for users of the enclave gRPC
#   stack, including:
#     * Channel and server credentials objects
#     * Assertion generator and verifier interfaces
#     * Null assertion libraries
package(default_visibility = ["//asylo:__subpackages__"])

exports_files(["LICENSE"])

load("//asylo/bazel:asylo.bzl", "cc_test")
load("//asylo/bazel:copts.bzl", "ASYLO_DEFAULT_COPTS")

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
        "//asylo/grpc/auth/util:bridge_cpp_to_c",
        "//asylo/identity:assertion_description_util",
        "//asylo/identity:identity_proto_cc",
        "@com_github_grpc_grpc//:grpc++",
    ],
)

cc_library(
    name = "enclave_credentials_options",
    srcs = ["enclave_credentials_options.cc"],
    hdrs = ["enclave_credentials_options.h"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        "//asylo/identity:assertion_description_util",
        "//asylo/identity:identity_proto_cc",
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
        "//asylo/identity/null_identity:null_assertion_generator",  # alwayslink = 1
        "//asylo/identity/null_identity:null_assertion_verifier",  # alwayslink = 1
        "//asylo/identity/null_identity:null_identity_util",
    ],
)

# Configuration for building SGX local credentials (used for local gRPC
# connections between SGX enclaves).
cc_library(
    name = "sgx_local_credentials_options",
    srcs = ["sgx_local_credentials_options.cc"],
    hdrs = ["sgx_local_credentials_options.h"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":grpc++_security_enclave",
        "//asylo/identity/sgx:code_identity_util",
        "//asylo/identity/sgx:sgx_local_assertion_generator",  # alwayslink = 1
        "//asylo/identity/sgx:sgx_local_assertion_verifier",  # alwayslink = 1
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
        "//asylo/grpc/auth/core:handshake_proto_cc",
        "//asylo/identity:identity_proto_cc",
        "//asylo/util:status",
        "@com_github_grpc_grpc//:grpc++",
        "@com_github_grpc_grpc//:grpc_secure",
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
        "//asylo/grpc/auth/core:handshake_proto_cc",
        "//asylo/test/util:proto_matchers",
        "//asylo/test/util:status_matchers",
        "//asylo/test/util:test_main",
        "@com_github_grpc_grpc//:grpc++",
        "@com_github_grpc_grpc//:grpc_secure",
        "@com_google_absl//absl/memory",
        "@com_google_googletest//:gtest",
        "@com_google_protobuf//:protobuf",
        "@com_google_protobuf//:protobuf_lite",
    ],
)

cc_test(
    name = "enclave_credentials_options_test",
    srcs = ["enclave_credentials_options_test.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    enclave_test_name = "enclave_credentials_options_enclave_test",
    deps = [
        ":enclave_credentials_options",
        ":null_credentials_options",
        ":sgx_local_credentials_options",
        "//asylo/identity:identity_proto_cc",
        "//asylo/identity/null_identity:null_identity_util",
        "//asylo/identity/sgx:code_identity_util",
        "//asylo/test/util:proto_matchers",
        "//asylo/test/util:test_main",
        "@com_google_googletest//:gtest",
    ],
)

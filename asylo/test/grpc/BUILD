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

load(
    "//asylo/bazel:asylo.bzl",
    "cc_test",
    "enclave_test",
)
load("@linux_sgx//:sgx_sdk.bzl", "sgx_enclave", "sgx_enclave_configuration")
load("//asylo/bazel:proto.bzl", "asylo_grpc_proto_library")

# Service definition for testing gRPC in Asylo.
asylo_grpc_proto_library(
    name = "service_grpc_proto",
    srcs = ["service.proto"],
)

# Simple server implementation for testing.
cc_library(
    name = "messenger_server_impl",
    testonly = 1,
    hdrs = ["messenger_server_impl.h"],
    copts = ["-DPORTABLE_STATUS"],
    visibility = ["//asylo:implementation"],
    deps = [
        ":service_grpc_proto",
        "@com_github_grpc_grpc//:grpc++",
        "@com_google_absl//absl/strings",
    ],
)

# Simple client implementation for testing.
cc_library(
    name = "messenger_client_impl",
    testonly = 1,
    hdrs = ["messenger_client_impl.h"],
    visibility = ["//asylo:implementation"],
    deps = [
        ":service_grpc_proto",
        "//asylo/util:status",
        "@com_github_grpc_grpc//:grpc++",
        "@com_google_asylo//asylo/util:logging",
    ],
)

# Base implementation for a simple gRPC server in an enclave.
cc_library(
    name = "enclave_server",
    testonly = 1,
    srcs = ["enclave_server.cc"],
    hdrs = ["enclave_server.h"],
    deps = [
        ":messenger_server_impl",
        "//asylo:enclave_runtime",
        "//asylo/util:status",
    ],
)

sgx_enclave_configuration(
    name = "grpc_debug_config",
    # gRPC needs more than the default amount of heap to run. ~1.2GB.
    heap_max_size = "0x47000000",
    tcs_num = "200",
)

# Enclave with a service_proto server running.
sgx_enclave(
    name = "enclave_insecure_server.so",
    testonly = 1,
    srcs = ["enclave_insecure_server.cc"],
    config = ":grpc_debug_config",
    deps = [
        ":messenger_server_impl",
        "//asylo:enclave_runtime",
        "//asylo/grpc/util:enclave_server",
        "//asylo/util:status",
        "@com_google_absl//absl/memory",
    ],
)

# Enclave running a gRPC server backed by enclave gRPC security.
sgx_enclave(
    name = "enclave_secure_server.so",
    testonly = 1,
    srcs = ["enclave_secure_server.cc"],
    config = ":grpc_debug_config",
    deps = [
        ":messenger_server_impl",
        "//asylo/grpc/auth:grpc++_security_enclave",
        "//asylo/grpc/auth:null_credentials_options",
        "//asylo/grpc/util:enclave_server",
        "//asylo/identity:identity_proto_cc",
        "//asylo/util:status",
        "@com_google_absl//absl/memory",
    ],
)

# Test for gRPC in Asylo.
enclave_test(
    name = "enclave_insecure_server_test",
    srcs = ["enclave_insecure_server_test.cc"],
    enclave = ":enclave_insecure_server.so",
    flaky = 1,
    tags = ["regression"],
    deps = [
        ":messenger_client_impl",
        ":messenger_server_impl",
        "//asylo:enclave_client",
        "//asylo/grpc/util:enclave_server_proto_cc",
        "//asylo/test/util:enclave_test",
        "//asylo/test/util:status_matchers",
        "//asylo/test/util:test_main",
        "//asylo/util:status",
        "@com_github_grpc_grpc//:grpc++",
        "@com_google_absl//absl/memory",
        "@com_google_absl//absl/strings",
        "@com_google_googletest//:gtest",
        "@linux_sgx//:urts_inc",
    ],
)

# Test for gRPC using enclave gRPC security.
enclave_test(
    name = "enclave_secure_server_test",
    srcs = ["enclave_secure_server_test.cc"],
    enclave = ":enclave_secure_server.so",
    tags = ["regression"],
    deps = [
        ":messenger_client_impl",
        ":messenger_server_impl",
        "//asylo:enclave_client",
        "//asylo/grpc/auth:grpc++_security_enclave",
        "//asylo/grpc/auth:null_credentials_options",
        "//asylo/grpc/util:enclave_server_proto_cc",
        "//asylo/identity:enclave_assertion_authority_config_proto_cc",
        "//asylo/identity:init",
        "//asylo/test/util:enclave_test",
        "//asylo/test/util:status_matchers",
        "//asylo/test/util:test_main",
        "//asylo/util:status",
        "@com_github_grpc_grpc//:grpc++",
        "@com_google_absl//absl/memory",
        "@com_google_absl//absl/strings",
        "@com_google_googletest//:gtest",
        "@linux_sgx//:urts_inc",
    ],
)

cc_test(
    name = "channel_test",
    srcs = ["channel_test.cc"],
    enclave_test_name = "channel_enclave_test",
    tags = ["regression"],
    deps = [
        ":messenger_client_impl",
        ":messenger_server_impl",
        "//asylo/grpc/auth:grpc++_security_enclave",
        "//asylo/grpc/util:grpc_server_launcher",
        "//asylo/identity:enclave_assertion_authority_config_proto_cc",
        "//asylo/identity:init",
        "//asylo/identity/null_identity:null_identity_constants",
        "//asylo/test/util:status_matchers",
        "//asylo/test/util:test_main",
        "@com_google_absl//absl/memory",
        "@com_google_absl//absl/time",
        "@com_google_asylo//asylo/util:logging",
        "@com_google_googletest//:gtest",
    ],
)

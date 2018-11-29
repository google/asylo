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
load("@linux_sgx//:sgx_sdk.bzl", "sgx_enclave")
load(
    "//asylo/bazel:proto.bzl",
    "asylo_grpc_proto_library",
    "asylo_proto_library",
)
load("//asylo/bazel:copts.bzl", "ASYLO_DEFAULT_COPTS")

# Service definition for testing gRPC in Asylo.
asylo_grpc_proto_library(
    name = "service_grpc_proto",
    srcs = ["service.proto"],
)

# Extensions used in the gRPC client enclave implementation.
asylo_proto_library(
    name = "client_enclave_proto",
    srcs = ["client_enclave.proto"],
    deps = ["//asylo:enclave_proto"],
)

# Simple server implementation for testing.
cc_library(
    name = "messenger_server_impl",
    testonly = 1,
    hdrs = ["messenger_server_impl.h"],
    copts = ["-DPORTABLE_STATUS"] + ASYLO_DEFAULT_COPTS,
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
    copts = ASYLO_DEFAULT_COPTS,
    visibility = ["//asylo:implementation"],
    deps = [
        ":service_grpc_proto",
        "//asylo/util:logging",
        "//asylo/util:status",
        "@com_github_grpc_grpc//:grpc++",
    ],
)

# Base implementation for a simple gRPC server in an enclave.
cc_library(
    name = "enclave_server",
    testonly = 1,
    srcs = ["enclave_server.cc"],
    hdrs = ["enclave_server.h"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":messenger_server_impl",
        "//asylo:enclave_runtime",
        "//asylo/util:status",
    ],
)

# Enclave with a service_proto server running.
sgx_enclave(
    name = "enclave_insecure_server.so",
    testonly = 1,
    srcs = ["enclave_insecure_server.cc"],
    config = "//asylo/grpc/util:grpc_enclave_config",
    copts = ASYLO_DEFAULT_COPTS,
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
    config = "//asylo/grpc/util:grpc_enclave_config",
    copts = ASYLO_DEFAULT_COPTS,
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

sgx_enclave(
    name = "server_enclave.so",
    testonly = 1,
    srcs = ["server_enclave.cc"],
    config = "//asylo/grpc/util:grpc_enclave_config",
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":messenger_server_impl",
        "//asylo/grpc/auth:grpc++_security_enclave",
        "//asylo/grpc/auth:sgx_local_credentials_options",
        "//asylo/grpc/util:enclave_server",
        "//asylo/identity:identity_proto_cc",
        "//asylo/util:status",
    ],
)

sgx_enclave(
    name = "client_enclave.so",
    testonly = 1,
    srcs = ["client_enclave.cc"],
    config = "//asylo/grpc/util:grpc_enclave_config",
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":client_enclave_proto_cc",
        ":messenger_client_impl",
        "//asylo:enclave_runtime",
        "//asylo/grpc/auth:grpc++_security_enclave",
        "//asylo/grpc/auth:sgx_local_credentials_options",
        "//asylo/identity:identity_proto_cc",
        "//asylo/util:status",
        "@com_github_grpc_grpc//:grpc++",
        "@com_google_absl//absl/time",
    ],
)

# Test for gRPC in Asylo.
enclave_test(
    name = "enclave_insecure_server_test",
    srcs = ["enclave_insecure_server_test.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    enclaves = {"enclave": ":enclave_insecure_server.so"},
    flaky = 1,
    test_args = ["--enclave_path='{enclave}'"],
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
    ],
)

# Test for gRPC using enclave gRPC security.
enclave_test(
    name = "enclave_secure_server_test",
    srcs = ["enclave_secure_server_test.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    enclaves = {"enclave": ":enclave_secure_server.so"},
    test_args = ["--enclave_path='{enclave}'"],
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
    ],
)

# Test for gRPC client and gRPC server in the same enclave.
cc_test(
    name = "channel_test",
    srcs = ["channel_test.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    enclave_test_config = "//asylo/grpc/util:grpc_enclave_config",
    enclave_test_name = "channel_enclave_test",
    deps = [
        ":messenger_client_impl",
        ":messenger_server_impl",
        "//asylo/grpc/auth:grpc++_security_enclave",
        "//asylo/grpc/auth:null_credentials_options",
        "//asylo/grpc/util:grpc_server_launcher",
        "//asylo/identity:enclave_assertion_authority_config_proto_cc",
        "//asylo/identity:init",
        "//asylo/test/util:status_matchers",
        "//asylo/test/util:test_main",
        "//asylo/util:logging",
        "@com_google_absl//absl/memory",
        "@com_google_absl//absl/time",
        "@com_google_googletest//:gtest",
    ],
)

# Test for gRPC communication between two enclaves.
enclave_test(
    name = "enclave_communication_test",
    srcs = ["enclave_communication_test.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    enclaves = {
        "server_enclave": ":server_enclave.so",
        "client_enclave": ":client_enclave.so",
    },
    test_args = [
        "--server_enclave_path='{server_enclave}'",
        "--client_enclave_path='{client_enclave}'",
    ],
    deps = [
        ":client_enclave_proto_cc",
        ":messenger_server_impl",
        "//asylo:enclave_proto_cc",
        "//asylo/grpc/util:enclave_server_proto_cc",
        "//asylo/test/util:enclave_test_launcher",
        "//asylo/test/util:status_matchers",
        "//asylo/test/util:test_flags",
        "//asylo/test/util:test_main",
        "//asylo/util:status",
        "@com_google_absl//absl/strings",
        "@com_google_googletest//:gtest",
    ],
)

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

load("@com_github_grpc_grpc//bazel:cc_grpc_library.bzl", "cc_grpc_library")
load("@linux_sgx//:sgx_sdk.bzl", "sgx")
load("@rules_cc//cc:defs.bzl", "cc_library", "cc_proto_library")
load("@rules_proto//proto:defs.bzl", "proto_library")
load("//asylo/bazel:asylo.bzl", "cc_test", "cc_unsigned_enclave", "debug_sign_enclave")
load("//asylo/bazel:copts.bzl", "ASYLO_DEFAULT_COPTS")
load("//asylo/bazel:sgx_rules.bzl", "sgx_enclave_test")

licenses(["notice"])

# Service definition for testing gRPC in Asylo.
proto_library(
    name = "service_proto",
    srcs = ["service.proto"],
)

cc_proto_library(
    name = "service_cc_proto",
    deps = ["service_proto"],
)

cc_grpc_library(
    name = "service",
    srcs = [":service_proto"],
    grpc_only = True,
    deps = [":service_cc_proto"],
)

# Extensions used in the gRPC client enclave implementation.
proto_library(
    name = "client_enclave_proto",
    srcs = ["client_enclave.proto"],
    deps = [
        "//asylo:enclave_proto",
        "//asylo/identity:identity_acl_proto",
    ],
)

cc_proto_library(
    name = "client_enclave_cc_proto",
    visibility = ["//asylo:implementation"],
    deps = [":client_enclave_proto"],
)

# Simple server implementation for testing.
cc_library(
    name = "messenger_server_impl",
    testonly = 1,
    hdrs = ["messenger_server_impl.h"],
    copts = ["-DPORTABLE_STATUS"] + ASYLO_DEFAULT_COPTS,
    visibility = ["//asylo:implementation"],
    deps = [
        ":service",
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
        ":service",
        "//asylo/util:logging",
        "//asylo/util:status",
        "//asylo/util:status_helpers",
        "@com_github_grpc_grpc//:grpc++",
    ],
)

# Enclave with a service_proto server running.
cc_unsigned_enclave(
    name = "enclave_insecure_server_unsigned.so",
    testonly = 1,
    srcs = ["enclave_insecure_server.cc"],
    backends = sgx.backend_labels,
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":messenger_server_impl",
        "//asylo:enclave_runtime",
        "//asylo/grpc/util:enclave_server",
        "//asylo/util:status",
        "@com_github_grpc_grpc//:grpc++",
        "@com_google_absl//absl/memory",
    ],
)

debug_sign_enclave(
    name = "enclave_insecure_server.so",
    testonly = 1,
    backends = sgx.backend_labels,
    config = "//asylo/grpc/util:grpc_enclave_config",
    unsigned = "enclave_insecure_server_unsigned.so",
)

# Enclave running a gRPC server backed by enclave gRPC security.
cc_unsigned_enclave(
    name = "enclave_secure_server_unsigned.so",
    testonly = 1,
    srcs = ["enclave_secure_server.cc"],
    backends = sgx.backend_labels,
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":messenger_server_impl",
        "//asylo/grpc/auth:grpc++_security_enclave",
        "//asylo/grpc/auth:null_credentials_options",
        "//asylo/grpc/util:enclave_server",
        "//asylo/identity:identity_cc_proto",
        "//asylo/util:status",
        "@com_github_grpc_grpc//:grpc++",
        "@com_google_absl//absl/memory",
    ],
)

debug_sign_enclave(
    name = "enclave_secure_server.so",
    testonly = 1,
    backends = sgx.backend_labels,
    config = "//asylo/grpc/util:grpc_enclave_config",
    unsigned = "enclave_secure_server_unsigned.so",
)

cc_unsigned_enclave(
    name = "server_enclave_unsigned.so",
    testonly = 1,
    srcs = ["server_enclave.cc"],
    backends = sgx.backend_labels,
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":messenger_server_impl",
        "//asylo/grpc/auth:grpc++_security_enclave",
        "//asylo/grpc/auth:sgx_local_credentials_options",
        "//asylo/grpc/util:enclave_server",
        "//asylo/identity:identity_cc_proto",
        "@com_google_absl//absl/memory",
    ],
)

debug_sign_enclave(
    name = "server_enclave.so",
    testonly = 1,
    backends = sgx.backend_labels,
    config = "//asylo/grpc/util:grpc_enclave_config",
    unsigned = "server_enclave_unsigned.so",
)

cc_unsigned_enclave(
    name = "client_enclave_unsigned.so",
    testonly = 1,
    srcs = [
        "client_enclave.cc",
        "client_enclave.h",
    ],
    backends = sgx.backend_labels,
    copts = ASYLO_DEFAULT_COPTS,
    visibility = ["//visibility:private"],
    deps = [
        ":client_enclave_cc_proto",
        ":messenger_client_impl",
        "//asylo:enclave_cc_proto",
        "//asylo:enclave_runtime",
        "//asylo/grpc/auth:grpc++_security_enclave",
        "//asylo/grpc/auth:null_credentials_options",
        "//asylo/grpc/auth:sgx_age_remote_credentials_options",
        "//asylo/grpc/auth:sgx_local_credentials_options",
        "//asylo/identity:identity_cc_proto",
        "//asylo/util:status",
        "@com_github_grpc_grpc//:gpr",
        "@com_github_grpc_grpc//:gpr_codegen",
        "@com_github_grpc_grpc//:grpc++",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/time",
    ],
)

debug_sign_enclave(
    name = "client_enclave.so",
    testonly = 1,
    backends = sgx.backend_labels,
    config = "//asylo/grpc/util:grpc_enclave_config",
    unsigned = "client_enclave_unsigned.so",
    visibility = ["//asylo:implementation"],
)

# Test for gRPC in Asylo.
sgx_enclave_test(
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
        "//asylo/grpc/util:enclave_server_cc_proto",
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
sgx_enclave_test(
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
        "//asylo/grpc/util:enclave_server_cc_proto",
        "//asylo/identity:init",
        "//asylo/test/util:enclave_assertion_authority_configs",
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
        "//asylo/identity:enclave_assertion_authority_config_cc_proto",
        "//asylo/identity:init",
        "//asylo/test/util:enclave_assertion_authority_configs",
        "//asylo/test/util:status_matchers",
        "//asylo/test/util:test_main",
        "//asylo/util:logging",
        "@com_google_absl//absl/memory",
        "@com_google_absl//absl/time",
        "@com_google_googletest//:gtest",
    ],
)

# Test for gRPC communication between two enclaves.
sgx_enclave_test(
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
        ":client_enclave_cc_proto",
        ":messenger_server_impl",
        "//asylo:enclave_cc_proto",
        "//asylo/grpc/util:enclave_server_cc_proto",
        "//asylo/test/util:enclave_assertion_authority_configs",
        "//asylo/test/util:enclave_test_launcher",
        "//asylo/test/util:status_matchers",
        "//asylo/test/util:test_flags",
        "//asylo/test/util:test_main",
        "//asylo/util:status",
        "@com_google_absl//absl/flags:flag",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/strings",
        "@com_google_googletest//:gtest",
    ],
)

cc_library(
    name = "client_side_auth_test_constants",
    testonly = 1,
    srcs = ["client_side_auth_test_constants.cc"],
    hdrs = ["client_side_auth_test_constants.h"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        "//asylo/crypto:sha256_hash_cc_proto",
        "//asylo/identity/platform/sgx:architecture_bits",
        "//asylo/identity/platform/sgx:attributes_cc_proto",
        "//asylo/identity/platform/sgx:code_identity_cc_proto",
        "//asylo/identity/platform/sgx:sgx_identity_cc_proto",
        "//asylo/identity/platform/sgx:sgx_identity_util",
        "//asylo/identity/platform/sgx/internal:hardware_types",
        "//asylo/util:proto_parse_util",
        "//asylo/util:status",
        "//asylo/util:status_macros",
        "@linux_sgx//:debug_key_mrsigner",
    ],
)

sgx.enclave_configuration(
    name = "client_side_auth_test_enclave_config",
    base = "//asylo/grpc/util:grpc_enclave_config",
    isvsvn = "2",
    prodid = "1",
)

debug_sign_enclave(
    name = "client_side_auth_server_enclave.so",
    testonly = 1,
    backends = sgx.backend_labels,
    config = ":client_side_auth_test_enclave_config",
    unsigned = ":server_enclave_unsigned.so",
)

# Test for client-side gRPC authorization.
sgx_enclave_test(
    name = "client_side_authorization_test",
    srcs = ["client_side_authorization_test.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    enclaves = {
        "client_enclave": ":client_enclave.so",
        "server_enclave": ":client_side_auth_server_enclave.so",
    },
    test_args = [
        "--client_enclave_path='{client_enclave}'",
        "--server_enclave_path='{server_enclave}'",
    ],
    deps = [
        ":client_enclave_cc_proto",
        ":client_side_auth_test_constants",
        ":messenger_server_impl",
        "//asylo:enclave_cc_proto",
        "//asylo:enclave_client",
        "//asylo/crypto:sha256_hash_cc_proto",
        "//asylo/grpc/util:enclave_server_cc_proto",
        "//asylo/identity:identity_acl_cc_proto",
        "//asylo/identity/platform/sgx:code_identity_cc_proto",
        "//asylo/identity/platform/sgx:sgx_identity_cc_proto",
        "//asylo/identity/platform/sgx:sgx_identity_util",
        "//asylo/test/util:enclave_assertion_authority_configs",
        "//asylo/test/util:status_matchers",
        "//asylo/test/util:test_main",
        "//asylo/util:status",
        "@com_google_absl//absl/flags:flag",
        "@com_google_absl//absl/status",
        "@com_google_googletest//:gtest",
        "@com_google_protobuf//:protobuf",
    ],
)

cc_unsigned_enclave(
    name = "sgx_age_remote_server_enclave_unsigned.so",
    testonly = 1,
    srcs = ["sgx_age_remote_server_enclave.cc"],
    backends = sgx.backend_labels,
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":messenger_server_impl",
        "//asylo/grpc/auth:grpc++_security_enclave",
        "//asylo/grpc/auth:null_credentials_options",
        "//asylo/grpc/auth:sgx_age_remote_credentials_options",
        "//asylo/grpc/util:enclave_server",
        "//asylo/identity:identity_cc_proto",
        "@com_google_absl//absl/memory",
    ],
)

debug_sign_enclave(
    name = "sgx_age_remote_server_enclave.so",
    testonly = 1,
    backends = sgx.backend_labels,
    config = ":client_side_auth_test_enclave_config",
    unsigned = ":sgx_age_remote_server_enclave_unsigned.so",
)

# Test for SGX AGE remote attestation.
sgx_enclave_test(
    name = "sgx_age_remote_server_enclave_test",
    srcs = ["sgx_age_remote_server_enclave_test.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    enclaves = {
        "client_enclave": ":client_enclave.so",
        "server_enclave": ":sgx_age_remote_server_enclave.so",
        "age_enclave": "//asylo/identity/attestation/sgx/internal:remote_assertion_generator_enclave_no_flc.so",
    },
    test_args = [
        "--enclave_path='{server_enclave}'",
        "--client_enclave_path='{client_enclave}'",
        "--age_path='{age_enclave}'",
    ],
    deps = [
        ":client_enclave_cc_proto",
        ":client_side_auth_test_constants",
        ":messenger_client_impl",
        ":messenger_server_impl",
        "//asylo:enclave_cc_proto",
        "//asylo:enclave_client",
        "//asylo/crypto:certificate_cc_proto",
        "//asylo/grpc/auth:grpc++_security_enclave",
        "//asylo/grpc/auth:null_credentials_options",
        "//asylo/grpc/auth:peer_sgx_age_remote_credentials_options",
        "//asylo/grpc/util:enclave_server_cc_proto",
        "//asylo/identity:init",
        "//asylo/identity/attestation/sgx/internal:fake_pce",
        "//asylo/identity/attestation/sgx/internal:sgx_infrastructural_enclave_manager",
        "//asylo/identity/platform/sgx:sgx_identity_util",
        "//asylo/identity/provisioning/sgx/internal:fake_sgx_pki",
        "//asylo/test/util:enclave_assertion_authority_configs",
        "//asylo/test/util:enclave_test",
        "//asylo/test/util:enclave_test_launcher",
        "//asylo/test/util:status_matchers",
        "//asylo/test/util:test_main",
        "//asylo/util:status",
        "//asylo/util:status_macros",
        "@com_google_absl//absl/flags:flag",
        "@com_google_absl//absl/memory",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/time",
        "@com_google_googletest//:gtest",
    ],
)

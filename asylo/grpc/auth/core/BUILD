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

load("@rules_cc//cc:defs.bzl", "cc_library", "cc_proto_library")
load("@rules_proto//proto:defs.bzl", "proto_library")

# Used to selectively enable gtest tests to run inside an enclave.
load("//asylo/bazel:asylo.bzl", "cc_test")
load("//asylo/bazel:copts.bzl", "ASYLO_DEFAULT_COPTS")

licenses(["notice"])  # Apache v2.0

# Description:
#   This package provides an implementation of gRPC security components for the
#   enclave gRPC security stack.

package(default_visibility = [
    "//asylo/grpc/auth:__subpackages__",
])

# Implementation of credentials, security connectors, and transport security
# interface (TSI) for enclave gRPC security stack.
cc_library(
    name = "grpc_security_enclave",
    srcs = [
        "enclave_credentials.cc",
        "enclave_security_connector.cc",
        "enclave_transport_security.cc",
    ],
    hdrs = [
        "enclave_credentials.h",
        "enclave_grpc_security_constants.h",
        "enclave_security_connector.h",
        "enclave_transport_security.h",
    ],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":client_ekep_handshaker",
        ":ekep_handshaker",
        ":ekep_handshaker_util",
        ":handshake_cc_proto",
        ":server_ekep_handshaker",
        "//asylo/grpc/auth:enclave_credentials_options",
        "//asylo/identity:identity_acl_cc_proto",
        "//asylo/identity:identity_acl_evaluator",
        "//asylo/identity:identity_cc_proto",
        "//asylo/identity:identity_expectation_matcher",
        "//asylo/util:cleansing_types",
        "//asylo/util:logging",
        "//asylo/util:status",
        "@com_github_grpc_grpc//:alts_frame_protector",
        "@com_github_grpc_grpc//:gpr_base",
        "@com_github_grpc_grpc//:grpc_base_c",
        "@com_github_grpc_grpc//:grpc_secure",
        "@com_github_grpc_grpc//:ref_counted_ptr",
        "@com_github_grpc_grpc//:tsi_interface",
        "@com_google_absl//absl/memory",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/types:optional",
        "@com_google_absl//absl/types:span",
        "@com_google_protobuf//:protobuf_lite",
    ],
)

# Utility for managing hashed EKEP transcripts.
cc_library(
    name = "transcript",
    srcs = ["transcript.cc"],
    hdrs = ["transcript.h"],
    copts = ASYLO_DEFAULT_COPTS,
    visibility = ["//visibility:private"],
    deps = [
        "//asylo/crypto:hash_interface",
        "//asylo/crypto/util:byte_container_util",
        "//asylo/util:status",
        "@com_google_protobuf//:protobuf_lite",
    ],
)

# Tests for EKEP transcripts.
cc_test(
    name = "transcript_test",
    srcs = ["transcript_test.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    enclave_test_name = "transcript_enclave_test",
    deps = [
        ":transcript",
        "//asylo/crypto:hash_interface",
        "//asylo/crypto:sha256_hash",
        "//asylo/crypto/util:byte_container_view",
        "//asylo/test/util:status_matchers",
        "//asylo/test/util:test_main",
        "//asylo/util:status",
        "@com_google_absl//absl/memory",
        "@com_google_absl//absl/status",
        "@com_google_googletest//:gtest",
        "@com_google_protobuf//:protobuf_lite",
    ],
)

cc_library(
    name = "ekep_error_matchers",
    testonly = 1,
    srcs = ["ekep_error_matchers.cc"],
    hdrs = ["ekep_error_matchers.h"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":ekep_errors",
        ":handshake_cc_proto",
        "//asylo/test/util:status_matchers",
        "//asylo/util:proto_enum_util",
        "//asylo/util:status",
        "@com_google_absl//absl/types:optional",
        "@com_google_googletest//:gtest",
    ],
)

# Error functions for EKEP Abort errors.
cc_library(
    name = "ekep_errors",
    srcs = ["ekep_errors.cc"],
    hdrs = ["ekep_errors.h"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":handshake_cc_proto",
        "//asylo/util:status",
        "//asylo/util:status_helpers",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/strings:cord",
        "@com_google_absl//absl/types:optional",
    ],
)

# Tests for the EKEP error functions.
cc_test(
    name = "ekep_errors_test",
    srcs = ["ekep_errors_test.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    enclave_test_name = "ekep_errors_enclave_test",
    deps = [
        ":ekep_error_matchers",
        ":ekep_errors",
        ":handshake_cc_proto",
        "//asylo/test/util:status_matchers",
        "//asylo/test/util:test_main",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/types:optional",
        "@com_google_googletest//:gtest",
    ],
)

# Implementation of EKEP cryptographic operations.
cc_library(
    name = "ekep_crypto",
    srcs = ["ekep_crypto.cc"],
    hdrs = ["ekep_crypto.h"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":ekep_errors",
        ":handshake_cc_proto",
        "//asylo/crypto:sha256_hash",
        "//asylo/crypto/util:bssl_util",
        "//asylo/crypto/util:byte_container_view",
        "//asylo/util:cleansing_types",
        "//asylo/util:logging",
        "//asylo/util:proto_enum_util",
        "//asylo/util:status",
        "@boringssl//:crypto",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/strings",
    ],
)

# Tests for the EKEP crypto library.
cc_test(
    name = "ekep_crypto_test",
    srcs = ["ekep_crypto_test.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    enclave_test_name = "ekep_crypto_enclave_test",
    deps = [
        ":ekep_crypto",
        ":ekep_error_matchers",
        ":handshake_cc_proto",
        "//asylo/crypto:sha256_hash",
        "//asylo/crypto/util:bytes",
        "//asylo/crypto/util:trivial_object_util",
        "//asylo/test/util:status_matchers",
        "//asylo/test/util:test_main",
        "@boringssl//:crypto",
        "@com_google_googletest//:gtest",
    ],
)

# Implementation of the Enclave Key Exchange Protocol (EKEP) handshake.
cc_library(
    name = "ekep_handshaker",
    srcs = ["ekep_handshaker.cc"],
    hdrs = ["ekep_handshaker.h"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":ekep_crypto",
        ":ekep_errors",
        ":handshake_cc_proto",
        ":transcript",
        "//asylo/crypto:hash_interface",
        "//asylo/crypto/util:bssl_util",
        "//asylo/crypto/util:byte_container_view",
        "//asylo/grpc/auth/util:multi_buffer_input_stream",
        "//asylo/identity:identity_cc_proto",
        "//asylo/util:cleansing_types",
        "//asylo/util:logging",
        "//asylo/util:proto_enum_util",
        "//asylo/util:status",
        "@com_google_absl//absl/memory",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/strings",
        "@com_google_protobuf//:protobuf",
        "@com_google_protobuf//:protobuf_lite",
    ],
)

# Server implementation of EkepHandshaker.
cc_library(
    name = "server_ekep_handshaker",
    srcs = ["server_ekep_handshaker.cc"],
    hdrs = ["server_ekep_handshaker.h"],
    copts = ASYLO_DEFAULT_COPTS,
    visibility = ["//asylo:implementation"],
    deps = [
        ":ekep_crypto",
        ":ekep_errors",
        ":ekep_handshaker",
        ":ekep_handshaker_util",
        ":handshake_cc_proto",
        "//asylo/crypto:sha256_hash",
        "//asylo/identity:identity_cc_proto",
        "//asylo/util:cleansing_types",
        "//asylo/util:logging",
        "//asylo/util:proto_enum_util",
        "//asylo/util:status",
        "@boringssl//:crypto",
        "@com_google_absl//absl/memory",
        "@com_google_absl//absl/status",
        "@com_google_protobuf//:protobuf",
    ],
)

# Client implementation of EkepHandshaker.
cc_library(
    name = "client_ekep_handshaker",
    srcs = ["client_ekep_handshaker.cc"],
    hdrs = ["client_ekep_handshaker.h"],
    copts = ASYLO_DEFAULT_COPTS,
    visibility = ["//asylo:implementation"],
    deps = [
        ":ekep_crypto",
        ":ekep_errors",
        ":ekep_handshaker",
        ":ekep_handshaker_util",
        ":handshake_cc_proto",
        "//asylo/crypto:sha256_hash",
        "//asylo/identity:identity_cc_proto",
        "//asylo/util:cleansing_types",
        "//asylo/util:logging",
        "//asylo/util:proto_enum_util",
        "//asylo/util:status",
        "@boringssl//:crypto",
        "@com_google_absl//absl/memory",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/strings",
        "@com_google_protobuf//:protobuf",
    ],
)

# Utilities used by EkepHandshaker implementations.
cc_library(
    name = "ekep_handshaker_util",
    srcs = ["ekep_handshaker_util.cc"],
    hdrs = ["ekep_handshaker_util.h"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":ekep_handshaker",
        "//asylo/identity:enclave_assertion_authority",
        "//asylo/identity:identity_cc_proto",
        "//asylo/identity/attestation:enclave_assertion_generator",
        "//asylo/identity/attestation:enclave_assertion_verifier",
        "//asylo/util:status",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/strings",
        "@com_google_protobuf//:protobuf",
    ],
)

# Tests for EKEP handshaker utility functions.
cc_test(
    name = "ekep_handshaker_util_test",
    srcs = ["ekep_handshaker_util_test.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    enclave_test_name = "ekep_handshaker_util_enclave_test",
    deps = [
        ":ekep_handshaker",
        ":ekep_handshaker_util",
        "//asylo/identity:descriptions",
        "//asylo/identity:identity_cc_proto",
        "//asylo/identity/attestation/null:null_assertion_generator",
        "//asylo/identity/attestation/null:null_assertion_verifier",
        "//asylo/identity/attestation/null:null_identity_util",
        "//asylo/test/util:status_matchers",
        "//asylo/test/util:test_main",
        "@com_google_googletest//:gtest",
    ],
)

# Definition of Enclave Key Exchange Protocol (EKEP) handshake messages.
proto_library(
    name = "handshake_proto",
    srcs = ["handshake.proto"],
    deps = ["//asylo/identity:identity_proto"],
)

cc_proto_library(
    name = "handshake_cc_proto",
    deps = [":handshake_proto"],
)

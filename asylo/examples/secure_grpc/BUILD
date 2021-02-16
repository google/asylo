#
# Copyright 2019 Asylo authors
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
load("@rules_cc//cc:defs.bzl", "cc_library", "cc_proto_library")
load("@rules_proto//proto:defs.bzl", "proto_library")
load(
    "//asylo/bazel:asylo.bzl",
    "ASYLO_ALL_BACKEND_TAGS",
    "cc_unsigned_enclave",
    "debug_sign_enclave",
    "enclave_loader",
    "enclave_test",
)
load("//asylo/bazel:copts.bzl", "ASYLO_DEFAULT_COPTS")

licenses(["notice"])  # Apache v2.0

# Example demonstrating secure gRPC in Asylo.

# The implementation of the translation server.
cc_library(
    name = "translator_server_impl",
    srcs = ["translator_server_impl.cc"],
    hdrs = ["translator_server_impl.h"],
    copts = ASYLO_DEFAULT_COPTS,
    tags = ASYLO_ALL_BACKEND_TAGS,
    deps = [
        "//asylo/examples/grpc_server:translator_server",
        "//asylo/grpc/auth:enclave_auth_context",
        "//asylo/identity:descriptions",
        "//asylo/identity:identity_acl_cc_proto",
        "@com_github_grpc_grpc//:grpc++",
        "@com_google_absl//absl/base:core_headers",
        "@com_google_absl//absl/container:flat_hash_map",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/synchronization",
    ],
)

# Contains extensions to enclave protos.
proto_library(
    name = "grpc_server_config_proto",
    srcs = ["grpc_server_config.proto"],
    deps = [
        "//asylo:enclave_proto",
        "//asylo/identity/platform/sgx:sgx_identity_proto",
    ],
)

cc_proto_library(
    name = "grpc_server_config_cc_proto",
    deps = [":grpc_server_config_proto"],
)

# Extensions used in the gRPC client enclave implementation.
proto_library(
    name = "grpc_client_enclave_proto",
    srcs = ["grpc_client_enclave.proto"],
    deps = [
        "//asylo:enclave_proto",
        "//asylo/examples/grpc_server:translator_server_proto",
    ],
)

cc_proto_library(
    name = "grpc_client_enclave_cc_proto",
    deps = [":grpc_client_enclave_proto"],
)

_grpc_server_sgx_deps = [
    "//asylo/identity/platform/sgx:sgx_identity_cc_proto",
    "//asylo/identity/platform/sgx:sgx_identity_expectation_matcher",
    "//asylo/identity/platform/sgx:sgx_identity_util",
]

# The enclave hosting the translation server.
cc_unsigned_enclave(
    name = "grpc_server_enclave_unsigned.so",
    srcs = ["grpc_server_enclave.cc"],
    backends = sgx.backend_labels,  # Has SGX identity dependencies
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":grpc_server_config_cc_proto",
        ":translator_server_impl",
        "@com_google_absl//absl/base:core_headers",
        "@com_google_absl//absl/memory",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/synchronization",
        "//asylo:enclave_runtime",
        "//asylo/examples/grpc_server:grpc_server_config_cc_proto",
        "//asylo/grpc/auth:grpc++_security_enclave",
        "//asylo/grpc/auth:sgx_local_credentials_options",
        "//asylo/identity:identity_acl_cc_proto",
        "//asylo/util:status",
        "@com_github_grpc_grpc//:grpc++",
        "@com_github_grpc_grpc//:grpc++_reflection",
    ] + select(
        {
            "@linux_sgx//:sgx_hw": _grpc_server_sgx_deps,
            "@linux_sgx//:sgx_sim": _grpc_server_sgx_deps,
        },
        no_match_error = "The grpc server enclave is only configured for SGX backends",
    ),
)

sgx.enclave_configuration(
    name = "grpc_client_config",
    base = "//asylo/grpc/util:grpc_enclave_config",
    isvsvn = "1",
    prodid = "2",
)

debug_sign_enclave(
    name = "grpc_server_enclave.so",
    backends = sgx.backend_labels,
    config = "//asylo/grpc/util:grpc_enclave_config",
    unsigned = ":grpc_server_enclave_unsigned.so",
)

cc_unsigned_enclave(
    name = "grpc_client_enclave_unsigned.so",
    srcs = [
        "grpc_client_enclave.cc",
        "grpc_client_enclave.h",
    ],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":grpc_client_enclave_cc_proto",
        "//asylo:enclave_runtime",
        "//asylo/examples/grpc_server:translator_server",
        "//asylo/grpc/auth:grpc++_security_enclave",
        "//asylo/grpc/auth:null_credentials_options",
        "//asylo/grpc/auth:sgx_local_credentials_options",
        "//asylo/util:status",
        "@com_github_grpc_grpc//:grpc++",
        "@com_google_absl//absl/time",
    ],
)

debug_sign_enclave(
    name = "grpc_client_enclave.so",
    backends = sgx.backend_labels,
    config = ":grpc_client_config",
    unsigned = ":grpc_client_enclave_unsigned.so",
)

cc_library(
    name = "grpc_server_util",
    srcs = ["grpc_server_util.cc"],
    hdrs = ["grpc_server_util.h"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":attestation_domain",
        ":grpc_server_config_cc_proto",
        "//asylo:enclave_cc_proto",
        "//asylo:enclave_client",
        "//asylo/examples/grpc_server:grpc_server_config_cc_proto",
        "//asylo/identity:enclave_assertion_authority_config_cc_proto",
        "//asylo/identity:enclave_assertion_authority_configs",
        "//asylo/identity/platform/sgx:sgx_identity_cc_proto",
        "//asylo/platform/primitives/sgx:loader_cc_proto",
        "//asylo/util:status",
        "@com_google_absl//absl/strings",
        "@com_google_protobuf//:protobuf",
    ],
)

# The driver for the gRPC server enclave.
enclave_loader(
    name = "grpc_server",
    srcs = ["grpc_server_main.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    enclaves = {"enclave": ":grpc_server_enclave.so"},
    loader_args = ["--enclave_path='{enclave}'"],
    deps = [
        ":grpc_server_util",
        "//asylo:enclave_client",
        "//asylo/identity/platform/sgx:sgx_identity_cc_proto",
        "//asylo/util:logging",
        "//asylo/util:proto_flag",
        "//asylo/util:status",
        "@com_google_absl//absl/flags:flag",
        "@com_google_absl//absl/flags:parse",
        "@com_google_absl//absl/time",
        "@com_google_protobuf//:protobuf",
    ],
)

cc_library(
    name = "grpc_client_util",
    srcs = ["grpc_client_util.cc"],
    hdrs = ["grpc_client_util.h"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":attestation_domain",
        ":grpc_client_enclave_cc_proto",
        "//asylo:enclave_cc_proto",
        "//asylo:enclave_client",
        "//asylo/examples/grpc_server:translator_server",
        "//asylo/identity:enclave_assertion_authority_config_cc_proto",
        "//asylo/identity:enclave_assertion_authority_configs",
        "//asylo/platform/primitives/sgx:loader_cc_proto",
        "//asylo/util:status",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/strings",
    ],
)

cc_library(
    name = "attestation_domain",
    srcs = ["attestation_domain.cc"],
    hdrs = ["attestation_domain.h"],
)

enclave_loader(
    name = "grpc_client",
    srcs = ["grpc_client_main.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    enclaves = {"enclave": ":grpc_client_enclave.so"},
    loader_args = ["--enclave_path='{enclave}'"],
    deps = [
        ":grpc_client_enclave_cc_proto",
        ":grpc_client_util",
        "//asylo:enclave_client",
        "//asylo/util:logging",
        "//asylo/util:status",
        "@com_google_absl//absl/flags:flag",
        "@com_google_absl//absl/flags:parse",
        "@com_google_absl//absl/strings",
        "@com_google_protobuf//:protobuf",
    ],
)

# A test of the example using the client enclave and the server enclave.
enclave_test(
    name = "secure_grpc_test",
    srcs = ["secure_grpc_test.cc"],
    backends = sgx.backend_labels,
    copts = ASYLO_DEFAULT_COPTS,
    data = [
        ":acl_isvprodid_2.textproto",
        ":acl_isvprodid_3.textproto",
        ":acl_non_debug.textproto",
    ],
    enclaves = {
        "server_enclave": ":grpc_server_enclave.so",
        "client_enclave": ":grpc_client_enclave.so",
    },
    test_args = [
        "--server_enclave_path='{server_enclave}'",
        "--client_enclave_path='{client_enclave}'",
        "--acl_isvprodid_2_path=$(rootpath :acl_isvprodid_2.textproto)",
        "--acl_isvprodid_3_path=$(rootpath :acl_isvprodid_3.textproto)",
        "--acl_non_debug_path=$(rootpath :acl_non_debug.textproto)",
    ],
    deps = [
        ":grpc_client_util",
        ":grpc_server_util",
        ":translator_server_impl",
        "//asylo:enclave_client",
        "//asylo/identity/platform/sgx:sgx_identity_cc_proto",
        "//asylo/test/util:status_matchers",
        "//asylo/test/util:test_main",
        "//asylo/util:status",
        "@com_github_grpc_grpc//:grpc++",
        "@com_google_absl//absl/base:core_headers",
        "@com_google_absl//absl/flags:flag",
        "@com_google_absl//absl/memory",
        "@com_google_absl//absl/strings",
        "@com_google_googletest//:gtest",
        "@com_google_protobuf//:protobuf",
    ],
)

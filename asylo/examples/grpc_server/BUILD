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

# Example demonstrating gRPC in Asylo.

package(
    default_visibility = ["//visibility:public"],
)

# The generated code for the translator server (and client).
proto_library(
    name = "translator_server_proto",
    srcs = ["translator_server.proto"],
    tags = ASYLO_ALL_BACKEND_TAGS,
)

cc_proto_library(
    name = "translator_server_cc_proto",
    tags = ASYLO_ALL_BACKEND_TAGS,
    deps = [":translator_server_proto"],
)

cc_grpc_library(
    name = "translator_server",
    srcs = [":translator_server_proto"],
    grpc_only = True,
    tags = ASYLO_ALL_BACKEND_TAGS,
    deps = [":translator_server_cc_proto"],
)

# The implementation of the translation server.
cc_library(
    name = "translator_server_impl",
    srcs = ["translator_server_impl.cc"],
    hdrs = ["translator_server_impl.h"],
    copts = ASYLO_DEFAULT_COPTS,
    tags = ASYLO_ALL_BACKEND_TAGS,
    deps = [
        ":translator_server",
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
    deps = ["//asylo:enclave_proto"],
)

cc_proto_library(
    name = "grpc_server_config_cc_proto",
    deps = [":grpc_server_config_proto"],
)

# The enclave hosting the translation server.
cc_unsigned_enclave(
    name = "grpc_server_enclave_unsigned.so",
    srcs = ["grpc_server_enclave.cc"],
    backends = sgx.backend_labels,
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":grpc_server_config_cc_proto",
        ":translator_server_impl",
        "//asylo:enclave_runtime",
        "//asylo/util:status",
        "@com_github_grpc_grpc//:grpc++",
        "@com_github_grpc_grpc//:grpc++_reflection",
        "@com_google_absl//absl/base:core_headers",
        "@com_google_absl//absl/memory",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/synchronization",
        "@com_google_absl//absl/time",
    ],
)

debug_sign_enclave(
    name = "grpc_server_enclave.so",
    backends = sgx.backend_labels,
    config = "//asylo/grpc/util:grpc_enclave_config",
    unsigned = "grpc_server_enclave_unsigned.so",
)

# The driver for the gRPC server enclave.
enclave_loader(
    name = "grpc_server",
    srcs = ["grpc_server_driver.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    enclaves = {"enclave": ":grpc_server_enclave.so"},
    loader_args = ["--enclave_path='{enclave}'"],
    deps = [
        ":grpc_server_util",
        "//asylo:enclave_client",
        "//asylo/util:logging",
        "//asylo/util:status",
        "@com_google_absl//absl/flags:flag",
        "@com_google_absl//absl/flags:parse",
        "@com_google_absl//absl/time",
    ],
)

cc_library(
    name = "grpc_server_util",
    srcs = ["grpc_server_util.cc"],
    hdrs = ["grpc_server_util.h"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":grpc_server_config_cc_proto",
        "//asylo:enclave_cc_proto",
        "//asylo:enclave_client",
        "//asylo/platform/primitives/sgx:loader_cc_proto",
        "//asylo/util:status",
        "@com_google_absl//absl/strings",
        "@com_google_protobuf//:protobuf",
    ],
)

# A test of the example using the server enclave.
enclave_test(
    name = "grpc_server_test",
    srcs = ["grpc_server_test.cc"],
    backend_dependent_data = [":grpc_server_host_loader"],
    backends = sgx.backend_labels,
    copts = ASYLO_DEFAULT_COPTS,
    enclaves = {"server_enclave": ":grpc_server_enclave.so"},
    test_args = [
        "--server_enclave_path='{server_enclave}'",
    ],
    deps = [
        ":grpc_server_util",
        ":translator_client",
        ":translator_server_impl",
        "//asylo:enclave_client",
        "//asylo/test/util:status_matchers",
        "//asylo/test/util:test_main",
        "//asylo/util:path",
        "//asylo/util:status",
        "@com_github_grpc_grpc//:grpc++",
        "@com_google_absl//absl/base:core_headers",
        "@com_google_absl//absl/flags:flag",
        "@com_google_absl//absl/memory",
        "@com_google_absl//absl/strings",
        "@com_google_googletest//:gtest",
    ],
)

cc_library(
    name = "translator_client",
    testonly = 1,
    srcs = ["translator_client.cc"],
    hdrs = ["translator_client.h"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":translator_server",
        ":translator_server_cc_proto",
        "//asylo/util:status",
        "//asylo/util:status_helpers",
        "@com_github_grpc_grpc//:gpr",
        "@com_github_grpc_grpc//:gpr_codegen",
        "@com_github_grpc_grpc//:grpc",
        "@com_github_grpc_grpc//:grpc++",
        "@com_google_absl//absl/memory",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/time",
    ],
)

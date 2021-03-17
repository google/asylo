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

load("@linux_sgx//:sgx_sdk.bzl", "sgx_enclave_configuration")
load("@rules_cc//cc:defs.bzl", "cc_library", "cc_proto_library")
load("@rules_proto//proto:defs.bzl", "proto_library")
load("//asylo/bazel:asylo.bzl", "ASYLO_ALL_BACKEND_TAGS", "cc_test")
load("//asylo/bazel:copts.bzl", "ASYLO_DEFAULT_COPTS")

licenses(["notice"])  # Apache v2.0

# An enclave configuration that should keep up with gRPC's resource usage.
sgx_enclave_configuration(
    name = "grpc_enclave_config",
    # Allocate additional thread control structures, as we assume gRPC
    # workloads will be more heavily threaded than workloads which do not
    # use gRPC.
    tcs_num = "32",
    visibility = ["//visibility:public"],
)

# The GrpcServerLauncher library is used for launching a gRPC server that hosts
# one or more services, each on its own thread.
cc_library(
    name = "grpc_server_launcher",
    srcs = ["grpc_server_launcher.cc"],
    hdrs = ["grpc_server_launcher.h"],
    copts = ASYLO_DEFAULT_COPTS,
    visibility = ["//visibility:public"],
    deps = [
        "//asylo/util:logging",
        "//asylo/util:status",
        "@com_github_grpc_grpc//:grpc++",
        "@com_github_grpc_grpc//:grpc++_codegen_base",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/synchronization",
    ],
)

# Tests for the GrpcServerLauncher library.
cc_test(
    name = "grpc_server_launcher_test",
    size = "medium",
    srcs = ["grpc_server_launcher_test.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    enclave_test_config = ":grpc_enclave_config",
    enclave_test_name = "grpc_server_launcher_enclave_test",
    deps = [
        ":grpc_server_launcher",
        "//asylo/test/grpc:messenger_client_impl",
        "//asylo/test/grpc:messenger_server_impl",
        "//asylo/test/util:status_matchers",
        "//asylo/test/util:test_main",
        "//asylo/util:status",
        "@com_github_grpc_grpc//:grpc++",
        "@com_github_grpc_grpc//:grpc++_codegen_base",
        "@com_google_absl//absl/memory",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/time",
        "@com_google_googletest//:gtest",
    ],
)

proto_library(
    name = "enclave_server_proto",
    srcs = ["enclave_server.proto"],
    visibility = ["//visibility:public"],
    deps = ["//asylo:enclave_proto"],
)

cc_proto_library(
    name = "enclave_server_cc_proto",
    visibility = ["//visibility:public"],
    deps = [":enclave_server_proto"],
)

cc_library(
    name = "enclave_server",
    hdrs = ["enclave_server.h"],
    copts = ASYLO_DEFAULT_COPTS,
    tags = ASYLO_ALL_BACKEND_TAGS,
    visibility = ["//visibility:public"],
    deps = [
        ":enclave_server_cc_proto",
        "//asylo:enclave_runtime",
        "//asylo/util:logging",
        "//asylo/util:mutex_guarded",
        "//asylo/util:status",
        "@com_github_grpc_grpc//:grpc++",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/strings",
    ],
)

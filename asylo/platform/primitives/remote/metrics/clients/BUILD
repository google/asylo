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

# Collection of clients for proc_system_service

load("@rules_cc//cc:defs.bzl", "cc_library", "cc_test")
load("//asylo/bazel:copts.bzl", "ASYLO_DEFAULT_COPTS")

licenses(["notice"])

cc_library(
    name = "proc_system_service_client_cc",
    srcs = ["proc_system_service_client.cc"],
    hdrs = ["proc_system_service_client.h"],
    copts = ASYLO_DEFAULT_COPTS,
    visibility = ["//visibility:private"],
    deps = [
        "//asylo/platform/primitives/remote/metrics:proc_system_cc_proto",
        "//asylo/platform/primitives/remote/metrics:proc_system_grpc_proto",
        "//asylo/util:logging",
        "//asylo/util:status",
        "//asylo/util:status_helpers",
        "@com_github_grpc_grpc//:grpc++",
        "@com_github_grpc_grpc//:grpc++_codegen_base",
        "@com_google_absl//absl/status",
    ],
)

cc_test(
    name = "proc_system_service_client_test",
    size = "small",
    srcs = ["proc_system_service_client_test.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    visibility = ["//visibility:private"],
    deps = [
        ":proc_system_service_client_cc",
        "//asylo/platform/primitives/remote/metrics:proc_system_cc_proto",
        "//asylo/platform/primitives/remote/metrics:proc_system_grpc_proto",
        "//asylo/platform/primitives/remote/metrics/mocks:mock_proc_system_service",
        "//asylo/test/util:proto_matchers",
        "//asylo/test/util:status_matchers",
        "//asylo/test/util:test_main",
        "//asylo/util:asylo_macros",
        "//asylo/util:status_helpers",
        "@com_github_grpc_grpc//:grpc++",
        "@com_github_grpc_grpc//:grpc++_codegen_base",
        "@com_google_absl//absl/memory",
        "@com_google_absl//absl/status",
        "@com_google_googletest//:gtest",
    ],
)

cc_library(
    name = "opencensus_client",
    srcs = ["opencensus_client.cc"],
    hdrs = ["opencensus_client.h"],
    copts = ASYLO_DEFAULT_COPTS,
    visibility = ["//asylo:implementation"],
    deps = [
        ":opencensus_client_config",
        ":proc_system_service_client_cc",
        "//asylo/util:mutex_guarded",
        "//asylo/util:path",
        "//asylo/util:status_macros",
        "//asylo/util:thread",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/synchronization",
        "@io_opencensus_cpp//opencensus/stats",
        "@io_opencensus_cpp//opencensus/tags",
    ],
)

cc_library(
    name = "opencensus_client_config",
    hdrs = ["opencensus_client_config.h"],
    copts = ASYLO_DEFAULT_COPTS,
    visibility = ["//asylo:implementation"],
    deps = [
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/time",
    ],
)

cc_test(
    name = "opencensus_client_test",
    size = "small",
    srcs = ["opencensus_client_test.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    visibility = ["//visibility:private"],
    deps = [
        ":opencensus_client",
        ":opencensus_client_config",
        "//asylo/platform/primitives/remote/metrics/mocks:mock_proc_system_parser",
        "//asylo/platform/primitives/remote/metrics/mocks:mock_proc_system_service",
        "//asylo/platform/primitives/remote/metrics/mocks:mock_proc_system_service_server",
        "//asylo/test/util:test_main",
        "//asylo/util/remote:grpc_channel_builder",
        "//asylo/util/remote:grpc_server_main_wrapper",
        "@com_google_absl//absl/memory",
        "@com_google_absl//absl/strings",
        "@com_google_googletest//:gtest",
        "@io_opencensus_cpp//opencensus/stats",
        "@io_opencensus_cpp//opencensus/tags",
    ],
)

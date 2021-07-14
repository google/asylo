load("@com_github_grpc_grpc//bazel:cc_grpc_library.bzl", "cc_grpc_library")
load("@rules_cc//cc:defs.bzl", "cc_library", "cc_proto_library", "cc_test")
load("@rules_proto//proto:defs.bzl", "proto_library")

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
load("//asylo/bazel:copts.bzl", "ASYLO_DEFAULT_COPTS")

licenses(["notice"])  # Apache v2.0

# Proto library for transferring /proc/[pid]/stat information.
proto_library(
    name = "proc_system_proto",
    srcs = ["proc_system.proto"],
    visibility = ["//visibility:private"],
)

cc_proto_library(
    name = "proc_system_cc_proto",
    visibility = ["//asylo:implementation"],
    deps = [":proc_system_proto"],
)

cc_grpc_library(
    name = "proc_system_grpc_proto",
    srcs = ["proc_system_proto"],
    generate_mocks = True,
    grpc_only = True,
    visibility = ["//asylo:implementation"],
    deps = [":proc_system_cc_proto"],
)

cc_library(
    name = "proc_system_parser",
    srcs = ["proc_system_parser.cc"],
    hdrs = ["proc_system_parser.h"],
    copts = ASYLO_DEFAULT_COPTS,
    visibility = ["//asylo:implementation"],
    deps = [
        "//asylo/util:asylo_macros",
        "//asylo/util:cleanup",
        "//asylo/util:error_codes",
        "//asylo/util:status",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/strings:str_format",
    ],
)

cc_library(
    name = "proc_system_service",
    srcs = ["proc_system_service.cc"],
    hdrs = ["proc_system_service.h"],
    copts = ASYLO_DEFAULT_COPTS,
    visibility = ["//asylo:implementation"],
    deps = [
        ":proc_system_cc_proto",
        ":proc_system_grpc_proto",
        ":proc_system_parser",
        "//asylo/util:status",
        "//asylo/util:status_helpers",
        "@com_github_grpc_grpc//:grpc++",
        "@com_github_grpc_grpc//:grpc++_codegen_base",
        "@com_google_absl//absl/memory",
        "@com_google_absl//absl/status",
    ],
)

cc_test(
    name = "proc_system_parser_test",
    size = "small",
    srcs = ["proc_system_parser_test.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    visibility = ["//visibility:private"],
    deps = [
        ":proc_system_parser",
        "//asylo/platform/primitives/remote/metrics/mocks:mock_proc_system_parser",
        "//asylo/test/util:status_matchers",
        "//asylo/test/util:test_main",
        "//asylo/util:status",
        "@com_google_absl//absl/memory",
        "@com_google_googletest//:gtest",
    ],
)

cc_test(
    name = "proc_system_service_test",
    srcs = ["proc_system_service_test.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    visibility = ["//visibility:private"],
    deps = [
        ":proc_system_service",
        "//asylo/platform/primitives/remote/metrics/mocks:mock_proc_system_parser",
        "//asylo/platform/primitives/remote/metrics/mocks:mock_proc_system_service",
        "//asylo/test/util:status_matchers",
        "//asylo/test/util:test_main",
        "//asylo/util:status_helpers",
        "@com_google_absl//absl/memory",
        "@com_google_googletest//:gtest",
    ],
)

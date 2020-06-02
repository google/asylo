load("@rules_cc//cc:defs.bzl", "cc_library")

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

licenses(["notice"])

cc_library(
    name = "mock_proc_system_parser",
    testonly = 1,
    hdrs = ["mock_proc_system_parser.h"],
    copts = ASYLO_DEFAULT_COPTS,
    visibility = ["//asylo:implementation"],
    deps = [
        "//asylo/platform/primitives/remote/metrics:proc_system_parser",
        "//asylo/test/util:test_main",
        "@com_google_absl//absl/strings",
        "@com_google_googletest//:gtest",
    ],
)

cc_library(
    name = "mock_proc_system_service",
    testonly = 1,
    hdrs = ["mock_proc_system_service.h"],
    copts = ASYLO_DEFAULT_COPTS,
    visibility = ["//asylo:implementation"],
    deps = [
        ":mock_proc_system_parser",
        "//asylo/platform/primitives/remote/metrics:proc_system_service",
    ],
)

cc_library(
    name = "mock_proc_system_service_server",
    testonly = 1,
    srcs = ["mock_proc_system_service_server.cc"],
    hdrs = ["mock_proc_system_service_server.h"],
    copts = ASYLO_DEFAULT_COPTS,
    visibility = ["//asylo:implementation"],
    deps = [
        ":mock_proc_system_service",
        "//asylo/util:status",
        "@com_github_grpc_grpc//:grpc++",
        "@com_google_absl//absl/memory",
    ],
)

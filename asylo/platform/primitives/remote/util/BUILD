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

load("@rules_cc//cc:defs.bzl", "cc_library", "cc_test")
load("//asylo/bazel:copts.bzl", "ASYLO_DEFAULT_COPTS")

licenses(["notice"])  # Apache v2.0

cc_library(
    name = "grpc_credential_builder",
    srcs = ["grpc_credential_builder.cc"],
    hdrs = ["grpc_credential_builder.h"],
    copts = ASYLO_DEFAULT_COPTS,
    visibility = ["//asylo:implementation"],
    deps = [
        "//asylo/util:cleanup",
        "//asylo/util:logging",
        "//asylo/util:posix_errors",
        "//asylo/util:status",
        "@com_github_grpc_grpc//:grpc++",
        "@com_google_absl//absl/flags:flag",
        "@com_google_absl//absl/memory",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/strings",
    ],
)

cc_test(
    name = "grpc_credential_builder_test",
    size = "small",
    srcs = ["grpc_credential_builder_test.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":grpc_credential_builder",
        "//asylo/test/util:status_matchers",
        "//asylo/test/util:test_flags",
        "//asylo/test/util:test_main",
        "//asylo/util:cleanup",
        "//asylo/util:posix_errors",
        "//asylo/util:status",
        "@com_github_grpc_grpc//:grpc++",
        "@com_google_absl//absl/flags:flag",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/strings",
        "@com_google_googletest//:gtest",
    ],
)

cc_library(
    name = "remote_proxy_lib",
    srcs = ["remote_proxy_lib.cc"],
    hdrs = ["remote_proxy_lib.h"],
    copts = ASYLO_DEFAULT_COPTS,
    visibility = ["//asylo:implementation"],
    deps = [
        "//asylo:enclave_cc_proto",
        "//asylo/platform/primitives",
        "//asylo/platform/primitives:untrusted_primitives",
        "//asylo/platform/primitives/dlopen:untrusted_dlopen",
        "//asylo/platform/primitives/remote:communicator",
        "//asylo/platform/primitives/remote:proxy_server",
        "//asylo/platform/primitives/util:message_reader_writer",
        "//asylo/util:logging",
        "//asylo/util:status",
        "//asylo/util/remote:process_main_wrapper",
        "@com_google_absl//absl/flags:flag",
        "@com_google_absl//absl/flags:parse",
        "@com_google_absl//absl/memory",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/strings",
    ],
)

cc_library(
    name = "proxy_launcher_lib",
    srcs = ["proxy_launcher.cc"],
    hdrs = ["proxy_launcher.h"],
    visibility = ["//asylo:implementation"],
    deps = [
        ":grpc_credential_builder",
        "//asylo/util:logging",
        "//asylo/util:status",
        "@com_google_absl//absl/flags:flag",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/strings",
    ],
)

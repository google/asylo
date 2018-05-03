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

# Common utilities for trusted and untrusted targets.

load("//asylo/bazel:proto.bzl", "asylo_proto_library")
load("//asylo/bazel:copts.bzl", "ASYLO_DEFAULT_COPTS")

# Minimal logging library implementation.
cc_library(
    name = "logging",
    srcs = ["logging.cc"],
    hdrs = ["logging.h"],
    visibility = ["//visibility:public"],
    deps = ["@com_google_absl//absl/base:core_headers"],
)

cc_library(
    name = "status",
    srcs = [
        "error_space.cc",
        "error_space.h",
        "posix_error_space.cc",
        "status.cc",
        "status_error_space.cc",
        "status_error_space.h",
        "status_internal.h",
    ],
    hdrs = [
        "posix_error_space.h",
        "status.h",
        "statusor.h",
    ],
    visibility = ["//visibility:public"],
    deps =
        [
            ":status_proto_cc",
            "//asylo/platform/common:static_map",
            "@boringssl//:crypto",
            "@com_google_absl//absl/meta:type_traits",
            "@com_google_absl//absl/strings",
            "@com_google_asylo//asylo/util:logging",
        ],
)

# Tests for the Status utility.
cc_test(
    name = "status_test",
    srcs = ["status_test.cc"],
    tags = ["regression"],
    deps = [
        ":status",
        "//asylo/test/util:status_matchers",
        "//asylo/test/util:test_main",
        "@com_github_grpc_grpc//:grpc++",
        "@com_google_googletest//:gtest",
    ],
)

# Tests for the StatusOr template class.
cc_test(
    name = "statusor_test",
    srcs = [
        "error_space.h",
        "status_error_space.h",
        "statusor_test.cc",
    ],
    tags = ["regression"],
    deps = [
        ":status",
        "//asylo/platform/common:static_map",
        "//asylo/test/util:status_matchers",
        "//asylo/test/util:test_main",
        "@boringssl//:crypto",
        "@com_google_googletest//:gtest",
    ],
)

# Container types that zero-out memory before freeing resources.
cc_library(
    name = "cleansing_types",
    hdrs = [
        "cleansing_allocator.h",
        "cleansing_types.h",
    ],
    visibility = ["//visibility:public"],
    deps = ["@boringssl//:crypto"],
)

cc_test(
    name = "cleansing_allocator_test",
    srcs = [
        "cleansing_allocator.h",
        "cleansing_allocator_test.cc",
    ],
    copts = ASYLO_DEFAULT_COPTS,
    tags = ["regression"],
    deps = [
        "//asylo/identity/util:bytes",
        "//asylo/identity/util:trivial_object_util",
        "//asylo/test/util:test_main",
        "@boringssl//:crypto",
        "@com_google_googletest//:gtest",
    ],
)

# Tests for Google canonical error space.
cc_test(
    name = "error_space_test",
    srcs = [
        "error_space.h",
        "error_space_test.cc",
    ],
    tags = ["regression"],
    deps = [
        ":status",
        "//asylo/platform/common:static_map",
        "//asylo/test/util:test_main",
        "@boringssl//:crypto",
        "@com_google_googletest//:gtest",
    ],
)

# Tests for Posix error space.
cc_test(
    name = "posix_error_space_test",
    srcs = ["posix_error_space_test.cc"],
    tags = ["regression"],
    deps = [
        ":status",
        "@com_google_googletest//:gtest_main",
    ],
)

# Protobuf representation for asylo::Status.
asylo_proto_library(
    name = "status_proto",
    srcs = ["status.proto"],
    visibility = ["//visibility:public"],
)

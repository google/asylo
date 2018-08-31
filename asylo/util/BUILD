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

load("//asylo/bazel:asylo.bzl", "cc_test")
load("//asylo/bazel:proto.bzl", "asylo_proto_library")
load("//asylo/bazel:copts.bzl", "ASYLO_DEFAULT_COPTS")

# Defines ASYLO macros.
cc_library(
    name = "asylo_macros",
    hdrs = ["asylo_macros.h"],
    visibility = ["//asylo:implementation"],
)

# A library for cleanup objects.
cc_library(
    name = "cleanup",
    hdrs = ["cleanup.h"],
    visibility = ["//asylo:implementation"],
)

cc_test(
    name = "cleanup_test",
    srcs = ["cleanup_test.cc"],
    enclave_test_name = "cleanup_enclave_test",
    deps = [
        ":cleanup",
        "//asylo/test/util:test_main",
        "@com_google_googletest//:gtest",
    ],
)

# A library for memory-mapping files.
cc_library(
    name = "file_mapping",
    srcs = ["file_mapping.cc"],
    hdrs = ["file_mapping.h"],
    visibility = ["//asylo:implementation"],
    deps = [
        ":cleanup",
        ":status",
        "//asylo/util:logging",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/types:span",
    ],
)

cc_test(
    name = "file_mapping_test",
    srcs = ["file_mapping_test.cc"],
    args = ["--test_file=$(location file_mapping_test_data.txt)"],
    data = ["file_mapping_test_data.txt"],
    deps = [
        ":file_mapping",
        ":status",
        "//asylo/test/util:status_matchers",
        "//asylo/test/util:test_main",
        "@com_github_gflags_gflags//:gflags_nothreads",
        "@com_google_absl//absl/strings",
        "@com_google_googletest//:gtest",
    ],
)

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
        "status_macros.h",
        "statusor.h",
    ],
    visibility = ["//visibility:public"],
    deps =
        [
            ":status_proto_cc",
            "//asylo/platform/common:static_map",
            "//asylo/util:logging",
            "@com_google_absl//absl/base:core_headers",
            "@com_google_absl//absl/meta:type_traits",
            "@com_google_absl//absl/strings",
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

# Tests for the Status macros.
cc_test(
    name = "status_macros_test",
    srcs = ["status_macros_test.cc"],
    tags = ["regression"],
    deps = [
        ":status",
        "//asylo/test/util:status_matchers",
        "//asylo/test/util:test_main",
        "@com_google_absl//absl/memory",
        "@com_google_absl//absl/strings",
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
        "//asylo/crypto/util:bytes",
        "//asylo/crypto/util:trivial_object_util",
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
        "//asylo/test/util:test_main",
        "@com_google_googletest//:gtest",
    ],
)

# Protobuf representation for asylo::Status.
asylo_proto_library(
    name = "status_proto",
    srcs = ["status.proto"],
    visibility = ["//visibility:public"],
)

# Library for manipulating file paths.
cc_library(
    name = "path",
    srcs = ["path.cc"],
    hdrs = ["path.h"],
    visibility = ["//visibility:public"],
    deps = ["@com_google_absl//absl/strings"],
)

# Test for the path library.
cc_test(
    name = "path_test",
    srcs = ["path_test.cc"],
    enclave_test_name = "path_enclave_test",
    tags = ["regression"],
    deps = [
        ":path",
        "//asylo/test/util:test_main",
        "@com_google_googletest//:gtest",
    ],
)

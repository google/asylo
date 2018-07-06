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

# This package defines utility libraries that are used by the identity libraries.

package(
    default_visibility = ["//asylo:implementation"],
)

load("//asylo/bazel:proto.bzl", "asylo_proto_library")
load("//asylo/bazel:copts.bzl", "ASYLO_DEFAULT_COPTS")

cc_library(
    name = "aligned_object_ptr",
    hdrs = ["aligned_object_ptr.h"],
)

cc_test(
    name = "aligned_object_ptr_test",
    srcs = ["aligned_object_ptr_test.cc"],
    tags = ["regression"],
    deps = [
        ":aligned_object_ptr",
        "@com_google_absl//absl/base:core_headers",
        "@com_google_googletest//:gtest_main",
    ],
)

asylo_proto_library(
    name = "bit_vector_128_proto",
    srcs = ["bit_vector_128.proto"],
)

cc_library(
    name = "bit_vector_128_util",
    srcs = ["bit_vector_128_util.cc"],
    hdrs = ["bit_vector_128_util.h"],
    deps = [
        ":bit_vector_128_proto_cc",
        "@com_google_protobuf//:protobuf",
    ],
)

cc_test(
    name = "bit_vector_128_util_test",
    srcs = ["bit_vector_128_util_test.cc"],
    tags = ["regression"],
    deps = [
        ":bit_vector_128_proto_cc",
        ":bit_vector_128_util",
        "//asylo/test/util:test_main",
        "@com_google_googletest//:gtest",
    ],
)

asylo_proto_library(
    name = "sha256_hash_proto",
    srcs = ["sha256_hash.proto"],
)

cc_library(
    name = "sha256_hash_util",
    srcs = ["sha256_hash_util.cc"],
    hdrs = ["sha256_hash_util.h"],
    deps = [
        ":sha256_hash_proto_cc",
        "//asylo/crypto/util:bytes",
        "//asylo/crypto/util:trivial_object_util",
        "@com_google_absl//absl/strings",
        "@com_google_protobuf//:protobuf",
    ],
)

cc_test(
    name = "sha256_hash_util_test",
    srcs = ["sha256_hash_util_test.cc"],
    tags = ["regression"],
    deps = [
        ":sha256_hash_proto_cc",
        ":sha256_hash_util",
        "//asylo/test/util:test_main",
        "@com_google_googletest//:gtest",
    ],
)

cc_library(
    name = "byte_container_util",
    hdrs = ["byte_container_util.h"],
    deps = [
        "//asylo/util:status",
        "@com_google_asylo//asylo/util:logging",
    ],
)

cc_test(
    name = "byte_container_util_test",
    srcs = ["byte_container_util_test.cc"],
    tags = ["regression"],
    deps = [
        ":byte_container_util",
        "//asylo/test/util:status_matchers",
        "//asylo/test/util:test_main",
        "//asylo/util:cleansing_types",
        "@com_google_googletest//:gtest",
    ],
)

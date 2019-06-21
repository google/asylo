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

load("//asylo/bazel:proto.bzl", "asylo_proto_library")
load("//asylo/bazel:copts.bzl", "ASYLO_DEFAULT_COPTS")

cc_library(
    name = "aligned_object_ptr",
    hdrs = ["aligned_object_ptr.h"],
    copts = ASYLO_DEFAULT_COPTS,
    visibility = ["//asylo:implementation"],
)

cc_test(
    name = "aligned_object_ptr_test",
    srcs = ["aligned_object_ptr_test.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":aligned_object_ptr",
        "//asylo/test/util:test_main",
        "@com_google_absl//absl/base:core_headers",
        "@com_google_absl//absl/container:flat_hash_map",
        "@com_google_googletest//:gtest",
    ],
)

asylo_proto_library(
    name = "sha256_hash_proto",
    srcs = ["sha256_hash.proto"],
    visibility = ["//asylo:implementation"],
)

cc_proto_library(
    name = "sha256_hash_cc_proto",
    visibility = ["//asylo:implementation"],
    deps = ["sha256_hash_proto"],
)

cc_library(
    name = "sha256_hash_util",
    srcs = ["sha256_hash_util.cc"],
    hdrs = ["sha256_hash_util.h"],
    copts = ASYLO_DEFAULT_COPTS,
    visibility = ["//asylo:implementation"],
    deps = [
        ":sha256_hash_cc_proto",
        "//asylo/crypto/util:bytes",
        "//asylo/crypto/util:trivial_object_util",
        "@com_google_absl//absl/strings",
        "@com_google_protobuf//:protobuf",
    ],
)

cc_test(
    name = "sha256_hash_util_test",
    srcs = ["sha256_hash_util_test.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":sha256_hash_cc_proto",
        ":sha256_hash_util",
        "//asylo/test/util:test_main",
        "//asylo/util:status",
        "@com_google_googletest//:gtest",
    ],
)

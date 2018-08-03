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

package(
    default_visibility = ["//asylo:implementation"],
)

load("//asylo/bazel:proto.bzl", "asylo_proto_library")
load("//asylo/bazel:copts.bzl", "ASYLO_DEFAULT_COPTS")

# Utility functions for translating time values and units.
cc_library(
    name = "time_util",
    srcs = ["time_util.cc"],
    hdrs = ["time_util.h"],
)

# A function for creating a hash from two hashes.
cc_library(
    name = "hash_combine",
    hdrs = ["hash_combine.h"],
)

cc_library(
    name = "singleton",
    hdrs = ["singleton.h"],
    deps = ["@com_google_absl//absl/synchronization"],
)

# Singleton test.
cc_test(
    name = "singleton_test",
    srcs = ["singleton_test.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    tags = ["regression"],
    deps = [
        ":singleton",
        "//asylo/test/util:test_main",
        "@boringssl//:crypto",
        "@com_google_absl//absl/synchronization",
        "@com_google_googletest//:gtest",
    ],
)

# Defines a StaticMap template class that can be used to create a global map
# containing instances of a particular type.
cc_library(
    name = "static_map",
    srcs = ["static_map_internal.h"],
    hdrs = ["static_map.h"],
    deps = [
        "//asylo/util:logging",
        "@com_google_absl//absl/synchronization",
    ],
)

# Tests for the StaticMap template class.
cc_test(
    name = "static_map_test",
    srcs = ["static_map_test.cc"],
    tags = ["regression"],
    deps = [
        ":static_map",
        "//asylo/test/util:test_main",
        "@com_google_absl//absl/strings",
        "@com_google_googletest//:gtest",
    ],
)

# Unit tests for time_util.
cc_test(
    name = "time_util_test",
    srcs = ["time_util_test.cc"],
    tags = ["regression"],
    deps = [
        ":time_util",
        "//asylo/test/util:test_main",
        "@com_google_googletest//:gtest",
    ],
)

# Shared types across bridge boundaries.
cc_library(
    name = "bridge_types",
    srcs = ["bridge_types.cc"],
    hdrs = ["bridge_types.h"],
    deps = [
        "//asylo/util:logging",
        "@com_google_absl//absl/base:core_headers",
    ],
)

# Types for arguments to be serialized and passed across the enclave boundary.
asylo_proto_library(
    name = "bridge_types_proto",
    srcs = ["bridge_proto_types.proto"],
)

# Shared proto serializer and deserializer across bridge boundaries.
cc_library(
    name = "bridge_proto_serializer",
    srcs = ["bridge_proto_serializer.cc"],
    hdrs = ["bridge_proto_serializer.h"],
    deps = [
        ":bridge_types_proto_cc",
        "@com_google_absl//absl/strings",
    ],
)

# Synchronized bounded queue type.
cc_library(
    name = "ring_buffer",
    hdrs = ["ring_buffer.h"],
)

cc_test(
    name = "ring_buffer_test",
    srcs = ["ring_buffer_test.cc"],
    deps = [
        ":ring_buffer",
        "//asylo/test/util:test_main",
        "@com_google_googletest//:gtest",
    ],
)

# Synchronized pool of tokens in shared memory.
cc_library(
    name = "shared_token_pool",
    srcs = ["spin_lock.h"],
    hdrs = ["shared_token_pool.h"],
)

cc_test(
    name = "shared_token_pool_test",
    size = "medium",
    srcs = ["shared_token_pool_test.cc"],
    deps = [
        ":shared_token_pool",
        "//asylo/test/util:test_main",
        "@com_google_googletest//:gtest",
    ],
)

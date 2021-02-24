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

package(
    default_visibility = ["//asylo:implementation"],
)

# Utility functions for translating time values and units.
cc_library(
    name = "time_util",
    srcs = ["time_util.cc"],
    hdrs = ["time_util.h"],
    copts = ASYLO_DEFAULT_COPTS,
)

# A function for creating a hash from two hashes.
cc_library(
    name = "hash_combine",
    hdrs = ["hash_combine.h"],
    copts = ASYLO_DEFAULT_COPTS,
)

cc_library(
    name = "singleton",
    hdrs = ["singleton.h"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = ["@com_google_absl//absl/synchronization"],
)

# Singleton test.
cc_test(
    name = "singleton_test",
    srcs = ["singleton_test.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":singleton",
        "//asylo/test/util:test_main",
        "@boringssl//:crypto",
        "@com_google_absl//absl/container:flat_hash_map",
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
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        "//asylo/util:logging",
        "@com_google_absl//absl/base:core_headers",
        "@com_google_absl//absl/synchronization",
    ],
)

# Tests for the StaticMap template class.
cc_test(
    name = "static_map_test",
    srcs = ["static_map_test.cc"],
    copts = ASYLO_DEFAULT_COPTS,
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
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":time_util",
        "//asylo/test/util:test_main",
        "@com_google_googletest//:gtest",
    ],
)

# Synchronized bounded queue type.
cc_library(
    name = "ring_buffer",
    hdrs = ["ring_buffer.h"],
    copts = ASYLO_DEFAULT_COPTS,
)

cc_test(
    name = "ring_buffer_test",
    srcs = ["ring_buffer_test.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":ring_buffer",
        "//asylo/test/util:test_main",
        "@com_google_googletest//:gtest",
    ],
)

# Provide a unique pointer for malloc'd memory.
cc_library(
    name = "memory",
    hdrs = ["memory.h"],
    copts = ASYLO_DEFAULT_COPTS,
)

# Utility functions for working with Linux futex objects.
cc_library(
    name = "futex",
    srcs = ["futex.cc"],
    hdrs = ["futex.h"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":time_util",
    ],
)

# Provide the current state of the enclave.
cc_library(
    name = "enclave_state",
    srcs = ["enclave_state.cc"],
    hdrs = ["enclave_state.h"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        "//asylo/platform/core:trusted_spin_lock",
        "//asylo/util:lock_guard",
        "//asylo/util:status",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/strings",
    ],
)

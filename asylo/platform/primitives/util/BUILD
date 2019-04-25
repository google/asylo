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

load("//asylo/bazel:copts.bzl", "ASYLO_DEFAULT_COPTS")

# Utilities for conversions between Asylo Status and PrimitiveStatus.
cc_library(
    name = "status_conversions",
    srcs = ["status_conversions.cc"],
    hdrs = ["status_conversions.h"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        "//asylo/platform/primitives",
        "//asylo/util:status",
    ],
)

cc_test(
    name = "status_conversions_test",
    srcs = ["status_conversions_test.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":status_conversions",
        "//asylo/test/util:test_main",
        "@com_google_googletest//:gtest",
    ],
)

# Utilities for working with primitive locks.
cc_library(
    name = "primitive_locks",
    hdrs = ["primitive_locks.h"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        "//asylo/platform/primitives/x86:spin_lock",
    ],
)

# A dispatch table implementation of Client::ExitCallProvider.
cc_library(
    name = "dispatch_table",
    srcs = ["dispatch_table.cc"],
    hdrs = ["dispatch_table.h"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        "//asylo/platform/primitives",
        "//asylo/platform/primitives:untrusted_primitives",
        "//asylo/util:asylo_macros",
        "@com_google_absl//absl/base:core_headers",
        "@com_google_absl//absl/container:flat_hash_map",
        "@com_google_absl//absl/synchronization",
    ],
)

cc_test(
    name = "dispatch_table_test",
    srcs = ["dispatch_table_test.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":dispatch_table",
        "//asylo/platform/primitives",
        "//asylo/platform/primitives:untrusted_primitives",
        "//asylo/test/util:status_matchers",
        "//asylo/test/util:test_main",
        "@com_google_absl//absl/memory",
        "@com_google_absl//absl/time",
        "@com_google_googletest//:gtest",
    ],
)

# A library that uses implementation-defined behavior of std::thread::id
# to serialize and deserialize it.
cc_library(
    name = "serializable_thread_id",
    srcs = ["serializable_thread_id.cc"],
    hdrs = ["serializable_thread_id.h"],
    copts = ASYLO_DEFAULT_COPTS,
    visibility = ["//asylo:implementation"],
)

cc_test(
    name = "serializable_thread_id_test",
    srcs = ["serializable_thread_id_test.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    visibility = ["//visibility:private"],
    deps = [
        ":serializable_thread_id",
        "//asylo/test/util:test_main",
        "@com_google_absl//absl/container:flat_hash_map",
        "@com_google_absl//absl/memory",
        "@com_google_absl//absl/synchronization",
        "@com_google_googletest//:gtest",
    ],
)

# A dispatch table implementation of Client::ExitCallProvider.
cc_library(
    name = "trusted_runtime_helper",
    srcs = ["trusted_runtime_helper.cc"],
    hdrs = ["trusted_runtime_helper.h"],
    copts = ASYLO_DEFAULT_COPTS,
    visibility = ["//asylo:implementation"],
    deps = [
        "//asylo/platform/primitives",
        "//asylo/platform/primitives:trusted_primitives",
        "//asylo/platform/primitives/util:primitive_locks",
        "//asylo/platform/primitives/x86:spin_lock",
        "//asylo/util:error_codes",
        "//asylo/util:status_macros",
    ],
)

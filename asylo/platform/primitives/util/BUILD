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

cc_library(
    name = "trusted_memory",
    hdrs = ["trusted_memory.h"],
    deps = ["//asylo/platform/primitives:trusted_primitives"],
)

# Utilities for conversions between Asylo Status and PrimitiveStatus.
cc_library(
    name = "status_conversions",
    srcs = ["status_conversions.cc"],
    hdrs = ["status_conversions.h"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        "//asylo/platform/primitives",
        "//asylo/util:status",
        "@com_google_absl//absl/status",
    ],
)

cc_test(
    name = "status_conversions_test",
    srcs = ["status_conversions_test.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":status_conversions",
        "//asylo/test/util:test_main",
        "@com_google_absl//absl/status",
        "@com_google_googletest//:gtest",
    ],
)

# A dispatch table implementation of Client::ExitCallProvider.
cc_library(
    name = "dispatch_table",
    srcs = ["dispatch_table.cc"],
    hdrs = ["dispatch_table.h"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":message_reader_writer",
        "//asylo/platform/primitives:untrusted_primitives",
        "//asylo/util:asylo_macros",
        "//asylo/util:mutex_guarded",
        "//asylo/util:status",
        "//asylo/util:status_macros",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/types:optional",
    ],
)

# Exit call hooks which log every exit call
cc_library(
    name = "exit_log",
    srcs = ["exit_log.cc"],
    hdrs = ["exit_log.h"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":dispatch_table",
        "//asylo/util:status",
        "@com_google_absl//absl/memory",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/time",
    ],
)

cc_test(
    name = "dispatch_table_test",
    srcs = ["dispatch_table_test.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":dispatch_table",
        "//asylo/platform/primitives:untrusted_primitives",
        "//asylo/test/util:status_matchers",
        "//asylo/test/util:test_main",
        "//asylo/util:status",
        "//asylo/util:thread",
        "@com_google_absl//absl/memory",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/time",
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
        ":message_reader_writer",
        "//asylo/platform/core:trusted_spin_lock",
        "//asylo/platform/primitives",
        "//asylo/platform/primitives:trusted_primitives",
        "//asylo/platform/primitives:trusted_runtime",
        "//asylo/util:lock_guard",
        "//asylo/util:status_macros",
        "@com_google_absl//absl/status",
    ],
)

cc_library(
    name = "message_reader_writer",
    hdrs = ["message.h"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        "//asylo/platform/primitives",
        "@com_google_absl//absl/memory",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/strings",
    ],
)

# Test MessageReader and MessageWriter implementation.
cc_test(
    name = "message_reader_writer_test",
    size = "small",
    srcs = ["message_test.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":message_reader_writer",
        "//asylo/test/util:test_main",
        "@com_google_absl//absl/memory",
        "@com_google_googletest//:gtest",
    ],
)

# Status serializer.
cc_library(
    name = "status_serializer",
    hdrs = [
        "status_serializer.h",
    ],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        "//asylo/platform/primitives:trusted_primitives",
        "//asylo/util:status",
    ],
)

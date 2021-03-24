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

load("@rules_cc//cc:defs.bzl", "cc_library", "cc_test")
load("//asylo/bazel:copts.bzl", "ASYLO_DEFAULT_COPTS")

licenses(["notice"])

package(
    default_visibility = ["//asylo:implementation"],
)

# Library for making host calls to the untrusted side.
cc_library(
    name = "host_call",
    srcs = [
        "trusted/concurrency.cc",
        "trusted/host_calls.cc",
    ],
    hdrs = [
        "trusted/host_calls.h",
    ],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":exit_handler_constants",
        ":host_call_dispatcher",
        ":serializer_functions",
        "//asylo/platform/primitives:trusted_primitives",
        "//asylo/platform/primitives/util:message_reader_writer",
        "//asylo/platform/system_call",
        "//asylo/platform/system_call/type_conversions",
        "//asylo/platform/system_call/type_conversions:types_functions",
        "@com_google_absl//absl/types:optional",
    ],
)

# Library containing untrusted handlers for serialized host call requests.
cc_library(
    name = "untrusted_host_calls",
    srcs = ["untrusted/host_call_handlers.cc"],
    hdrs = ["untrusted/host_call_handlers.h"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":host_call_handlers_util",
        ":serializer_functions",
        "//asylo/platform/common:memory",
        "//asylo/platform/primitives:untrusted_primitives",
        "//asylo/platform/primitives/util:message_reader_writer",
        "//asylo/platform/primitives/util:status_conversions",
        "//asylo/platform/system_call:untrusted_invoke",
        "//asylo/util:hex_util",
        "//asylo/util:status",
        "@com_google_absl//absl/status",
    ],
)

# Helper library containing common logic for handling host calls locally or
# remotely.
cc_library(
    name = "host_call_handlers_util",
    srcs = ["untrusted/host_call_handlers_util.cc"],
    hdrs = ["untrusted/host_call_handlers_util.h"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        "//asylo/platform/common:futex",
        "//asylo/platform/primitives/util:message_reader_writer",
        "//asylo/util:status",
        "@com_google_absl//absl/status",
    ],
)

# Library containing functions for serializing/deserializing data structures on
# the MessageWriter.
cc_library(
    name = "serializer_functions",
    srcs = ["serializer_functions.cc"],
    hdrs = ["serializer_functions.h"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        "//asylo/platform/primitives",
        "//asylo/platform/primitives/util:message_reader_writer",
        "//asylo/platform/system_call/type_conversions",
        "//asylo/util:status_macros",
        "@com_google_absl//absl/status",
    ],
)

# Test host call handlers implementation.
cc_test(
    name = "host_call_handlers_test",
    srcs = ["untrusted/host_call_handlers_test.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":untrusted_host_calls",
        "//asylo/platform/primitives/util:message_reader_writer",
        "//asylo/platform/primitives/util:status_conversions",
        "//asylo/platform/system_call",
        "//asylo/platform/system_call:message",
        "//asylo/test/util:status_matchers",
        "//asylo/test/util:test_main",
        "@com_google_absl//absl/memory",
        "@com_google_absl//absl/status",
        "@com_google_googletest//:gtest",
    ],
)

# Library for dispatching host calls to the untrusted host from the trusted
# side.
cc_library(
    name = "host_call_dispatcher",
    srcs = ["trusted/host_call_dispatcher.cc"],
    hdrs = ["trusted/host_call_dispatcher.h"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":exit_handler_constants",
        "//asylo/platform/primitives",
        "//asylo/platform/primitives:trusted_primitives",
        "//asylo/platform/primitives/util:message_reader_writer",
        "//asylo/util:status_macros",
        "@com_google_absl//absl/status",
    ],
)

# Library containing exit handler constants used by the host call dispatcher
# and host call handler initializer.
cc_library(
    name = "exit_handler_constants",
    hdrs = ["exit_handler_constants.h"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        "//asylo/platform/primitives",
    ],
)

# Library for initializing the dispatch table for host call handlers. Maps the
# exit handler constants to host call handler functions.
cc_library(
    name = "host_call_handlers_initializer",
    srcs = ["untrusted/host_call_handlers_initializer.cc"],
    hdrs = ["untrusted/host_call_handlers_initializer.h"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":exit_handler_constants",
        ":untrusted_host_calls",
        "//asylo/platform/primitives/util:dispatch_table",
        "//asylo/util:status",
        "@com_google_absl//absl/status",
    ],
)

# Test host call handlers initializer implementation.
cc_test(
    name = "host_call_handlers_initializers_test",
    srcs = ["untrusted/host_call_handlers_initializer_test.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":exit_handler_constants",
        ":host_call_handlers_initializer",
        "//asylo/platform/primitives:untrusted_primitives",
        "//asylo/platform/primitives/util:message_reader_writer",
        "//asylo/test/util:status_matchers",
        "//asylo/test/util:test_main",
        "//asylo/util:logging",
        "@com_google_absl//absl/status",
        "@com_google_googletest//:gtest",
    ],
)

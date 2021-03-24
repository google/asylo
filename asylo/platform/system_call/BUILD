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

load("@rules_cc//cc:defs.bzl", "cc_binary", "cc_library", "cc_test")
load("@rules_python//python:defs.bzl", "py_binary")
load("//asylo/bazel:copts.bzl", "ASYLO_DEFAULT_COPTS")

licenses(["notice"])  # Apache v2.0

package(
    default_visibility = ["//asylo:implementation"],
)

# Preprocessor script for the system call definitions file.
py_binary(
    name = "preprocess",
    srcs = ["preprocess.py"],
    python_version = "PY3",
)

genrule(
    name = "do_preprocess",
    srcs = ["syscalls.txt"],
    outs = ["syscalls.inc"],
    cmd = "$(location preprocess) < $(<) > $(@)",
    exec_tools = [":preprocess"],
)

# Code generator utility for building static C++ tables describing
# Linux system calls.
cc_binary(
    name = "generate_tables",
    srcs = [
        "generate_tables.cc",
        "syscalls.inc",
    ],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        "@com_google_absl//absl/container:flat_hash_map",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/strings:str_format",
    ],
)

genrule(
    name = "do_generate_tables",
    outs = ["generated_tables.inc"],
    cmd = "$(location generate_tables) > $(@)",
    tools = [":generate_tables"],
)

# System call metadata access library.
cc_library(
    name = "metadata",
    srcs = [
        "generated_tables.inc",
        "metadata.cc",
    ],
    hdrs = [
        "metadata.h",
    ],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        "@com_google_absl//absl/strings",
    ],
)

cc_test(
    name = "metadata_test",
    srcs = ["metadata_test.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":metadata",
        "//asylo/test/util:test_main",
        "@com_google_absl//absl/strings",
        "@com_google_googletest//:gtest",
    ],
)

# Serialized system call message reader and writer.
cc_library(
    name = "message",
    srcs = ["message.cc"],
    hdrs = ["message.h"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":metadata",
        "//asylo/platform/primitives",
        "//asylo/util:status_macros",
        "@com_google_absl//absl/base:core_headers",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/strings",
    ],
)

cc_test(
    name = "message_test",
    srcs = ["message_test.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":message",
        "//asylo/platform/primitives",
        "//asylo/test/util:test_main",
        "@com_google_absl//absl/base",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/strings",
        "@com_google_googletest//:gtest",
    ],
)

# Remote system call library.
cc_library(
    name = "system_call",
    srcs = [
        "serialize.cc",
        "system_call.cc",
    ],
    hdrs = [
        "serialize.h",
        "sysno.h",
        "system_call.h",
    ],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":message",
        ":metadata",
        "//asylo/platform/primitives",
        "//asylo/platform/system_call/type_conversions",
        "//asylo/platform/system_call/type_conversions:types_functions",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/strings",
    ],
)

# Code generator utility emitting a header file containing system call number
# definitions.
cc_binary(
    name = "generate_sysno",
    srcs = ["generate_sysno.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":metadata",
        "@com_google_absl//absl/strings:str_format",
    ],
)

genrule(
    name = "do_generate_sysno",
    outs = ["sysno.h"],
    cmd = "$(location generate_sysno) > $(@)",
    tools = [":generate_sysno"],
)

# Local invocation of a serialized system call request.
cc_library(
    name = "untrusted_invoke",
    srcs = [
        "untrusted_invoke.cc",
    ],
    hdrs = ["untrusted_invoke.h"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":metadata",
        ":system_call",
        "//asylo/platform/primitives",
    ],
)

cc_test(
    name = "system_call_test",
    size = "medium",
    srcs = ["system_call_test.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":system_call",
        ":untrusted_invoke",
        "//asylo/platform/primitives",
        "//asylo/platform/primitives:untrusted_primitives",
        "//asylo/platform/system_call/type_conversions",
        "//asylo/test/util:test_flags",
        "//asylo/test/util:test_main",
        "//asylo/util:status_macros",
        "@com_google_absl//absl/flags:flag",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/strings",
        "@com_google_googletest//:gtest",
    ],
)

cc_test(
    name = "serialize_test",
    srcs = ["serialize_test.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":system_call",
        "//asylo/platform/primitives",
        "//asylo/test/util:test_main",
        "@com_google_absl//absl/strings",
        "@com_google_googletest//:gtest",
    ],
)

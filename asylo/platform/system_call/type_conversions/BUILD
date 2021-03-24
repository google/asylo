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
load("@rules_python//python:defs.bzl", "py_binary", "py_library", "py_test")
load(
    "//asylo/bazel:asylo.bzl",
    "cc_enclave_test",
    "cc_test_and_cc_enclave_test",
)
load("//asylo/bazel:copts.bzl", "ASYLO_DEFAULT_COPTS")

licenses(["notice"])  # Apache v2.0

package(
    default_visibility = ["//asylo:implementation"],
)

# Functions for declaring entities to be emitted by the types conversions generator.
py_library(
    name = "types_parse_functions",
    srcs = ["types_parse_functions.py"],
)

# Tests for types_parse_functions.
py_test(
    name = "types_parse_functions_test",
    srcs = ["types_parse_functions_test.py"],
    python_version = "PY3",
    deps = [
        ":types_parse_functions",
    ],
)

# Binary for the .py file to be parsed for generating the C macros.
py_binary(
    name = "generate_macros",
    srcs = ["define_types.py"],
    main = "define_types.py",
    python_version = "PY3",
    deps = [
        ":types_parse_functions",
    ],
)

# Preprocesses the definitions in types.py and emits a header file suitable for inclusion by the C++
# code generator, types conversions generator.
genrule(
    name = "do_generate_macros",
    outs = ["types_macros.inc"],
    cmd = "$(location generate_macros) > $(@)",
    exec_tools = [":generate_macros"],
)

# Code generator utility emitting definitions and metadata describing the symbols defined in
# types_macros.inc
cc_binary(
    name = "generate_types",
    srcs = [
        "types_conversions_generator.cc",
        "types_macros.inc",
    ],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        "//asylo/util:logging",
        "@com_google_absl//absl/container:flat_hash_map",
        "@com_google_absl//absl/flags:flag",
        "@com_google_absl//absl/flags:parse",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/strings:str_format",
    ],
)

# Uses the type conversions generator to generate the .h and .cc files
# containing the host enum definitions, conversion functions declarations and
# their implementations.
genrule(
    name = "do_generate_types",
    outs = [
        "generated_types.h",
        "generated_types_functions.h",
        "generated_types_functions.cc",
    ],
    cmd = "$(location generate_types) --output_dir=$(@D)",
    tools = [":generate_types"],
)

# Library containing type definitions (generated or manually written).
cc_library(
    name = "types_definitions",
    hdrs = [
        "generated_types.h",
        "kernel_types.h",
    ],
    copts = ASYLO_DEFAULT_COPTS,
    deps = ["@com_google_absl//absl/base:core_headers"],
)

# Library containing the type conversion functions (generated or manually
# written) for the type definitions.
cc_library(
    name = "types_functions",
    srcs = [
        "generated_types_functions.cc",
        "manual_types_functions.cc",
    ],
    hdrs = [
        "generated_types_functions.h",
        "manual_types_functions.h",
    ],
    copts = ASYLO_DEFAULT_COPTS + ["-D_GNU_SOURCE"],
    deps = [
        ":types_definitions",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/types:optional",
    ],
)

# Tests generated conversion functions on the host and inside the enclave.
cc_test_and_cc_enclave_test(
    name = "generated_types_functions_test",
    srcs = ["generated_types_functions_test.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":types_functions",
        "//asylo/test/util:finite_domain_fuzz",
        "//asylo/test/util:test_main",
        "@com_google_absl//absl/random",
        "@com_google_googletest//:gtest",
    ],
)

# Tests whether manually written kernel types match the native types on the
# host.
cc_test(
    name = "kernel_types_test",
    srcs = ["kernel_types_test.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":types_functions",
        "//asylo/test/util:test_main",
        "@com_google_googletest//:gtest",
    ],
)

# Tests the manually written type conversion functions inside the enclave.
cc_enclave_test(
    name = "manual_types_functions_test",
    srcs = ["manual_types_functions_test.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":types_functions",
        "//asylo/test/util:test_main",
        "@com_google_googletest//:gtest",
    ],
)

# Library containing the type definitions and type conversion functions
# between enclave C library implementation and the target host implementation.
# This library contains both the auto-generated as well as manually written
# type definitions and type conversion functions.
cc_library(
    name = "type_conversions",
    hdrs = [
        "types.h",
        "types_functions.h",
    ],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":types_definitions",
        ":types_functions",
    ],
)

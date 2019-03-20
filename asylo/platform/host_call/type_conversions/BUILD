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

licenses(["notice"])  # Apache v2.0

load("//asylo/bazel:copts.bzl", "ASYLO_DEFAULT_COPTS")

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
    deps = [
        ":types_parse_functions",
    ],
)

# Binary for the .py file to be parsed for generating the C macros.
py_binary(
    name = "types",
    srcs = ["types.py"],
    deps = [
        ":types_parse_functions",
    ],
)

# Preprocesses the definitions in types.py and emits a header file suitable for inclusion by the C++
# code generator, types conversions generator.
genrule(
    name = "do_generate_macros",
    outs = ["types_macros.inc"],
    cmd = "$(location types) > $(@)",
    tools = [":types"],
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
        "@com_github_gflags_gflags//:gflags_nothreads",
        "@com_google_absl//absl/container:flat_hash_map",
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

# Library containing the generated type definitions and data conversions
# between newlib and the Linux host for the Primitives interface.
cc_library(
    name = "generated_types",
    srcs = ["generated_types_functions.cc"],
    hdrs = [
        "generated_types.h",
        "generated_types_functions.h",
    ],
    copts = ASYLO_DEFAULT_COPTS,
)

# Tests the generated types conversion functions.
cc_test(
    name = "generated_types_functions_test",
    srcs = ["generated_types_functions_test.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":generated_types",
        "//asylo/test/util:finite_domain_fuzz",
        "//asylo/test/util:test_main",
        "//asylo/util:logging",
        "@com_google_googletest//:gtest",
    ],
)

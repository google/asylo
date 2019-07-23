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

load("//asylo/bazel:copts.bzl", "ASYLO_DEFAULT_COPTS")

package(
    default_visibility = ["//asylo:implementation"],
)

# Common definitions shared by trusted and untrusted code.
cc_library(
    name = "primitives",
    hdrs = [
        "extent.h",
        "primitive_status.h",
        "primitives.h",
    ],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        "//asylo/util:error_codes",
    ],
)

# Primitive API headers for untrusted code.
cc_library(
    name = "untrusted_primitives",
    srcs = ["untrusted_primitives.cc"],
    hdrs = ["untrusted_primitives.h"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":primitives",
        "//asylo/platform/primitives/util:message_reader_writer",
        "//asylo/platform/primitives/util:status_conversions",
        "//asylo/util:asylo_macros",
        "//asylo/util:status",
    ],
)

# Target exposing trusted backend-dependent components for the build configuration.
cc_library(
    name = "trusted_backend",
    hdrs = [
        "trusted_runtime.h",
        "//asylo/platform/primitives/util:trusted_memory.h",
    ],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [":primitives"] + select({
        "//asylo/platform/primitives:sgx": [
            "//asylo/platform/primitives/sgx:trusted_sgx",
        ],
        "//conditions:default": [],
    }),
)

# Primitive API headers for trusted code.
cc_library(
    name = "trusted_primitives",
    hdrs = ["trusted_primitives.h"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":primitives",
        "//asylo/platform/primitives/util:message_reader_writer",
        "//asylo/util:asylo_macros",
    ],
)

# Primitive API headers for trusted runtime support functions.
cc_library(
    name = "trusted_runtime",
    hdrs = ["trusted_runtime.h"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [":primitives"],
)

# Test extent implementation.
cc_test(
    name = "extent_test",
    size = "small",
    srcs = ["extent_test.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":primitives",
        "//asylo/test/util:test_main",
        "@com_google_absl//absl/base:core_headers",
        "@com_google_googletest//:gtest",
    ],
)

# Test shared type implementation.
cc_test(
    name = "primitive_status_test",
    size = "small",
    srcs = ["primitive_status_test.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":primitives",
        "//asylo/test/util:test_main",
        "@com_google_absl//absl/base:core_headers",
        "@com_google_googletest//:gtest",
    ],
)

# Configuration setting for the primitives/sim backend.
config_setting(
    name = "asylo_sim",
    values = {
        "define": "ASYLO_SIM=1",
    },
)

# Configuration setting for the primitives/sgx backend.
config_setting(
    name = "asylo_sgx",
    values = {
        "define": "ASYLO_SGX=1",
    },
)

# Set when we are compiling for sgx backend.
config_setting(
    name = "sgx",
    values = {
        "crosstool_top": "@com_google_asylo_toolchain//toolchain:crosstool",
    },
)

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

# Utility libraries for IO operations.

load("//asylo/bazel:asylo.bzl", "cc_enclave_test")
load("//asylo/bazel:copts.bzl", "ASYLO_DEFAULT_COPTS")

package(
    default_visibility = ["//asylo:implementation"],
)

cc_library(
    name = "trusted_utils",
    copts = ASYLO_DEFAULT_COPTS,
    deps = select({
        "@com_google_asylo//asylo": [
            "offset_translator",
            "fd_closer",
        ],
        "//conditions:default": [],
    }),
)

cc_library(
    name = "fd_closer",
    srcs = ["fd_closer.cc"],
    hdrs = ["fd_closer.h"],
    copts = ASYLO_DEFAULT_COPTS,
)

cc_test(
    name = "fd_closer_test",
    size = "small",
    srcs = ["fd_closer_test.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":fd_closer",
        "//asylo/test/util:test_main",
        "@com_google_googletest//:gtest",
    ],
)

cc_library(
    name = "offset_translator",
    srcs = ["offset_translator.cc"],
    hdrs = ["offset_translator.h"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        "@com_google_absl//absl/memory",
    ],
)

# Offset Translator test in enclave.
cc_enclave_test(
    name = "offset_translator_test",
    srcs = ["offset_translator_test.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        "@com_google_googletest//:gtest",
    ],
)

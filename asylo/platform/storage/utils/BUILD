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

# Utility libraries for IO operations.

load("@rules_cc//cc:defs.bzl", "cc_library", "cc_test")
load("//asylo/bazel:asylo.bzl", "cc_enclave_test")
load("//asylo/bazel:copts.bzl", "ASYLO_DEFAULT_COPTS")

licenses(["notice"])  # Apache v2.0

package(
    default_visibility = ["//asylo:implementation"],
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
        ":offset_translator",
        "//asylo/util:logging",
        "@com_google_googletest//:gtest",
    ],
)

cc_library(
    name = "test_utils",
    testonly = 1,
    srcs = ["test_utils.cc"],
    hdrs = ["test_utils.h"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        "//asylo/test/util:test_flags",
        "//asylo/util:logging",
        "@com_google_absl//absl/flags:flag",
        "@com_google_absl//absl/strings",
        "@com_google_googletest//:gtest",
    ],
)

cc_library(
    name = "random_access_storage",
    srcs = ["untrusted_file.cc"],
    hdrs = [
        "random_access_storage.h",
        "untrusted_file.h",
    ],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        "//asylo/util:asylo_macros",
        "//asylo/util:posix_errors",
        "//asylo/util:status",
        "@com_google_absl//absl/status",
    ],
)

cc_test(
    name = "untrusted_file_test",
    srcs = ["untrusted_file_test.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":fd_closer",
        ":random_access_storage",
        ":test_utils",
        "//asylo/test/util:status_matchers",
        "//asylo/test/util:test_main",
        "@com_google_googletest//:gtest",
    ],
)

cc_library(
    name = "record_store",
    hdrs = [
        "record_store.h",
    ],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":random_access_storage",
        "//asylo/util:asylo_macros",
        "//asylo/util:logging",
        "//asylo/util:status",
        "@com_google_absl//absl/container:flat_hash_map",
        "@com_google_absl//absl/status",
    ],
)

cc_test(
    name = "record_store_test",
    srcs = [
        "record_store_test.cc",
    ],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":fd_closer",
        ":random_access_storage",
        ":record_store",
        ":test_utils",
        "//asylo/test/util:status_matchers",
        "//asylo/test/util:test_main",
        "@com_google_googletest//:gtest",
    ],
)

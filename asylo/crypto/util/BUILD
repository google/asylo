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

# Asylo Crypto library utilities.

load("@rules_cc//cc:defs.bzl", "cc_library")
load(
    "//asylo/bazel:asylo.bzl",
    cc_test = "cc_test_and_cc_enclave_test",
)
load("//asylo/bazel:copts.bzl", "ASYLO_DEFAULT_COPTS")

licenses(["notice"])

cc_library(
    name = "bssl_util",
    srcs = ["bssl_util.cc"],
    hdrs = ["bssl_util.h"],
    copts = ASYLO_DEFAULT_COPTS,
    visibility = ["//asylo:implementation"],
    deps = ["@boringssl//:crypto"],
)

cc_library(
    name = "byte_container_util",
    srcs = ["byte_container_util_internal.h"],
    hdrs = ["byte_container_util.h"],
    copts = ASYLO_DEFAULT_COPTS,
    visibility = ["//asylo:implementation"],
    deps = [
        ":byte_container_view",
        "//asylo/util:status",
        "@com_google_absl//absl/status",
    ],
)

cc_test(
    name = "byte_container_util_test",
    srcs = ["byte_container_util_test.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":byte_container_util",
        ":byte_container_view",
        ":bytes",
        ":trivial_object_util",
        "//asylo/test/util:status_matchers",
        "//asylo/test/util:test_main",
        "//asylo/util:cleansing_types",
        "@com_google_absl//absl/base:core_headers",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/types:span",
        "@com_google_googletest//:gtest",
    ],
)

cc_library(
    name = "byte_container_view",
    srcs = ["byte_container_view_internal.h"],
    hdrs = ["byte_container_view.h"],
    copts = ASYLO_DEFAULT_COPTS,
    visibility = ["//asylo:implementation"],
    deps = [
        "//asylo/util:logging",
        "@boringssl//:crypto",
        "@com_google_absl//absl/strings",
    ],
)

cc_test(
    name = "byte_container_view_test",
    srcs = [
        "byte_container_view_internal.h",
        "byte_container_view_test.cc",
    ],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":byte_container_view",
        ":bytes",
        "//asylo/test/util:test_main",
        "//asylo/util:status",
        "@com_google_absl//absl/strings",
        "@com_google_googletest//:gtest",
    ],
)

cc_library(
    name = "byte_container_reader",
    hdrs = ["byte_container_reader.h"],
    copts = ASYLO_DEFAULT_COPTS,
    visibility = ["//asylo:implementation"],
    deps = [
        ":byte_container_view",
        "//asylo/util:status",
        "@boringssl//:crypto",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/strings:str_format",
    ],
)

cc_test(
    name = "byte_container_reader_test",
    srcs = ["byte_container_reader_test.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":byte_container_reader",
        ":byte_container_view",
        ":trivial_object_util",
        "//asylo/test/util:status_matchers",
        "//asylo/test/util:test_main",
        "//asylo/util:cleansing_types",
        "@com_google_absl//absl/base:core_headers",
        "@com_google_absl//absl/status",
        "@com_google_googletest//:gtest",
    ],
)

cc_library(
    name = "bytes",
    hdrs = ["bytes.h"],
    copts = ASYLO_DEFAULT_COPTS,
    visibility = ["//asylo:implementation"],
    deps = [
        ":byte_container_view",
        ":trivial_object_util",
        "//asylo/util:cleansing_types",
        "//asylo/util:logging",
        "//asylo/util:status",
        "@boringssl//:crypto",
        "@com_google_absl//absl/base:core_headers",
    ],
)

cc_test(
    name = "bytes_test",
    srcs = ["bytes_test.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":byte_container_view",
        ":bytes",
        ":trivial_object_util",
        "//asylo/test/util:test_main",
        "@com_google_googletest//:gtest",
    ],
)

cc_library(
    name = "trivial_object_util",
    hdrs = ["trivial_object_util.h"],
    copts = ASYLO_DEFAULT_COPTS,
    visibility = ["//asylo:implementation"],
    deps = [
        "//asylo/util:status",
        "@boringssl//:crypto",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/strings",
    ],
)

cc_test(
    name = "trivial_object_util_test",
    srcs = ["trivial_object_util_test.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":bytes",
        ":trivial_object_util",
        "//asylo/test/util:status_matchers",
        "//asylo/test/util:test_main",
        "@com_google_absl//absl/container:flat_hash_set",
        "@com_google_googletest//:gtest",
    ],
)

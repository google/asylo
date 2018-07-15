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

package(default_visibility = ["//asylo:implementation"])

load("//asylo/bazel:copts.bzl", "ASYLO_DEFAULT_COPTS")

# Asylo Crypto library utilities.

cc_library(
    name = "bssl_util",
    srcs = ["bssl_util.cc"],
    hdrs = ["bssl_util.h"],
    deps = ["@boringssl//:crypto"],
)

cc_library(
    name = "byte_container_util",
    hdrs = ["byte_container_util.h"],
    deps = [
        "//asylo/util:status",
        "@com_google_asylo//asylo/util:logging",
    ],
)

cc_test(
    name = "byte_container_util_test",
    srcs = ["byte_container_util_test.cc"],
    tags = ["regression"],
    deps = [
        ":byte_container_util",
        "//asylo/test/util:status_matchers",
        "//asylo/test/util:test_main",
        "//asylo/util:cleansing_types",
        "@com_google_googletest//:gtest",
    ],
)

cc_library(
    name = "byte_container_view",
    hdrs = ["byte_container_view.h"],
    deps = ["@com_google_asylo//asylo/util:logging"],
)

cc_test(
    name = "byte_container_view_test",
    srcs = ["byte_container_view_test.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    tags = ["regression"],
    deps = [
        ":byte_container_view",
        ":bytes",
        "//asylo/test/util:test_main",
        "@com_google_googletest//:gtest",
    ],
)

cc_library(
    name = "bytes",
    hdrs = ["bytes.h"],
    deps = [
        ":byte_container_view",
        ":trivial_object_util",
        "//asylo/util:cleansing_types",
        "@boringssl//:crypto",
        "@com_google_absl//absl/base:core_headers",
        "@com_google_asylo//asylo/util:logging",
    ],
)

cc_test(
    name = "bytes_test",
    srcs = ["bytes_test.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    tags = ["regression"],
    deps = [
        ":bytes",
        ":trivial_object_util",
        "//asylo/test/util:test_main",
        "@com_google_googletest//:gtest",
    ],
)

cc_library(
    name = "trivial_object_util",
    hdrs = ["trivial_object_util.h"],
    deps = [
        "@boringssl//:crypto",
        "@com_google_absl//absl/strings",
    ],
)

cc_test(
    name = "trivial_object_util_test",
    srcs = ["trivial_object_util_test.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    tags = ["regression"],
    deps = [
        ":bytes",
        ":trivial_object_util",
        "//asylo/test/util:test_main",
        "@com_google_googletest//:gtest",
    ],
)

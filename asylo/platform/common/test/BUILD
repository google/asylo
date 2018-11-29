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

package(
    default_visibility = ["//asylo:implementation"],
)

load("@linux_sgx//:sgx_sdk.bzl", "sgx_enclave")
load("//asylo/bazel:asylo.bzl", "enclave_test")
load("//asylo/bazel:copts.bzl", "ASYLO_DEFAULT_COPTS")

# Enclave used to test bridge_types's packed struct size inside an enclave.
sgx_enclave(
    name = "bridge_types_enclave.so",
    srcs = ["bridge_types_test_enclave.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":bridge_types_test_data",
        "//asylo/test/util:enclave_test_application",
    ],
)

# Tests for the packed struct size for bridge_types.
enclave_test(
    name = "bridge_types_test",
    srcs = ["bridge_types_test_driver.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    enclaves = {"enclave": ":bridge_types_enclave.so"},
    test_args = ["--enclave_path='{enclave}'"],
    deps = [
        ":bridge_types_test_data",
        "//asylo/platform/common:bridge_types",
        "//asylo/test/util:enclave_test",
        "//asylo/test/util:status_matchers",
        "//asylo/test/util:test_main",
        "@com_google_googletest//:gtest",
    ],
)

# Simple library to populate shared test data for inside and outside enclaves.
cc_library(
    name = "bridge_types_test_data",
    srcs = ["bridge_types_test_data.cc"],
    hdrs = ["bridge_types_test_data.h"],
    copts = ASYLO_DEFAULT_COPTS,
    visibility = ["//visibility:private"],
)

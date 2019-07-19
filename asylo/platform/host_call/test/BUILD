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

load("//asylo/bazel:asylo.bzl", "sim_enclave_test")
load("//asylo/bazel:sim_enclave.bzl", "sim_enclave")
load("//asylo/bazel:copts.bzl", "ASYLO_DEFAULT_COPTS")

package(
    default_visibility = ["//asylo:implementation"],
)

# Library containing enclave entry handler constants for testing host calls
# from the untrusted side. These entry handlers trigger the host calls inside
# the enclave.
cc_library(
    name = "enclave_test_selectors",
    hdrs = ["enclave_test_selectors.h"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        "//asylo/platform/primitives",
        "//asylo/platform/system_call",
    ],
)

# Test enclave for invoking host calls for the tests.
sim_enclave(
    name = "sim_test_enclave.so",
    testonly = 1,
    srcs = [
        "test_enclave.cc",
    ],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":enclave_test_selectors",
        "//asylo/platform/host_call",
        "//asylo/platform/host_call:host_call_dispatcher",
        "//asylo/platform/system_call",
        "//asylo/platform/system_call/type_conversions:types",
        "//asylo/util:status_macros",
    ],
)

# Unit tests for the host calls. Use this library to run the same set of tests
# on different enclave backends.
cc_library(
    name = "host_call_test_1_lib",
    testonly = 1,
    srcs = ["host_call_test_1.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":enclave_test_selectors",
        "//asylo/platform/host_call:host_call_handlers_initializer",
        "//asylo/platform/primitives",
        "//asylo/platform/primitives:untrusted_primitives",
        "//asylo/platform/primitives/test:test_backend",
        "//asylo/platform/primitives/util:message_reader_writer",
        "//asylo/platform/storage/utils:fd_closer",
        "//asylo/platform/system_call/type_conversions:types",
        "//asylo/test/util:status_matchers",
        "//asylo/test/util:test_flags",
        "@com_google_absl//absl/flags:flag",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/time",
        "@com_google_googletest//:gtest",
    ],
    # Required to prevent the linker from dropping the flag symbol.
    alwayslink = 1,
)

cc_library(
    name = "host_call_test_2_lib",
    testonly = 1,
    srcs = ["host_call_test_2.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":enclave_test_selectors",
        "//asylo/platform/host_call:host_call_handlers_initializer",
        "//asylo/platform/primitives",
        "//asylo/platform/primitives:untrusted_primitives",
        "//asylo/platform/primitives/test:test_backend",
        "//asylo/platform/primitives/util:message_reader_writer",
        "//asylo/platform/storage/utils:fd_closer",
        "//asylo/platform/system_call/type_conversions:types",
        "//asylo/test/util:status_matchers",
        "//asylo/test/util:test_flags",
        "@com_google_absl//absl/flags:flag",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/time",
        "@com_google_googletest//:gtest",
    ],
    # Required to prevent the linker from dropping the flag symbol.
    alwayslink = 1,
)

# Tests host calls against sim backend.
sim_enclave_test(
    name = "sim_host_call_test_1",
    copts = ASYLO_DEFAULT_COPTS,
    enclaves = {"sim": ":sim_test_enclave.so"},
    linkstatic = True,
    test_args = [
        "--enclave_binary='{sim}'",
    ],
    deps = [
        ":host_call_test_1_lib",
        "//asylo/platform/primitives",
        "//asylo/platform/primitives:trusted_runtime",
        "//asylo/platform/primitives/test:sim_test_backend",
        "//asylo/test/util:test_main",
    ],
)

sim_enclave_test(
    name = "sim_host_call_test_2",
    copts = ASYLO_DEFAULT_COPTS,
    enclaves = {"sim": ":sim_test_enclave.so"},
    linkstatic = True,
    test_args = [
        "--enclave_binary='{sim}'",
    ],
    deps = [
        ":host_call_test_2_lib",
        "//asylo/platform/primitives",
        "//asylo/platform/primitives:trusted_runtime",
        "//asylo/platform/primitives/test:sim_test_backend",
        "//asylo/test/util:test_main",
    ],
)

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

load("@linux_sgx//:sgx_sdk.bzl", "sgx")
load("@rules_cc//cc:defs.bzl", "cc_library")
load(
    "//asylo/bazel:asylo.bzl",
    "cc_enclave_test",
    "cc_unsigned_enclave",
    "debug_sign_enclave",
    "enclave_test",
)
load("//asylo/bazel:copts.bzl", "ASYLO_DEFAULT_COPTS")
load("//asylo/bazel:dlopen_enclave.bzl", "dlopen_enclave_test", "primitives_dlopen_enclave")

licenses(["notice"])

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
primitives_dlopen_enclave(
    name = "dlopen_test_enclave.so",
    testonly = 1,
    srcs = [
        "test_enclave.cc",
    ],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":enclave_test_selectors",
        "//asylo/platform/host_call",
        "//asylo/platform/host_call:host_call_dispatcher",
        "//asylo/platform/primitives",
        "//asylo/platform/primitives:trusted_runtime",
        "//asylo/platform/primitives/util:message_reader_writer",
        "//asylo/platform/system_call/type_conversions",
        "//asylo/util:status_macros",
        "@com_google_absl//absl/base:core_headers",
    ],
)

# Unit tests for the host calls. Use this library to run the same set of tests
# on different enclave backends.
cc_library(
    name = "host_call_test_lib",
    testonly = 1,
    srcs = ["host_call_test.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":enclave_test_selectors",
        "//asylo:enclave_client",
        "//asylo/platform/common:time_util",
        "//asylo/platform/host_call:host_call_handlers_initializer",
        "//asylo/platform/primitives",
        "//asylo/platform/primitives:untrusted_primitives",
        "//asylo/platform/primitives/test:test_backend",
        "//asylo/platform/primitives/util:message_reader_writer",
        "//asylo/platform/storage/utils:fd_closer",
        "//asylo/test/util:status_matchers",
        "//asylo/test/util:test_flags",
        "@com_google_absl//absl/base:core_headers",
        "@com_google_absl//absl/container:flat_hash_set",
        "@com_google_absl//absl/flags:flag",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/time",
        "@com_google_googletest//:gtest",
    ],
    # Required to prevent the linker from dropping the flag symbol.
    alwayslink = 1,
)

# Tests host calls against dlopen backend.
dlopen_enclave_test(
    name = "dlopen_host_call_test",
    copts = ASYLO_DEFAULT_COPTS,
    enclaves = {"enclave_binary": ":dlopen_test_enclave.so"},
    linkstatic = True,
    test_args = [
        "--enclave_binary='{enclave_binary}'",
    ],
    deps = [
        ":host_call_test_lib",
        "//asylo/platform/primitives",
        "//asylo/platform/primitives:trusted_runtime",
        "//asylo/platform/primitives/test:dlopen_test_backend",
        "//asylo/test/util:test_main",
    ],
)

cc_unsigned_enclave(
    name = "sgx_test_enclave_unsigned.so",
    testonly = 1,
    srcs = [
        "test_enclave.cc",
    ],
    backends = sgx.backend_labels,
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":enclave_test_selectors",
        "//asylo/platform/host_call",
        "//asylo/platform/host_call:host_call_dispatcher",
        "//asylo/platform/posix:trusted_posix",
        "//asylo/platform/primitives",
        "//asylo/platform/primitives:trusted_primitives",
        "//asylo/platform/primitives:trusted_runtime",
        "//asylo/platform/primitives/sgx:trusted_sgx",
        "//asylo/platform/primitives/util:message_reader_writer",
        "//asylo/platform/system",
        "//asylo/platform/system_call",
        "//asylo/platform/system_call/type_conversions",
        "//asylo/util:status_macros",
        "@com_google_absl//absl/base:core_headers",
    ],
)

debug_sign_enclave(
    name = "sgx_test_enclave.so",
    testonly = 1,
    unsigned = "sgx_test_enclave_unsigned.so",
)

enclave_test(
    name = "sgx_host_call_test",
    size = "medium",
    srcs = ["host_call_test.cc"],
    backends = sgx.backend_labels,
    copts = ASYLO_DEFAULT_COPTS + ["-D_GNU_SOURCE"],
    enclaves = {"sgx": "sgx_test_enclave.so"},
    test_args = [
        "--enclave_binary='{sgx}'",
    ],
    deps = [
        ":enclave_test_selectors",
        "//asylo:enclave_client",
        "//asylo/platform/common:time_util",
        "//asylo/platform/host_call:host_call_handlers_initializer",
        "//asylo/platform/primitives",
        "//asylo/platform/primitives:trusted_runtime",
        "//asylo/platform/primitives:untrusted_primitives",
        "//asylo/platform/primitives/sgx:untrusted_sgx",
        "//asylo/platform/primitives/test:sgx_test_backend",
        "//asylo/platform/primitives/test:test_backend",
        "//asylo/platform/primitives/util:message_reader_writer",
        "//asylo/platform/storage/utils:fd_closer",
        "//asylo/platform/system_call/type_conversions",
        "//asylo/test/util:status_matchers",
        "//asylo/test/util:test_flags",
        "//asylo/test/util:test_main",
        "@com_google_absl//absl/base:core_headers",
        "@com_google_absl//absl/container:flat_hash_set",
        "@com_google_absl//absl/flags:flag",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/time",
        "@com_google_googletest//:gtest",
    ],
)

sgx.enclave_configuration(
    name = "many_threads_enclave_config",
    tcs_num = "1000",
)

cc_enclave_test(
    name = "wait_queue_test",
    srcs = ["wait_queue_test.cc"],
    backends = sgx.backend_labels,
    copts = ASYLO_DEFAULT_COPTS,
    enclave_config = ":many_threads_enclave_config",
    deps = [
        "//asylo/platform/host_call",
        "//asylo/util:thread",
        "@com_google_googletest//:gtest",
    ],
)

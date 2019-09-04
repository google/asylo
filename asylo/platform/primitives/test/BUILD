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

load(
    "//asylo/bazel:asylo.bzl",
    "sim_enclave_test",
)
load("//asylo/bazel:sim_enclave.bzl", "primitives_sim_enclave")
load("//asylo/bazel:copts.bzl", "ASYLO_DEFAULT_COPTS")

cc_library(
    name = "test_selectors",
    hdrs = ["test_selectors.h"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = ["//asylo/platform/primitives"],
)

cc_library(
    name = "test_backend",
    testonly = 1,
    hdrs = ["test_backend.h"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        "//asylo/platform/primitives:untrusted_primitives",
        "//asylo/platform/primitives/util:dispatch_table",
        "//asylo/test/util:status_matchers",
    ],
)

primitives_sim_enclave(
    name = "sim_test_enclave.so",
    testonly = 1,
    srcs = ["test_enclave.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":test_selectors",
        "//asylo/platform/primitives",
        "//asylo/platform/primitives:trusted_runtime",
    ],
)

cc_library(
    name = "primitives_test_lib",
    testonly = 1,
    srcs = ["primitives_test.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":test_backend",
        ":test_selectors",
        "//asylo/platform/primitives",
        "//asylo/platform/primitives:trusted_primitives",
        "//asylo/platform/primitives:untrusted_primitives",
        "//asylo/platform/primitives/util:dispatch_table",
        "//asylo/platform/primitives/util:message_reader_writer",
        "//asylo/test/util:status_matchers",
        "//asylo/util:status",
        "//asylo/util:thread",
        "@com_google_absl//absl/debugging:leak_check",
        "@com_google_absl//absl/memory",
        "@com_google_googletest//:gtest",
    ],
    # Required to prevent the linker from dropping the flag symbol.
    alwayslink = 1,
)

cc_library(
    name = "sim_test_backend",
    testonly = 1,
    srcs = ["sim_test_backend.cc"],
    hdrs = ["sim_test_backend.h"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":test_backend",
        "//asylo/platform/primitives:untrusted_primitives",
        "//asylo/platform/primitives/sim:untrusted_sim",
        "//asylo/platform/primitives/util:dispatch_table",
        "//asylo/util:status",
        "@com_google_absl//absl/flags:flag",
        "@com_google_absl//absl/memory",
    ],
    # Required to prevent the linker from dropping the flag symbol.
    alwayslink = 1,
)

cc_library(
    name = "sgx_test_backend",
    testonly = 1,
    srcs = ["sgx_test_backend.cc"],
    hdrs = ["sgx_test_backend.h"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":test_backend",
        "//asylo:enclave_cc_proto",
        "//asylo/platform/primitives:untrusted_primitives",
        "//asylo/platform/primitives/sgx:untrusted_sgx",
        "//asylo/platform/primitives/util:dispatch_table",
        "//asylo/util:status",
        "@com_google_absl//absl/flags:flag",
        "@com_google_absl//absl/memory",
    ],
    # Required to prevent the linker from dropping the flag symbol.
    alwayslink = 1,
)

sim_enclave_test(
    name = "primitives_test",
    size = "small",
    copts = ASYLO_DEFAULT_COPTS,
    enclaves = {"sim": ":sim_test_enclave.so"},
    linkstatic = True,
    test_args = [
        "--enclave_binary='{sim}'",
    ],
    deps = [
        ":primitives_test_lib",
        ":sim_test_backend",
        "//asylo/platform/primitives:untrusted_primitives",
        "//asylo/platform/primitives/sim:untrusted_sim",
        "//asylo/platform/primitives/util:dispatch_table",
        "//asylo/test/util:test_main",
        "//asylo/util:status",
        "@com_google_absl//absl/memory",
    ],
)

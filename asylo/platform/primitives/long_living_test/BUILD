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
    name = "long_living_test_selectors",
    hdrs = ["long_living_test_selectors.h"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = ["//asylo/platform/primitives"],
)

primitives_sim_enclave(
    name = "sim_long_living_test_enclave.so",
    testonly = 1,
    srcs = ["long_living_test_enclave.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":long_living_test_selectors",
        "//asylo/platform/primitives",
        "//asylo/platform/primitives:trusted_runtime",
        "//asylo/util:status_macros",
        "@com_google_absl//absl/time",
    ],
)

cc_library(
    name = "long_living_test_lib",
    testonly = 1,
    srcs = ["long_living_test.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":long_living_test_selectors",
        "//asylo/platform/primitives",
        "//asylo/platform/primitives:trusted_primitives",
        "//asylo/platform/primitives:untrusted_primitives",
        "//asylo/platform/primitives/test:test_backend",
        "//asylo/platform/primitives/util:dispatch_table",
        "//asylo/platform/primitives/util:message_reader_writer",
        "//asylo/test/util:status_matchers",
        "//asylo/test/util:test_main",
        "//asylo/util:logging",
        "//asylo/util:status",
        "@com_google_absl//absl/debugging:leak_check",
        "@com_google_absl//absl/flags:flag",
        "@com_google_absl//absl/memory",
        "@com_google_absl//absl/time",
        "@com_google_googletest//:gtest",
    ],
    # Required to prevent the linker from dropping the flag symbol.
    alwayslink = 1,
)

sim_enclave_test(
    name = "long_living_test",
    size = "small",
    copts = ASYLO_DEFAULT_COPTS,
    enclaves = {
        "sim": ":sim_long_living_test_enclave.so",
    },
    linkstatic = True,
    remote_proxy = "//asylo/util/remote:sim_remote_proxy",
    tags = [
        "exclusive",
    ],
    test_args = [
        "--sleep_time='15s'",
        "--enclave_binary='{sim}'",
    ],
    deps = [
        ":long_living_test_lib",
        "//asylo/platform/primitives",
        "//asylo/platform/primitives:untrusted_primitives",
        "//asylo/platform/primitives/remote:proxy_client",
        "//asylo/platform/primitives/test:remote_sim_test_backend",
        "//asylo/platform/primitives/test:test_backend",
        "//asylo/platform/primitives/util:dispatch_table",
        "//asylo/util:logging",
        "//asylo/util:status",
        "//asylo/util/remote:local_provision",
        "@com_github_grpc_grpc//:grpc++",
        "@com_google_absl//absl/flags:flag",
        "@com_google_absl//absl/strings",
    ],
)

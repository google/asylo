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
    "sim_enclave_loader",
    "sim_enclave_test",
)
load("//asylo/bazel:sim_enclave.bzl", "sim_enclave")
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
        "//asylo/test/util:status_matchers",
    ],
)

sim_enclave(
    name = "sim_test_enclave.so",
    testonly = 1,
    srcs = ["test_enclave.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":test_selectors",
        "//asylo/util:error_codes",
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
        "//asylo/test/util:status_matchers",
        "//asylo/util:status",
        "@com_google_absl//absl/debugging:leak_check",
        "@com_google_absl//absl/memory",
        "@com_google_googletest//:gtest",
    ],
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
        "@com_github_gflags_gflags//:gflags_nothreads",
        "@com_google_absl//absl/memory",
    ],
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
        "//asylo/util:status",
        "@com_github_gflags_gflags//:gflags_nothreads",
        "@com_google_absl//absl/memory",
    ],
)

sim_enclave_test(
    name = "proxy_primitives_test",
    size = "small",
    copts = ASYLO_DEFAULT_COPTS,
    data = [
        ":proxy_test_process",
        ":proxy_test_process_host_loader",
    ],
    enclaves = {"sim": ":sim_test_enclave.so"},
    linkstatic = True,
    tags = [
        "exclusive",
    ],
    test_args = [
        "--proxy_binary='third_party/asylo/platform/primitives/test/proxy_test_process'",
        "--enclave_binary='{sim}'",
    ],
    deps = [
        ":primitives_test_lib",
        ":test_backend",
        "//asylo/platform/primitives",
        "//asylo/platform/primitives:untrusted_primitives",
        "//asylo/platform/primitives/util:dispatch_table",
        "//asylo/util:logging",
        "//asylo/util:status",
        "@com_github_gflags_gflags//:gflags_nothreads",
        "@com_github_grpc_grpc//:grpc++",
        "@com_google_absl//absl/strings",
    ],
)

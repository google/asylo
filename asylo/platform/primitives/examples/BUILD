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
    default_visibility = ["//visibility:public"],
)

load("//asylo/bazel:copts.bzl", "ASYLO_DEFAULT_COPTS")
load(
    "//asylo/bazel:asylo.bzl",
    "sim_enclave_loader",
    "sim_enclave_test",
)
load(
    "//asylo/bazel:sim_enclave.bzl",
    "sim_enclave",
)

sim_enclave(
    name = "hello_enclave.so",
    srcs = [
        "hello_enclave.cc",
        "hello_enclave.h",
    ],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        "//asylo/platform/primitives",
        "//asylo/platform/primitives:trusted_runtime",
        "//asylo/util:status_macros",
    ],
)

sim_enclave_loader(
    name = "hello_driver",
    srcs = [
        "hello_driver.cc",
        "hello_enclave.h",
    ],
    copts = ASYLO_DEFAULT_COPTS,
    enclaves = {"hello": ":hello_enclave.so"},
    deps = [
        "//asylo/platform/primitives",
        "//asylo/platform/primitives:untrusted_primitives",
        "//asylo/platform/primitives/test:sim_test_backend",
        "//asylo/platform/primitives/test:test_backend",
        "//asylo/platform/primitives/util:dispatch_table",
        "//asylo/util:status",
        "@com_github_gflags_gflags//:gflags_nothreads",
    ],
)

sim_enclave_test(
    name = "hello_test",
    size = "small",
    srcs = [
        "hello_enclave.h",
        "hello_test.cc",
    ],
    copts = ASYLO_DEFAULT_COPTS,
    enclaves = {"hello": ":hello_enclave.so"},
    test_args = [
        "--enclave_binary='{hello}'",
    ],
    deps = [
        "//asylo/platform/primitives",
        "//asylo/platform/primitives:trusted_primitives",
        "//asylo/platform/primitives:untrusted_primitives",
        "//asylo/platform/primitives/test:sim_test_backend",
        "//asylo/platform/primitives/test:test_backend",
        "//asylo/platform/primitives/util:dispatch_table",
        "//asylo/test/util:status_matchers",
        "//asylo/test/util:test_main",
        "//asylo/util:status",
        "@com_github_gflags_gflags//:gflags_nothreads",
        "@com_google_absl//absl/memory",
        "@com_google_googletest//:gtest",
    ],
)

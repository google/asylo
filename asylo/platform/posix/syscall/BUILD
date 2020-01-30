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

load(
    "//asylo/bazel:asylo.bzl",
    "ASYLO_ALL_BACKEND_TAGS",
    "cc_enclave_test",
)
load("//asylo/bazel:copts.bzl", "ASYLO_DEFAULT_COPTS")

licenses(["notice"])  # Apache v2.0

package(
    default_visibility = [
        "//asylo:implementation",
    ],
)

cc_library(
    name = "enclave_syscall",
    srcs = [
        "enclave_syscall.cc",
        "enclave_syscall_helper.cc",
    ],
    hdrs = [
        "enclave_syscall.h",
        "enclave_syscall_helper.h",
    ],
    copts = ASYLO_DEFAULT_COPTS,
    linkstatic = 1,
    tags = ASYLO_ALL_BACKEND_TAGS,
    deps = [
        "//asylo/platform/host_call",
        "//asylo/platform/posix/io:io_manager",
        "//asylo/platform/primitives:trusted_primitives",
        "//asylo/platform/system_call",
    ],
    alwayslink = 1,
)

cc_enclave_test(
    name = "enclave_syscall_test",
    srcs = ["enclave_syscall_test.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":enclave_syscall",
        "//asylo/test/util:test_main",
        "@com_google_googletest//:gtest",
    ],
)

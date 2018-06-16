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

load("@linux_sgx//:sgx_sdk.bzl", "sgx_enclave")
load(
    "//asylo/bazel:asylo.bzl",
    "enclave_test",
    "cc_enclave_test",
    "cc_test",
)
load("//asylo/bazel:copts.bzl", "ASYLO_DEFAULT_COPTS")

package(
    default_visibility = [
        "//asylo:implementation",
    ],
)

# POSIX IO and virtual file system implementation.
cc_library(
    name = "io_manager",
    srcs = [
        "io_manager.cc",
        "io_syscalls.cc",
        "native_paths.cc",
        "random_devices.cc",
        "secure_paths.cc",
    ],
    hdrs = [
        "io_manager.h",
        "native_paths.h",
        "random_devices.h",
        "secure_paths.h",
    ],
    linkstatic = 1,
    deps = [
        ":util",
        "//asylo/platform/arch:trusted_arch",
        "//asylo/platform/crypto/gcmlib:trusted_gcmlib",
        "//asylo/platform/storage/secure:trusted_secure",
        "@com_google_absl//absl/algorithm:container",
        "@com_google_absl//absl/memory",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/synchronization",
    ],
)

cc_library(
    name = "util",
    srcs = ["util.cc"],
    hdrs = ["util.h"],
    linkstatic = 1,
    visibility = ["//visibility:private"],
    deps = ["@com_google_absl//absl/strings"],
)

# Test reading and writing to a file from inside an enclave.
cc_enclave_test(
    name = "read_write_test",
    srcs = ["read_write_test.cc"],
    tags = ["regression"],
    deps = [
        "//asylo/test/util:status_matchers",
        "//asylo/test/util:test_flags",
        "//asylo/util:cleansing_types",
        "@com_google_absl//absl/strings",
        "@com_google_googletest//:gtest",
    ],
)

# Test for multi-threaded read/write inside an enclave.
cc_enclave_test(
    name = "read_write_multithread_test",
    srcs = ["read_write_multithread_test.cc"],
    tags = ["regression"],
    deps = [
        "//asylo/test/util:status_matchers",
        "//asylo/test/util:test_flags",
        "@com_google_absl//absl/strings",
        "@com_google_asylo//asylo/util:logging",
        "@com_google_googletest//:gtest",
    ],
)

# Test virtual device handlers inside an enclave.
cc_enclave_test(
    name = "virtual_test",
    srcs = ["virtual_test.cc"],
    tags = ["regression"],
    deps = [
        ":io_manager",
        "//asylo/test/util:status_matchers",
        "@com_google_absl//absl/memory",
        "@com_google_absl//absl/strings",
        "@com_google_googletest//:gtest",
    ],
)

# Test current working directory handling inside an enclave.
cc_enclave_test(
    name = "cwd_test",
    srcs = ["cwd_test.cc"],
    tags = ["regression"],
    deps = [
        ":io_manager",
        "//asylo/test/util:test_flags",
        "@com_google_absl//absl/strings",
        "@com_google_googletest//:gtest",
    ],
)

# Test enclave for routing standard streams to host file descriptors.
sgx_enclave(
    name = "test_pipe.so",
    srcs = ["pipe_test_enclave.cc"],
    deps = [
        ":io_manager",
        "//asylo/test/util:enclave_test_application",
    ],
)

enclave_test(
    name = "pipe_test",
    srcs = ["pipe_test_driver.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    enclaves = {"enclave": ":test_pipe.so"},
    tags = ["regression"],
    test_args = ["--enclave_path='{enclave}'"],
    deps = [
        "//asylo/test/util:enclave_test",
        "//asylo/test/util:status_matchers",
        "//asylo/test/util:test_main",
        "@com_google_asylo//asylo/util:logging",
        "@com_google_googletest//:gtest",
    ],
)

cc_test(
    name = "path_normalization_test",
    size = "small",
    srcs = ["path_normalization_test.cc"],
    enclave_test_name = "enclave_path_normalization_test",
    tags = ["regression"],
    deps = [
        ":util",
        "//asylo/test/util:test_main",
        "@com_google_absl//absl/strings",
        "@com_google_googletest//:gtest",
    ],
)

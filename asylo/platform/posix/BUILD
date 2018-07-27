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

# asylo POSIX interface.

package(
    default_visibility = ["//asylo:implementation"],
)

load("@linux_sgx//:sgx_sdk.bzl", "sgx_enclave")
load("//asylo/bazel:proto.bzl", "asylo_proto_library")
load(
    "//asylo/bazel:asylo.bzl",
    "enclave_test",
    "cc_enclave_test",
)

# Note: this target cannot be a cc_library because the toolchain itself depends
# on these headers, which creates a circular dependency when cc_library adds a
# dependency on the toolchain.
# Note: the toolchain is entrusted to properly resolve and disambiguate included
# system headers in favor of the ones defined here.
filegroup(
    name = "posix_headers",
    srcs = glob(["include/**/*.h"]),
    visibility = ["//visibility:public"],
)

# Generic target exposing trusted POSIX components selected by build
# configuration.
cc_library(
    name = "trusted_posix",
    deps = select({
        "//asylo/platform/arch:sgx": [":posix"],
    }),
)

# POSIX runtime implementation.
cc_library(
    name = "posix",
    srcs = [
        "dirent.cc",
        "errno.cc",
        "grp.cc",
        "ifaddrs.cc",
        "ioctl.cc",
        "mman.cc",
        "poll.cc",
        "pthread.cc",
        "pwd.cc",
        "resource.cc",
        "sched.cc",
        "signal.cc",
        "stat.cc",
        "syslog.cc",
        "termios.cc",
        "time.cc",
        "uio.cc",
        "unistd.cc",
        "utsname.cc",
        "wait.cc",
    ],
    hdrs = [":posix_headers"] + select({
        "//asylo/platform/arch:sgx": ["//asylo/third_party/intel:posix_sgx_headers"],
        "//conditions:default": [],
    }),
    linkstatic = 1,
    visibility = ["//visibility:private"],
    deps = [
        "@com_google_asylo//asylo/util:logging",
        "//asylo/platform/arch:trusted_arch",
        "//asylo/platform/common:bridge_types",
        "//asylo/platform/common:time_util",
        "//asylo/platform/core:shared_name",
        "//asylo/platform/core:trusted_core",
        "//asylo/platform/posix/io:io_manager",
        "//asylo/platform/posix/sockets",
        "//asylo/platform/posix/signal:signal_manager",
        "//asylo/platform/posix/threading:thread_manager",
        "//asylo/platform/system",
        "//asylo/util:status",
    ] + select({
        "//asylo/platform/arch:sgx": ["@linux_sgx//:common_inc"],
        "//conditions:default": [],
    }),
)

# Test byteswap.h posix extension inside an enclave.
cc_enclave_test(
    name = "bswap_test",
    srcs = ["bswap_test.cc"],
    tags = ["regression"],
    deps = [
        "@com_google_googletest//:gtest",
    ],
)

# Test for errno inside an enclave.
cc_enclave_test(
    name = "errno_test",
    srcs = ["errno_test.cc"],
    tags = ["regression"],
    deps = [
        "@com_google_googletest//:gtest",
    ],
)

# A protobuf used by syscalls test. The input contains the target syscall to
# test, and the output contains the output of the syscall inside enclave.
asylo_proto_library(
    name = "syscalls_test_proto",
    srcs = ["syscalls_test.proto"],
    deps = ["//asylo:enclave_proto"],
)

# SGX enclave used to test different syscalls.
sgx_enclave(
    name = "syscalls_test.so",
    srcs = ["syscalls_test_enclave.cc"],
    deps = [
        ":syscalls_test_proto_cc",
        "//asylo/platform/common:bridge_proto_serializer",
        "//asylo/test/util:enclave_test_application",
        "//asylo/util:status",
        "@com_google_asylo//asylo/util:logging",
    ],
)

enclave_test(
    name = "syscalls_test",
    srcs = ["syscalls_test_driver.cc"],
    enclaves = {"enclave": ":syscalls_test.so"},
    tags = ["regression"],
    test_args = ["--enclave_path='{enclave}'"],
    deps = [
        ":syscalls_test_proto_cc",
        "//asylo:enclave_client",
        "//asylo/platform/common:bridge_proto_serializer",
        "//asylo/test/util:enclave_test",
        "//asylo/test/util:test_main",
        "//asylo/util:status",
        "@com_google_absl//absl/strings",
        "@com_google_asylo//asylo/util:logging",
        "@com_google_googletest//:gtest",
    ],
)

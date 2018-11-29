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
    "cc_test",
)
load("//asylo/bazel:copts.bzl", "ASYLO_DEFAULT_COPTS")

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
    copts = ASYLO_DEFAULT_COPTS,
    deps = select({
        "//asylo/platform/arch:sgx": [":posix"],
    }),
)

cc_library(
    name = "pthread_impl",
    hdrs = ["pthread_impl.h"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = ["//asylo/util:logging"],
)

# POSIX runtime implementation.
cc_library(
    name = "posix",
    srcs = [
        "dirent.cc",
        "epoll.cc",
        "errno.cc",
        "eventfd.cc",
        "file.cc",
        "grp.cc",
        "ifaddrs.cc",
        "inotify.cc",
        "ioctl.cc",
        "malloc_lock.cc",
        "math.cc",
        "mman.cc",
        "poll.cc",
        "pthread.cc",
        "pwd.cc",
        "resource.cc",
        "sched.cc",
        "select.cc",
        "signal.cc",
        "stat.cc",
        "stdlib.cc",
        "syslog.cc",
        "termios.cc",
        "time.cc",
        "uio.cc",
        "unistd.cc",
        "utime.cc",
        "utsname.cc",
        "wait.cc",
    ],
    hdrs = [
        ":posix_headers",
    ] + select({
        "//asylo/platform/arch:sgx": ["//asylo/third_party/intel:posix_sgx_headers"],
        "//conditions:default": [],
    }),
    copts = ASYLO_DEFAULT_COPTS,
    linkstatic = 1,
    visibility = ["//visibility:private"],
    deps = [
        ":pthread_impl",
        "@com_google_absl//absl/container:flat_hash_map",
        "@com_google_absl//absl/synchronization",
        "//asylo/util:logging",
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
        "//asylo/platform/arch:sgx": ["@linux_sgx//:trts"],
        "//conditions:default": [],
    }),
)

# Test byteswap.h posix extension inside an enclave.
cc_enclave_test(
    name = "bswap_test",
    srcs = ["bswap_test.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        "@com_google_googletest//:gtest",
    ],
)

# Test for errno inside an enclave.
cc_enclave_test(
    name = "errno_test",
    srcs = ["errno_test.cc"],
    copts = ASYLO_DEFAULT_COPTS,
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
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":syscalls_test_proto_cc",
        "//asylo/platform/common:bridge_proto_serializer",
        "//asylo/test/util:enclave_test_application",
        "//asylo/util:logging",
        "//asylo/util:status",
        "@com_google_absl//absl/container:flat_hash_set",
    ],
)

cc_test(
    name = "select_test",
    srcs = ["select_test.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    enclave_test_name = "select_enclave_test",
    deps = [
        "//asylo/platform/storage/utils:fd_closer",
        "//asylo/test/util:status_matchers",
        "//asylo/test/util:test_main",
        "//asylo/util:status",
        "@com_google_absl//absl/strings",
        "@com_google_googletest//:gtest",
    ],
)

enclave_test(
    name = "syscalls_test",
    srcs = ["syscalls_test_driver.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    enclaves = {"enclave": ":syscalls_test.so"},
    test_args = ["--enclave_path='{enclave}'"],
    deps = [
        ":syscalls_test_proto_cc",
        "//asylo:enclave_client",
        "//asylo/platform/common:bridge_proto_serializer",
        "//asylo/test/util:enclave_test",
        "//asylo/test/util:test_main",
        "//asylo/util:logging",
        "//asylo/util:status",
        "@com_google_absl//absl/container:flat_hash_set",
        "@com_google_absl//absl/strings",
        "@com_google_googletest//:gtest",
    ],
)

cc_enclave_test(
    name = "times_test",
    srcs = ["times_test.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        "@com_google_googletest//:gtest",
    ],
)

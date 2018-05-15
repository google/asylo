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

load("//asylo/bazel:asylo.bzl", "cc_enclave_test")

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
        "src/dirent.cc",
        "src/errno.cc",
        "src/grp.cc",
        "src/ioctl.cc",
        "src/poll.cc",
        "src/pthread.cc",
        "src/pwd.cc",
        "src/sched.cc",
        "src/signal.cc",
        "src/stat.cc",
        "src/time.cc",
        "src/uio.cc",
        "src/unistd.cc",
        "src/utsname.cc",
        "src/wait.cc",
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
    srcs = ["test/bswap_test.cc"],
    tags = ["regression"],
    deps = [
        "@com_google_googletest//:gtest",
    ],
)

# Test for errno inside an enclave.
cc_enclave_test(
    name = "errno_test",
    srcs = ["test/errno_test.cc"],
    tags = ["regression"],
    deps = [
        "@com_google_googletest//:gtest",
    ],
)

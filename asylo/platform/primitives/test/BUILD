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

load("@rules_cc//cc:defs.bzl", "cc_library")
load("//asylo/bazel:copts.bzl", "ASYLO_DEFAULT_COPTS")
load("//asylo/bazel:dlopen_enclave.bzl", "dlopen_enclave_test", "primitives_dlopen_enclave")

licenses(["notice"])

package(
    default_visibility = ["//asylo:implementation"],
)

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

primitives_dlopen_enclave(
    name = "dlopen_test_enclave.so",
    testonly = 1,
    srcs = ["test_enclave.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":test_selectors",
        "//asylo/platform/primitives",
        "//asylo/platform/primitives:trusted_runtime",
        "//asylo/platform/primitives/util:message_reader_writer",
        "//asylo/util:status_macros",
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
        "@com_google_absl//absl/status",
        "@com_google_googletest//:gtest",
    ],
    # Required to prevent the linker from dropping the flag symbol.
    alwayslink = 1,
)

cc_library(
    name = "dlopen_test_backend",
    testonly = 1,
    srcs = ["dlopen_test_backend.cc"],
    hdrs = ["dlopen_test_backend.h"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":test_backend",
        "//asylo/platform/primitives:untrusted_primitives",
        "//asylo/platform/primitives/dlopen:untrusted_dlopen",
        "//asylo/platform/primitives/util:dispatch_table",
        "//asylo/util:error_codes",
        "//asylo/util:status",
        "@com_google_absl//absl/flags:flag",
        "@com_google_absl//absl/memory",
        "@com_google_absl//absl/status",
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

dlopen_enclave_test(
    name = "primitives_test",
    size = "small",
    copts = ASYLO_DEFAULT_COPTS,
    enclaves = {"enclave_binary": ":dlopen_test_enclave.so"},
    linkstatic = True,
    test_args = [
        "--enclave_binary='{enclave_binary}'",
    ],
    deps = [
        ":dlopen_test_backend",
        ":primitives_test_lib",
        "//asylo/platform/primitives:untrusted_primitives",
        "//asylo/platform/primitives/dlopen:untrusted_dlopen",
        "//asylo/platform/primitives/util:dispatch_table",
        "//asylo/test/util:test_main",
        "//asylo/util:status",
        "@com_google_absl//absl/memory",
    ],
)

cc_library(
    name = "remote_test_backend",
    testonly = 1,
    srcs = ["remote_test_backend.cc"],
    hdrs = ["remote_test_backend.h"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":test_backend",
        "//asylo:enclave_cc_proto",
        "//asylo/platform/primitives:untrusted_primitives",
        "//asylo/platform/primitives/remote:proxy_client",
        "//asylo/platform/primitives/util:dispatch_table",
        "//asylo/test/util:test_flags",
        "//asylo/util:logging",
        "//asylo/util:path",
        "//asylo/util:status",
        "//asylo/util/remote:provision",
        "//asylo/util/remote:remote_loader_cc_proto",
        "@com_github_grpc_grpc//:grpc++",
        "@com_google_absl//absl/flags:flag",
        "@com_google_absl//absl/strings",
    ],
    # Required to prevent the linker from dropping the flag symbols.
    alwayslink = 1,
)

cc_library(
    name = "remote_dlopen_test_backend",
    testonly = 1,
    srcs = ["remote_dlopen_test_backend.cc"],
    hdrs = ["remote_dlopen_test_backend.h"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":remote_test_backend",
        "//asylo/platform/primitives:untrusted_primitives",
        "//asylo/platform/primitives/dlopen:loader_cc_proto",
        "//asylo/test/util:test_flags",
        "//asylo/util:path",
        "//asylo/util/remote:remote_loader_cc_proto",
        "@com_google_absl//absl/flags:flag",
        "@com_google_absl//absl/strings",
    ],
    # Required to prevent the linker from dropping the flag symbols.
    alwayslink = 1,
)

cc_library(
    name = "remote_sgx_test_backend",
    testonly = 1,
    srcs = ["remote_sgx_test_backend.cc"],
    hdrs = ["remote_sgx_test_backend.h"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":remote_test_backend",
        "//asylo/platform/primitives:untrusted_primitives",
        "//asylo/platform/primitives/sgx:loader_cc_proto",
        "//asylo/test/util:test_flags",
        "//asylo/util:path",
        "//asylo/util/remote:remote_loader_cc_proto",
        "@com_google_absl//absl/flags:flag",
        "@com_google_absl//absl/strings",
    ],
    # Required to prevent the linker from dropping the flag symbols.
    alwayslink = 1,
)

dlopen_enclave_test(
    name = "dlopen_proxy_primitives_test",
    size = "medium",  # Can run more than a minute.
    copts = ASYLO_DEFAULT_COPTS,
    enclaves = {
        "enclave_binary": ":dlopen_test_enclave.so",
    },
    linkstatic = True,
    remote_proxy = "//asylo/util/remote:dlopen_remote_proxy",
    tags = [
        "exclusive",
    ],
    test_args = [
        "--enclave_binary='{enclave_binary}'",
    ],
    deps = [
        ":primitives_test_lib",
        ":remote_dlopen_test_backend",
        ":test_backend",
        "//asylo/platform/primitives",
        "//asylo/platform/primitives:untrusted_primitives",
        "//asylo/platform/primitives/remote:proxy_client",
        "//asylo/platform/primitives/util:dispatch_table",
        "//asylo/test/util:test_main",
        "//asylo/util:logging",
        "//asylo/util:status",
        "//asylo/util/remote:local_provision",
        "@com_github_grpc_grpc//:grpc++",
        "@com_google_absl//absl/flags:flag",
        "@com_google_absl//absl/strings",
    ],
)

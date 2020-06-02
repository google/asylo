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

load("@linux_sgx//:sgx_sdk.bzl", "sgx")
load("@rules_cc//cc:defs.bzl", "cc_proto_library", "cc_test")
load("@rules_proto//proto:defs.bzl", "proto_library")
load(
    "//asylo/bazel:asylo.bzl",
    "cc_enclave_test",
    "cc_unsigned_enclave",
    "debug_sign_enclave",
    "enclave_test",
)
load("//asylo/bazel:copts.bzl", "ASYLO_DEFAULT_COPTS")

licenses(["notice"])

proto_library(
    name = "proto_test_proto",
    srcs = ["proto_test.proto"],
    deps = ["//asylo:enclave_proto"],
)

cc_proto_library(
    name = "proto_test_cc_proto",
    deps = [":proto_test_proto"],
)

cc_enclave_test(
    name = "random_test",
    srcs = ["random_test.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        "//asylo/platform/posix/io:io_manager",
        "//asylo/platform/storage/utils:fd_closer",
        "//asylo/test/util:status_matchers",
        "//asylo/util:logging",
        "//asylo/util:status",
        "@boringssl//:crypto",
        "@com_google_absl//absl/memory",
        "@com_google_absl//absl/strings",
        "@com_google_googletest//:gtest",
    ],
)

cc_unsigned_enclave(
    name = "test_proto_unsigned.so",
    srcs = ["proto_test_enclave.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":proto_test_cc_proto",
        "//asylo/platform/posix/io:io_manager",
        "//asylo/test/util:enclave_test_application",
        "//asylo/util:logging",
        "@com_google_absl//absl/memory",
    ],
)

debug_sign_enclave(
    name = "test_proto.so",
    unsigned = "test_proto_unsigned.so",
)

enclave_test(
    name = "proto_test",
    srcs = ["proto_test_driver.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    enclaves = {"enclave": ":test_proto.so"},
    test_args = ["--enclave_path='{enclave}'"],
    deps = [
        ":proto_test_cc_proto",
        "//asylo/test/util:enclave_test",
        "//asylo/test/util:status_matchers",
        "//asylo/test/util:test_main",
        "//asylo/util:logging",
        "@com_google_googletest//:gtest",
    ],
)

cc_unsigned_enclave(
    name = "getenv_test_enclave_unsigned.so",
    srcs = ["getenv_test_enclave.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":proto_test_cc_proto",
        "//asylo/test/util:enclave_test_application",
        "//asylo/util:logging",
        "//asylo/util:status_macros",
        "@com_google_absl//absl/strings",
    ],
)

debug_sign_enclave(
    name = "getenv_test_enclave.so",
    unsigned = "getenv_test_enclave_unsigned.so",
)

enclave_test(
    name = "getenv_test",
    srcs = ["getenv_test_driver.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    enclaves = {"enclave": ":getenv_test_enclave.so"},
    test_args = ["--enclave_path='{enclave}'"],
    deps = [
        ":proto_test_cc_proto",
        "//asylo:enclave_cc_proto",
        "//asylo/test/util:enclave_test",
        "//asylo/test/util:status_matchers",
        "//asylo/test/util:test_main",
        "//asylo/util:logging",
        "@com_google_googletest//:gtest",
    ],
)

cc_unsigned_enclave(
    name = "enclave_api_test_proto_unsigned.so",
    srcs = ["enclave_api_test_enclave.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":proto_test_cc_proto",
        "//asylo/platform/posix/io:io_manager",
        "//asylo/test/util:enclave_test_application",
        "//asylo/util:logging",
        "@com_google_absl//absl/memory",
    ],
)

debug_sign_enclave(
    name = "enclave_api_test_proto.so",
    unsigned = "enclave_api_test_proto_unsigned.so",
)

enclave_test(
    name = "enclave_api_test",
    srcs = ["enclave_api_test_driver.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    enclaves = {"enclave": ":enclave_api_test_proto.so"},
    test_args = ["--enclave_path='{enclave}'"],
    deps = [
        ":proto_test_cc_proto",
        "//asylo/test/util:enclave_test",
        "//asylo/test/util:status_matchers",
        "//asylo/test/util:test_main",
        "//asylo/util:logging",
        "@com_google_googletest//:gtest",
    ],
)

# Tests of the untrusted resource management API.
cc_test(
    name = "shared_resource_test",
    srcs = ["shared_resource_test.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        "//asylo/platform/core:untrusted_core",
        "//asylo/test/util:test_main",
        "@com_google_googletest//:gtest",
    ],
)

sgx.enclave_configuration(
    name = "many_threads_enclave_config",
    tcs_num = "1000",
)

cc_enclave_test(
    name = "lock_test",
    srcs = ["lock_test.cc"],
    backends = sgx.backend_labels,
    copts = ASYLO_DEFAULT_COPTS,
    enclave_config = ":many_threads_enclave_config",
    deps = [
        "//asylo/platform/core:trusted_mutex",
        "//asylo/platform/core:trusted_spin_lock",
        "@com_google_googletest//:gtest",
    ],
)

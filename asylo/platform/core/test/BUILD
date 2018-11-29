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

# Enclave test cases.

load("@linux_sgx//:sgx_sdk.bzl", "sgx_enclave", "sgx_enclave_configuration")
load(
    "//asylo/bazel:asylo.bzl",
    "enclave_test",
    "cc_enclave_test",
)
load("//asylo/bazel:proto.bzl", "asylo_proto_library")
load("//asylo/bazel:copts.bzl", "ASYLO_DEFAULT_COPTS")

asylo_proto_library(
    name = "config_test_proto",
    srcs = ["proto_test.proto"],
    deps = ["//asylo:enclave_proto"],
)

cc_enclave_test(
    name = "random_test",
    srcs = ["random_test.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        "//asylo/platform/posix/io:io_manager",
        "@boringssl//:crypto",
        "@com_google_absl//absl/memory",
        "@com_google_absl//absl/strings",
        "@com_google_googletest//:gtest",
    ],
)

sgx_enclave(
    name = "test_proto.so",
    srcs = ["proto_test_enclave.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":config_test_proto_cc",
        "//asylo/platform/posix/io:io_manager",
        "//asylo/test/util:enclave_test_application",
        "@com_google_absl//absl/memory",
    ],
)

enclave_test(
    name = "proto_test",
    srcs = ["proto_test_driver.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    enclaves = {"enclave": ":test_proto.so"},
    test_args = ["--enclave_path='{enclave}'"],
    deps = [
        ":config_test_proto_cc",
        "//asylo/test/util:enclave_test",
        "//asylo/test/util:status_matchers",
        "//asylo/test/util:test_main",
        "//asylo/util:logging",
        "@com_google_googletest//:gtest",
    ],
)

sgx_enclave(
    name = "getenv_test_enclave.so",
    srcs = ["getenv_test_enclave.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":config_test_proto_cc",
        "//asylo:enclave_proto_cc",
        "//asylo/test/util:enclave_test_application",
        "@com_google_absl//absl/strings",
    ],
)

enclave_test(
    name = "getenv_test",
    srcs = ["getenv_test_driver.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    enclaves = {"enclave": ":getenv_test_enclave.so"},
    test_args = ["--enclave_path='{enclave}'"],
    deps = [
        ":config_test_proto_cc",
        "//asylo:enclave_proto_cc",
        "//asylo/test/util:enclave_test",
        "//asylo/test/util:status_matchers",
        "//asylo/test/util:test_main",
        "//asylo/util:logging",
        "@com_google_googletest//:gtest",
    ],
)

sgx_enclave(
    name = "enclave_api_test_proto.so",
    srcs = ["enclave_api_test_enclave.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":config_test_proto_cc",
        "//asylo/platform/posix/io:io_manager",
        "//asylo/test/util:enclave_test_application",
        "@com_google_absl//absl/memory",
    ],
)

enclave_test(
    name = "enclave_api_test",
    srcs = ["enclave_api_test_driver.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    enclaves = {"enclave": ":enclave_api_test_proto.so"},
    test_args = ["--enclave_path='{enclave}'"],
    deps = [
        ":config_test_proto_cc",
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

sgx_enclave_configuration(
    name = "many_threads_enclave_config",
    tcs_num = "1000",
)

cc_enclave_test(
    name = "lock_test",
    srcs = ["lock_test.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    enclave_config = ":many_threads_enclave_config",
    deps = [
        "//asylo/platform/core:trusted_mutex",
        "//asylo/platform/core:trusted_spin_lock",
        "//asylo/platform/core:untrusted_mutex",
        "@com_google_googletest//:gtest",
    ],
)

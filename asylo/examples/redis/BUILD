#
# Copyright 2019 Asylo authors
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

load("@linux_sgx//:sgx_sdk.bzl", "sgx", "sgx_enclave_configuration")
load("@rules_cc//cc:defs.bzl", "cc_library")
load(
    "//asylo/bazel:asylo.bzl",
    "cc_enclave_binary",
    "enclave_test",
)
load("//asylo/bazel:copts.bzl", "ASYLO_DEFAULT_COPTS")

licenses(["notice"])

# An implementation of ApplicationConfig() that returns an EnclaveConfig with
# an SGX local assertion authority config.
cc_library(
    name = "redis_enclave_config",
    srcs = ["redis_enclave_config.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    visibility = ["//visibility:public"],
    deps = [
        "//asylo:enclave_cc_proto",
        "//asylo/identity:descriptions",
        "//asylo/identity:enclave_assertion_authority_config_cc_proto",
        "//asylo/identity/attestation/sgx:sgx_local_assertion_authority_config_cc_proto",
        "//asylo/util:logging",
    ],
)

# The SGX configuration to run Redis Server inside an enclave.
sgx_enclave_configuration(
    name = "redis_enclave_configuration",
    heap_max_size = "0x1000000",
    stack_max_size = "0x400000",
)

# The whole application wrapper target that runs Redis server inside an enclave.
cc_enclave_binary(
    name = "asylo_redis",
    application_enclave_config = ":redis_enclave_config",
    enclave_build_config = ":redis_enclave_configuration",
    deps = ["@com_github_antirez_redis//:redis_main"],
)

enclave_test(
    name = "redis_test",
    srcs = ["redis_test.cc"],
    backend_dependent_data = [
        ":asylo_redis_host_loader",
    ],
    backends = sgx.backend_labels,
    copts = ASYLO_DEFAULT_COPTS,
    data = ["@com_github_antirez_redis//:redis_cli_bin"],
    tags = ["exclusive"],
    test_args = [
        "--server_path=$(rootpath :asylo_redis_host_loader)",
        "--client_path=$(rootpath @com_github_antirez_redis//:redis_cli_bin)",
    ],
    deps = [
        "//asylo/test/util:exec_tester",
        "//asylo/test/util:status_matchers",
        "//asylo/test/util:test_flags",
        "//asylo/test/util:test_main",
        "//asylo/util:status",
        "@bazel_tools//tools/cpp/runfiles",
        "@com_google_absl//absl/base:core_headers",
        "@com_google_absl//absl/flags:flag",
        "@com_google_absl//absl/memory",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/synchronization",
        "@com_google_googletest//:gtest",
    ],
)

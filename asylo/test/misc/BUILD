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
    "copy_from_host",
    "cc_enclave_test",
    "cc_test",
)
load("//asylo/bazel:copts.bzl", "ASYLO_DEFAULT_COPTS")
load("//asylo/bazel:proto.bzl", "asylo_proto_library")

# A protobuf used by signal tests. The input contains whether to register a
# signal hander sa_handler, which takes a single argument signum, or
# sa_sigaction, which takes three arguments: signum, siginfo, and ucontext.
asylo_proto_library(
    name = "signal_test_proto",
    srcs = ["signal_test.proto"],
    deps = ["//asylo:enclave_proto"],
)

# Trivial SGX enclave.
sgx_enclave(
    name = "hello_world.so",
    srcs = ["hello_world.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        "//asylo/test/util:enclave_test_application",
    ],
)

# Enclave that attempts to forcibly create a global constructor/destructor; if
# this fails to build, then our compiler's behaving improperly.
sgx_enclave(
    name = "initfini.so",
    srcs = ["initfini.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        "//asylo/test/util:enclave_test_application",
    ],
)

# SGX enclave used to test signal handling inside an enclave with an active TCS.
sgx_enclave(
    name = "active_enclave_signal_test.so",
    srcs = ["active_enclave_signal_test_enclave.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":signal_test_proto_cc",
        "//asylo/test/util:enclave_test_application",
    ],
)

# SGX enclave used to test signal handling inside an enclave with no active TCS.
sgx_enclave(
    name = "inactive_enclave_signal_test.so",
    srcs = ["inactive_enclave_signal_test_enclave.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":signal_test_proto_cc",
        "//asylo/test/util:enclave_test_application",
    ],
)

# SGX enclave linked against the sgx_runtime that calls abort().
sgx_enclave(
    name = "die.so",
    srcs = ["die.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        "//asylo:enclave_runtime",
        "@linux_sgx//:trts",
    ],
)

# SGX enclave throws exception.
sgx_enclave(
    name = "exception.so",
    srcs = ["exception_enclave.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":exception",
        "//asylo:enclave_runtime",
        "//asylo/test/util:enclave_test_application",
        "//asylo/util:status",
        "@com_google_absl//absl/base:core_headers",
    ],
)

# SGX enclave testing logging.
sgx_enclave(
    name = "logging.so",
    srcs = ["logging_test_enclave.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        "//asylo/test/util:enclave_test_application",
        "//asylo/util:logging",
        "//asylo/util:status",
    ],
)

# Common exception class for inside and outside enclave.
cc_library(
    name = "exception",
    srcs = ["exception.cc"],
    hdrs = ["exception.h"],
    copts = ASYLO_DEFAULT_COPTS,
)

# Smoke tests for enclaves; currently identical to hello_world.so.
sgx_enclave(
    name = "test_enclave_smoke.so",
    srcs = ["hello_world.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        "//asylo/test/util:enclave_test_application",
    ],
)

# SGX enclave that returns various errors across the enclave boundary.
sgx_enclave(
    name = "error_propagation_enclave.so",
    srcs = ["error_propagation_enclave.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        "//asylo/test/util:enclave_test_application",
        "//asylo/util:logging",
        "//asylo/util:status",
    ],
)

TEST_DEPS_COMMON = [
    "@com_google_googletest//:gtest",
    "@com_google_absl//absl/memory",
    "//asylo:enclave_client",
    "//asylo/util:logging",
    "//asylo/test/util:enclave_test",
    "//asylo/test/util:status_matchers",
    "//asylo/test/util:test_main",
    "//asylo/util:status",
]

# Smoke tests for enclaves; currently identical to hello_world_test.
enclave_test(
    name = "enclave_smoke_test",
    srcs = ["hello_world_test.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    enclaves = {"enclave": ":test_enclave_smoke.so"},
    test_args = ["--enclave_path='{enclave}'"],
    deps = TEST_DEPS_COMMON,
)

cc_enclave_test(
    name = "threaded_test",
    srcs = ["threaded_test.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        "@com_google_absl//absl/strings",
        "@com_google_googletest//:gtest",
    ],
)

sgx_enclave_configuration(
    name = "exhaust_sgx_tcs_config",
    tcs_num = "3",
)

sgx_enclave(
    name = "exhaust_sgx_tcs.so",
    testonly = 1,
    srcs = ["exhaust_sgx_tcs.cc"],
    config = ":exhaust_sgx_tcs_config",
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        "//asylo/test/util:enclave_test_application",
        "//asylo/util:status",
    ],
)

# Note that a naive enclave simulator that does not respect the enclave
# configuration will not pass this test.
enclave_test(
    name = "exhaust_sgx_tcs_test",
    srcs = ["exhaust_sgx_tcs_test.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    enclaves = {"enclave": ":exhaust_sgx_tcs.so"},
    tags = ["noregression"],
    test_args = ["--enclave_path='{enclave}'"],
    deps = TEST_DEPS_COMMON,
)

cc_enclave_test(
    name = "threaded_test_in_initialize",
    srcs = ["threaded_test.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    test_in_initialize = True,
    deps = [
        "@com_google_absl//absl/strings",
        "@com_google_googletest//:gtest",
    ],
)

cc_enclave_test(
    name = "rdrand_test",
    srcs = ["rdrand_test.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        "@com_google_googletest//:gtest",
    ],
)

cc_enclave_test(
    name = "nanosleep_test",
    srcs = ["nanosleep_test.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        "@com_google_googletest//:gtest",
    ],
)

cc_enclave_test(
    name = "malloc_stress_test",
    srcs = ["malloc_stress_test.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        "@com_google_absl//absl/strings",
        "@com_google_googletest//:gtest",
    ],
)

cc_enclave_test(
    name = "pthread_test",
    srcs = ["pthread_test.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        "//asylo/test/util:status_matchers",
        "//asylo/util:logging",
        "//asylo/util:status",
        "@com_google_absl//absl/synchronization",
        "@com_google_googletest//:gtest",
    ],
)

cc_enclave_test(
    name = "mutex_test",
    srcs = ["mutex_test.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        "//asylo/test/util:status_matchers",
        "//asylo/test/util:test_util",
        "//asylo/util:logging",
        "//asylo/util:status",
        "@com_google_absl//absl/synchronization",
        "@com_google_googletest//:gtest",
    ],
)

cc_enclave_test(
    name = "condvar_test",
    srcs = ["condvar_test.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        "//asylo/test/util:status_matchers",
        "//asylo/test/util:test_util",
        "//asylo/util:logging",
        "//asylo/util:status",
        "@com_google_absl//absl/synchronization",
        "@com_google_googletest//:gtest",
    ],
)

cc_enclave_test(
    name = "sem_test",
    srcs = ["sem_test.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    tags = ["noregression"],
    deps = [
        "//asylo/test/util:status_matchers",
        "//asylo/test/util:test_util",
        "//asylo/util:logging",
        "//asylo/util:status",
        "@com_google_absl//absl/synchronization",
        "@com_google_googletest//:gtest",
    ],
)

cc_enclave_test(
    name = "memory_layout_test",
    srcs = ["memory_layout_test.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        "//asylo/test/util:status_matchers",
        "//asylo/test/util:test_util",
        "//asylo/util:logging",
        "//asylo/util:status",
        "@com_google_absl//absl/synchronization",
        "@com_google_googletest//:gtest",
    ],
)

cc_test(
    name = "raise_signal_test",
    srcs = ["raise_signal_test.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    enclave_test_name = "raise_signal_enclave_test",
    deps = [
        "//asylo/test/util:test_main",
        "@com_google_googletest//:gtest",
    ],
)

enclave_test(
    name = "active_enclave_signal_test",
    srcs = ["active_enclave_signal_test_driver.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    enclaves = {"enclave": "active_enclave_signal_test.so"},
    tags = ["noregression"],
    test_args = ["--enclave_path='{enclave}'"],
    deps = [
        ":signal_test_proto_cc",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/synchronization",
    ] + TEST_DEPS_COMMON,
)

enclave_test(
    name = "inactive_enclave_signal_test",
    srcs = ["inactive_enclave_signal_test_driver.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    enclaves = {"enclave": "inactive_enclave_signal_test.so"},
    test_args = ["--enclave_path='{enclave}'"],
    deps = [
        ":signal_test_proto_cc",
    ] + TEST_DEPS_COMMON,
)

enclave_test(
    name = "error_propagation_test",
    srcs = ["error_propagation_test.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    enclaves = {"enclave": ":error_propagation_enclave.so"},
    test_args = ["--enclave_path='{enclave}'"],
    deps = TEST_DEPS_COMMON,
)

enclave_test(
    name = "logging_test",
    srcs = ["logging_test_driver.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    enclaves = {"enclave": ":logging.so"},
    test_args = ["--enclave_path='{enclave}'"],
    deps = [
        "//asylo/test/util:test_flags",
    ] + TEST_DEPS_COMMON,
)

cc_binary(
    name = "double_die",
    testonly = 1,
    srcs = ["double_die.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        "//asylo:enclave_client",
        "@com_google_absl//absl/memory",
    ],
)

copy_from_host(
    output = "double_die_host_bin",
    target = "double_die",
)

enclave_test(
    name = "die_test",
    srcs = ["die_test.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    data = [":double_die_host_bin"],
    enclaves = {"enclave": ":die.so"},
    test_args = ["--enclave_path='{enclave}'"],
    deps = [
        "//asylo/test/util:exec_tester",
    ] + TEST_DEPS_COMMON,
)

cc_binary(
    name = "exception_app",
    testonly = 1,
    srcs = ["exception_app.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        "//asylo:enclave_client",
        "//asylo/test/util:enclave_test_launcher",
    ],
)

copy_from_host(
    output = "exception_app_host_bin",
    target = "exception_app",
)

enclave_test(
    name = "exception_test",
    srcs = ["exception_test.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    data = [":exception_app_host_bin"],
    enclaves = {"enclave": ":exception.so"},
    test_args = ["--enclave_path='{enclave}'"],
    deps = [
        ":exception",
        "//asylo/test/util:exec_tester",
    ] + TEST_DEPS_COMMON,
)

# The name of the ELF section to use for testing in embedded_enclave_test.
TEST_SECTION_NAME = "enclave"

# Tests that embedded enclaves work.
enclave_test(
    name = "embedded_enclave_test",
    srcs = ["embedded_enclave_test_driver.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    embedded_enclaves = {TEST_SECTION_NAME: "//asylo/test/util:do_nothing_enclave.so"},
    test_args = [
        "--enclave_section",
        TEST_SECTION_NAME,
    ],
    deps = [
        "//asylo:enclave_client",
        "//asylo:enclave_proto_cc",
        "//asylo/test/util:status_matchers",
        "//asylo/test/util:test_main",
        "@com_github_gflags_gflags//:gflags_nothreads",
        "@com_google_googletest//:gtest",
    ],
)

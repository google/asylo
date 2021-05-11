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

# Enclave test cases.

load("@com_google_asylo_backend_provider//:transitions.bzl", "transitions")
load("@linux_sgx//:sgx_sdk.bzl", "sgx")
load("@rules_cc//cc:defs.bzl", "cc_library", "cc_proto_library")
load("@rules_proto//proto:defs.bzl", "proto_library")
load(
    "//asylo/bazel:asylo.bzl",
    "cc_enclave_test",
    "cc_test",
    "cc_unsigned_enclave",
    "debug_sign_enclave",
    "enclave_test",
)
load("//asylo/bazel:copts.bzl", "ASYLO_DEFAULT_COPTS")
load("//asylo/bazel:sgx_rules.bzl", "sgx_debug_sign_enclave", "sgx_enclave_test")

licenses(["notice"])

# A protobuf used by block enclave entries test. The input contains whether the
# thread entering the enclave is to block/unblock entries, or the thread that
# tests whether the entries are blocked. It also contains a socket fd that is
# used between the two threads to inform whether block/unblock is done.
proto_library(
    name = "block_enclave_entries_test_proto",
    srcs = ["block_enclave_entries_test.proto"],
    deps = ["//asylo:enclave_proto"],
)

cc_proto_library(
    name = "block_enclave_entries_test_cc_proto",
    deps = [":block_enclave_entries_test_proto"],
)

# A protobuf used by signal tests. The input contains whether to register a
# signal hander sa_handler, which takes a single argument signum, or
# sa_sigaction, which takes three arguments: signum, siginfo, and ucontext.
proto_library(
    name = "signal_test_proto",
    srcs = ["signal_test.proto"],
    deps = ["//asylo:enclave_proto"],
)

cc_proto_library(
    name = "signal_test_cc_proto",
    deps = [":signal_test_proto"],
)

proto_library(
    name = "enclave_entry_count_test_proto",
    srcs = ["enclave_entry_count_test.proto"],
    deps = ["//asylo:enclave_proto"],
)

cc_proto_library(
    name = "enclave_entry_count_test_cc_proto",
    deps = [":enclave_entry_count_test_proto"],
)

# Trivial enclave.
cc_unsigned_enclave(
    name = "hello_world_unsigned.so",
    srcs = ["hello_world.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        "//asylo/test/util:enclave_test_application",
    ],
)

debug_sign_enclave(
    name = "hello_world.so",
    unsigned = ":hello_world_unsigned.so",
)

# Enclave that attempts to forcibly create a global constructor/destructor; if
# this fails to build, then our compiler's behaving improperly.
debug_sign_enclave(
    name = "initfini.so",
    unsigned = ":initfini_unsigned.so",
)

cc_unsigned_enclave(
    name = "initfini_unsigned.so",
    srcs = ["initfini.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        "//asylo/test/util:enclave_test_application",
    ],
)

# Enclave used to test enclave entry counting.
debug_sign_enclave(
    name = "enclave_entry_count_test.so",
    unsigned = ":enclave_entry_count_test_unsigned.so",
)

cc_unsigned_enclave(
    name = "enclave_entry_count_test_unsigned.so",
    srcs = ["enclave_entry_count_test_enclave.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":enclave_entry_count_test_cc_proto",
        "//asylo/platform/primitives:trusted_runtime",
        "//asylo/test/util:enclave_test_application",
        "//asylo/util:status",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/synchronization",
    ],
)

# Enclave used to test signal handling inside an enclave with an active TCS.
cc_unsigned_enclave(
    name = "active_enclave_signal_test_unsigned.so",
    srcs = ["active_enclave_signal_test_enclave.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":signal_test_cc_proto",
        "//asylo/test/util:enclave_test_application",
        "//asylo/util:posix_errors",
        "//asylo/util:status",
    ],
)

debug_sign_enclave(
    name = "active_enclave_signal_test.so",
    unsigned = ":active_enclave_signal_test_unsigned.so",
)

# Enclave used to test signal handling inside an enclave with no active TCS.
cc_unsigned_enclave(
    name = "inactive_enclave_signal_test_unsigned.so",
    srcs = ["inactive_enclave_signal_test_enclave.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":signal_test_cc_proto",
        "//asylo/test/util:enclave_test_application",
        "//asylo/util:status",
        "@com_google_absl//absl/status",
    ],
)

debug_sign_enclave(
    name = "inactive_enclave_signal_test.so",
    unsigned = ":inactive_enclave_signal_test_unsigned.so",
)

# Enclave that calls abort().
cc_unsigned_enclave(
    name = "die_unsigned.so",
    srcs = ["die.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        "//asylo:enclave_runtime",
        "@com_google_absl//absl/status",
    ],
)

debug_sign_enclave(
    name = "die.so",
    unsigned = ":die_unsigned.so",
)

# Enclave throws exception.
cc_unsigned_enclave(
    name = "exception_unsigned.so",
    srcs = ["exception_enclave.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    tags = [
        "manual",
    ],
    deps = [
        ":exception",
        "//asylo:enclave_runtime",
        "//asylo/test/util:enclave_test_application",
        "//asylo/util:status",
        "@com_google_absl//absl/base:core_headers",
        "@com_google_absl//absl/status",
    ],
)

debug_sign_enclave(
    name = "exception.so",
    unsigned = ":exception_unsigned.so",
)

# Enclave testing logging.
cc_unsigned_enclave(
    name = "logging_unsigned.so",
    srcs = ["logging_test_enclave.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        "//asylo/test/util:enclave_test_application",
        "//asylo/util:logging",
        "//asylo/util:status",
    ],
)

debug_sign_enclave(
    name = "logging.so",
    unsigned = ":logging_unsigned.so",
)

# Common exception class for inside and outside enclave.
cc_library(
    name = "exception",
    srcs = ["exception.cc"],
    hdrs = ["exception.h"],
    copts = ASYLO_DEFAULT_COPTS,
)

# Smoke tests for enclaves; currently identical to hello_world.so.
cc_unsigned_enclave(
    name = "test_enclave_smoke_unsigned.so",
    srcs = ["hello_world.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        "//asylo/platform/primitives:trusted_primitives",
        "//asylo/test/util:enclave_test_application",
    ],
)

debug_sign_enclave(
    name = "test_enclave_smoke.so",
    unsigned = ":test_enclave_smoke_unsigned.so",
)

# Enclave that returns various errors across the enclave boundary.
cc_unsigned_enclave(
    name = "error_propagation_enclave_unsigned.so",
    srcs = ["error_propagation_enclave.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        "//asylo/test/util:enclave_test_application",
        "//asylo/util:logging",
        "//asylo/util:posix_errors",
        "//asylo/util:status",
        "@com_google_absl//absl/status",
    ],
)

debug_sign_enclave(
    name = "error_propagation_enclave.so",
    unsigned = ":error_propagation_enclave_unsigned.so",
)

# Enclave used to test blocking enclave entries.
cc_unsigned_enclave(
    name = "block_enclave_entries_test_unsigned.so",
    srcs = ["block_enclave_entries_test_enclave.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":block_enclave_entries_test_cc_proto",
        "//asylo/platform/host_call",
        "//asylo/platform/primitives:trusted_runtime",
        "//asylo/test/util:enclave_test_application",
        "//asylo/util:posix_errors",
        "//asylo/util:status",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/strings",
    ],
)

debug_sign_enclave(
    name = "block_enclave_entries_test.so",
    unsigned = ":block_enclave_entries_test_unsigned.so",
)

# Smoke tests for enclaves; currently identical to hello_world_test.
enclave_test(
    name = "enclave_smoke_test",
    srcs = ["hello_world_test.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    enclaves = {"enclave": ":test_enclave_smoke.so"},
    test_args = ["--enclave_path='{enclave}'"],
    deps = [
        "//asylo:enclave_client",
        "//asylo/test/util:enclave_test",
        "//asylo/test/util:status_matchers",
        "//asylo/test/util:test_main",
        "//asylo/util:logging",
        "//asylo/util:status",
        "@com_google_absl//absl/memory",
        "@com_google_googletest//:gtest",
    ],
)

sgx.enclave_configuration(
    name = "threaded_test_config",
    tcs_num = "55",
)

cc_enclave_test(
    name = "threaded_test",
    srcs = ["threaded_test.cc"],
    backends = sgx.backend_labels,  # Uses SGX-specific configuration.
    copts = ASYLO_DEFAULT_COPTS,
    enclave_config = ":threaded_test_config",
    deps = [
        "@com_google_absl//absl/container:flat_hash_set",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/synchronization",
        "@com_google_absl//absl/time",
        "@com_google_googletest//:gtest",
    ],
)

# Test to illustrate how absl::Now never returns in sgx-gdb
cc_enclave_test(
    name = "now_test",
    srcs = ["now_test.cc"],
    backends = sgx.backend_labels,  # Uses SGX-specific configuration.
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        "@com_google_absl//absl/time",
        "@com_google_googletest//:gtest",
    ],
)

sgx.enclave_configuration(
    name = "exhaust_sgx_tcs_config",
    tcs_num = "3",
)

cc_unsigned_enclave(
    name = "exhaust_sgx_tcs_unsigned.so",
    testonly = 1,
    srcs = ["exhaust_sgx_tcs.cc"],
    backends = sgx.backend_labels,  # Uses SGX-specific configuration.
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        "//asylo/test/util:enclave_test_application",
        "//asylo/util:status",
        "@com_google_absl//absl/memory",
        "@com_google_absl//absl/synchronization",
    ],
)

sgx_debug_sign_enclave(
    name = "exhaust_sgx_tcs.so",
    testonly = 1,
    config = ":exhaust_sgx_tcs_config",
    unsigned = ":exhaust_sgx_tcs_unsigned.so",
)

# Note that a naive enclave simulator that does not respect the enclave
# configuration will not pass this test.
sgx_enclave_test(
    name = "exhaust_sgx_tcs_test",
    srcs = ["exhaust_sgx_tcs_test.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    enclaves = {"enclave": ":exhaust_sgx_tcs.so"},
    tags = [
        "noregression",
    ],
    test_args = ["--enclave_path='{enclave}'"],
    deps = [
        "//asylo:enclave_client",
        "//asylo/test/util:enclave_test",
        "//asylo/test/util:status_matchers",
        "//asylo/test/util:test_main",
        "//asylo/util:logging",
        "//asylo/util:status",
        "@com_google_absl//absl/memory",
        "@com_google_absl//absl/status",
        "@com_google_googletest//:gtest",
    ],
)

cc_enclave_test(
    name = "threaded_test_in_initialize",
    srcs = ["threaded_test.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    enclave_config = ":threaded_test_config",
    test_in_initialize = True,
    deps = [
        "@com_google_absl//absl/container:flat_hash_set",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/synchronization",
        "@com_google_absl//absl/time",
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
        "//asylo/platform/primitives:trusted_backend",
        "//asylo/util:binary_search",
        "//asylo/util:logging",
        "@com_google_absl//absl/strings",
        "@com_google_googletest//:gtest",
    ],
)

cc_enclave_test(
    name = "pthread_test",
    srcs = ["pthread_test.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        "//asylo/platform/posix:pthread_impl",
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
        "//asylo/test/util:pthread_test_util",
        "//asylo/test/util:status_matchers",
        "//asylo/util:logging",
        "//asylo/util:status",
        "@com_google_absl//absl/base:core_headers",
        "@com_google_absl//absl/synchronization",
        "@com_google_googletest//:gtest",
    ],
)

sgx.enclave_configuration(
    name = "condvar_test_config",
    # Condvar tests use 8 threads each, so bump the TCS to ensure we never
    # run too close to the default limit.
    tcs_num = "20",
)

cc_enclave_test(
    name = "condvar_test",
    srcs = ["condvar_test.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    enclave_config = ":condvar_test_config",
    deps = [
        "//asylo/platform/common:time_util",
        "//asylo/test/util:pthread_test_util",
        "//asylo/test/util:status_matchers",
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
        "//asylo/platform/common:time_util",
        "//asylo/test/util:pthread_test_util",
        "//asylo/test/util:status_matchers",
        "//asylo/util:logging",
        "//asylo/util:status",
        "@com_google_absl//absl/synchronization",
        "@com_google_googletest//:gtest",
    ],
)

cc_enclave_test(
    name = "rwlock_test",
    srcs = ["rwlock_test.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        "//asylo/platform/common:time_util",
        "//asylo/test/util:pthread_test_util",
        "//asylo/test/util:status_matchers",
        "//asylo/test/util:test_main",
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
        "//asylo/platform/primitives:trusted_backend",
        "//asylo/platform/primitives:trusted_primitives",
        "@com_google_absl//absl/memory",
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
    name = "enclave_entry_count_test",
    srcs = ["enclave_entry_count_test_driver.cc"],
    backends = sgx.backend_labels,
    copts = ASYLO_DEFAULT_COPTS,
    enclaves = {"enclave": "enclave_entry_count_test.so"},
    test_args = ["--enclave_path='{enclave}'"],
    deps = [
        ":enclave_entry_count_test_cc_proto",
        "//asylo:enclave_client",
        "//asylo/test/util:enclave_test",
        "//asylo/test/util:status_matchers",
        "//asylo/test/util:test_main",
        "//asylo/util:logging",
        "//asylo/util:status",
        "@com_google_absl//absl/memory",
        "@com_google_absl//absl/status",
        "@com_google_googletest//:gtest",
    ],
)

enclave_test(
    name = "active_enclave_signal_test",
    srcs = ["active_enclave_signal_test_driver.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    enclaves = {"enclave": "active_enclave_signal_test.so"},
    test_args = ["--enclave_path='{enclave}'"],
    deps = [
        ":signal_test_cc_proto",
        "//asylo:enclave_client",
        "//asylo/test/util:enclave_test",
        "//asylo/test/util:status_matchers",
        "//asylo/test/util:test_main",
        "//asylo/util:logging",
        "//asylo/util:posix_errors",
        "//asylo/util:status",
        "@com_google_absl//absl/memory",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/synchronization",
        "@com_google_googletest//:gtest",
    ],
)

enclave_test(
    name = "inactive_enclave_signal_test",
    srcs = ["inactive_enclave_signal_test_driver.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    enclaves = {"enclave": "inactive_enclave_signal_test.so"},
    test_args = ["--enclave_path='{enclave}'"],
    deps = [
        ":signal_test_cc_proto",
        "//asylo:enclave_client",
        "//asylo/test/util:enclave_test",
        "//asylo/test/util:status_matchers",
        "//asylo/test/util:test_main",
        "//asylo/util:logging",
        "//asylo/util:status",
        "@com_google_absl//absl/memory",
        "@com_google_absl//absl/status",
        "@com_google_googletest//:gtest",
    ],
)

enclave_test(
    name = "error_propagation_test",
    srcs = ["error_propagation_test.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    enclaves = {"enclave": ":error_propagation_enclave.so"},
    test_args = ["--enclave_path='{enclave}'"],
    deps = [
        "//asylo:enclave_client",
        "//asylo/test/util:enclave_test",
        "//asylo/test/util:status_matchers",
        "//asylo/test/util:test_main",
        "//asylo/util:logging",
        "//asylo/util:posix_error_matchers",
        "//asylo/util:status",
        "@com_google_absl//absl/memory",
        "@com_google_absl//absl/status",
        "@com_google_googletest//:gtest",
    ],
)

enclave_test(
    name = "logging_test",
    srcs = ["logging_test_driver.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    enclaves = {"enclave": ":logging.so"},
    test_args = ["--enclave_path='{enclave}'"],
    deps = [
        "//asylo:enclave_client",
        "//asylo/test/util:enclave_test",
        "//asylo/test/util:status_matchers",
        "//asylo/test/util:test_flags",
        "//asylo/test/util:test_main",
        "//asylo/util:logging",
        "//asylo/util:status",
        "@com_google_absl//absl/flags:flag",
        "@com_google_absl//absl/memory",
        "@com_google_googletest//:gtest",
    ],
)

enclave_test(
    name = "block_enclave_entries_test",
    srcs = ["block_enclave_entries_test_driver.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    enclaves = {"enclave": "block_enclave_entries_test.so"},
    test_args = ["--enclave_path='{enclave}'"],
    deps = [
        ":block_enclave_entries_test_cc_proto",
        "//asylo:enclave_client",
        "//asylo/platform/storage/utils:fd_closer",
        "//asylo/test/util:enclave_test",
        "//asylo/test/util:status_matchers",
        "//asylo/test/util:test_main",
        "//asylo/util:logging",
        "//asylo/util:status",
        "@com_google_absl//absl/memory",
        "@com_google_googletest//:gtest",
    ],
)

transitions.cc_binary(
    name = "double_die",
    testonly = 1,
    srcs = ["double_die.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    linkstatic = 1,
    deps = [
        "//asylo:enclave_cc_proto",
        "//asylo:enclave_client",
        "//asylo/platform/primitives/sgx:loader_cc_proto",
        "@com_google_absl//absl/memory",
        "@com_google_googletest//:gtest",
    ],
)

sgx_enclave_test(
    name = "die_test",
    srcs = ["die_test.cc"],
    backend_dependent_data = [":double_die"],
    copts = ASYLO_DEFAULT_COPTS,
    enclaves = {"enclave": ":die.so"},
    test_args = [
        "--enclave_path='{enclave}'",
        "--loader_path=$(rootpath :double_die)",
    ],
    deps = [
        "//asylo:enclave_client",
        "//asylo/test/util:enclave_test",
        "//asylo/test/util:exec_tester",
        "//asylo/test/util:status_matchers",
        "//asylo/test/util:test_main",
        "//asylo/util:logging",
        "//asylo/util:status",
        "@com_google_absl//absl/flags:flag",
        "@com_google_absl//absl/memory",
        "@com_google_googletest//:gtest",
    ],
)

transitions.cc_binary(
    name = "exception_app",
    testonly = 1,
    linkstatic = 1,
    srcs = ["exception_app.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        "//asylo:enclave_client",
        "//asylo/test/util:enclave_test_launcher",
        "//asylo/util:logging",
    ],
)

enclave_test(
    name = "exception_test",
    srcs = ["exception_test.cc"],
    backend_dependent_data = [":exception_app"],
    copts = ASYLO_DEFAULT_COPTS,
    enclaves = {"enclave": ":exception.so"},
    test_args = [
        "--enclave_path='{enclave}'",
        "--loader_path=$(rootpath :exception_app)",
    ],
    deps = [
        ":exception",
        "//asylo:enclave_client",
        "//asylo/test/util:enclave_test",
        "//asylo/test/util:exec_tester",
        "//asylo/test/util:status_matchers",
        "//asylo/test/util:test_main",
        "//asylo/util:logging",
        "//asylo/util:status",
        "@com_google_absl//absl/flags:flag",
        "@com_google_absl//absl/memory",
        "@com_google_absl//absl/strings",
        "@com_google_googletest//:gtest",
    ],
)

# The name of the ELF section to use for testing in embedded_enclave_test.
TEST_SECTION_NAME = "enclave"

# Tests that embedded enclaves work.
sgx_enclave_test(
    name = "embedded_enclave_test",
    srcs = ["embedded_enclave_test_driver.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    embedded_enclaves = {TEST_SECTION_NAME: "//asylo/test/util:do_nothing_enclave.so"},
    test_args = [
        "--enclave_section",
        TEST_SECTION_NAME,
    ],
    deps = [
        "//asylo:enclave_cc_proto",
        "//asylo:enclave_client",
        "//asylo/platform/primitives/sgx:loader_cc_proto",
        "//asylo/test/util:status_matchers",
        "//asylo/test/util:test_main",
        "@com_google_absl//absl/flags:flag",
        "@com_google_googletest//:gtest",
    ],
)

cc_unsigned_enclave(
    name = "threaded_finalize_unsigned.so",
    srcs = ["threaded_finalize.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        "//asylo:enclave_cc_proto",
        "//asylo:enclave_runtime",
        "//asylo/test/util:enclave_test_application",
        "//asylo/util:status",
        "@com_google_absl//absl/status",
    ],
)

debug_sign_enclave(
    name = "threaded_finalize.so",
    unsigned = ":threaded_finalize_unsigned.so",
)

sgx_enclave_test(
    name = "threaded_finalize_test",
    srcs = ["hello_world_test.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    enclaves = {"enclave": ":threaded_finalize.so"},
    test_args = ["--enclave_path='{enclave}'"],
    deps = [
        "//asylo:enclave_client",
        "//asylo/test/util:enclave_test",
        "//asylo/test/util:status_matchers",
        "//asylo/test/util:test_main",
        "//asylo/util:logging",
        "//asylo/util:status",
        "@com_google_absl//absl/memory",
        "@com_google_googletest//:gtest",
    ],
)

cc_unsigned_enclave(
    name = "fail_finalize_enclave_unsigned.so",
    srcs = ["fail_finalize_enclave.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        "//asylo:enclave_runtime",
        "@com_google_absl//absl/status",
    ],
)

debug_sign_enclave(
    name = "fail_finalize_enclave.so",
    unsigned = ":fail_finalize_enclave_unsigned.so",
)

sgx_enclave_test(
    name = "fail_finalize_enclave_test",
    size = "small",
    srcs = ["fail_finalize_enclave_test.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    embedded_enclaves = {"enclave": ":fail_finalize_enclave.so"},
    deps = [
        "//asylo:enclave_cc_proto",
        "//asylo:enclave_client",
        "//asylo/platform/primitives/sgx:loader_cc_proto",
        "//asylo/test/util:status_matchers",
        "//asylo/test/util:test_main",
        "@com_google_googletest//:gtest",
    ],
)

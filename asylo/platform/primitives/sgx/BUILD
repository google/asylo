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

load("@linux_sgx//:sgx_sdk.bzl", "sgx")
load("@rules_cc//cc:defs.bzl", "cc_library", "cc_proto_library")
load("@rules_proto//proto:defs.bzl", "proto_library")
load("//asylo/bazel:asylo.bzl", "cc_enclave_test", "cc_test")
load("//asylo/bazel:copts.bzl", "ASYLO_DEFAULT_COPTS")

licenses(["notice"])

package(
    default_visibility = ["//asylo:implementation"],
)

# Enclave loader for locally loaded SGX enclaves.
cc_library(
    name = "enclave_loader",
    srcs = ["enclave_loader.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":loader_cc_proto",
        ":untrusted_sgx",
        "//asylo:enclave_cc_proto",
        "//asylo/platform/primitives:enclave_loader_hdr",
        "//asylo/platform/primitives:untrusted_primitives",
        "//asylo/platform/primitives/util:dispatch_table",
        "//asylo/platform/primitives/util:exit_log",
        "//asylo/util:status",
        "//asylo/util:status_macros",
        "@com_google_absl//absl/status",
    ],
)

cc_library(
    name = "sgx_params",
    hdrs = ["sgx_params.h"],
    copts = ASYLO_DEFAULT_COPTS,
)

# Trusted runtime components for SGX.
_TRUSTED_SGX_BACKEND_DEPS = [
    ":sgx_errors",
    ":trusted_sgx_bridge",
    "//asylo:enclave_cc_proto",
    "//asylo/util:logging",
    "//asylo/platform/posix/signal:signal_manager",
    "//asylo/platform/posix/threading:thread_manager",
    "//asylo/platform/primitives",
    "//asylo/platform/primitives:random_bytes",
    "//asylo/platform/primitives/util:trusted_runtime_helper",
    "//asylo/util:error_codes",
    "//asylo/util:status",
    "@linux_sgx//:public",
    "@linux_sgx//:trts",
]

_TRUSTED_SGX_HW_SRCS = [
    "register_signal_sgx_hw.cc",
]

_TRUSTED_SGX_SIM_SRCS = [
    "register_signal_sgx_sim.cc",
]

cc_library(
    name = "trusted_sgx",
    srcs = [
        "exceptions.cc",
        "trusted_runtime.cc",
        "trusted_sgx.cc",
        "enclave_syscalls.cc",
        "untrusted_cache_malloc.cc",
    ] + select(
        {
            "@linux_sgx//:sgx_hw": _TRUSTED_SGX_HW_SRCS,
            "@linux_sgx//:sgx_sim": _TRUSTED_SGX_SIM_SRCS,
        },
        no_match_error = "Expected an SGX backend configuration",
    ),
    hdrs = [
        "trusted_sgx.h",
        "untrusted_cache_malloc.h",
    ],
    copts = ["-faligned-new"],
    tags = [
        "asylo-sgx",
        "manual",
    ],
    deps = select(
        {
            "@com_google_asylo//asylo": [
                "//asylo/platform/core:trusted_spin_lock",
                "//asylo/platform/posix/memory",
                "//asylo/platform/primitives:trusted_primitives",
                "//asylo/platform/primitives:trusted_runtime",
                "//asylo/platform/primitives/util:trusted_memory",
                "//asylo/platform/system_call/type_conversions",
            ],
        },
        no_match_error = "Must be built in the Asylo toolchain",
    ) + select(
        {
            "@linux_sgx//:sgx_hw": _TRUSTED_SGX_BACKEND_DEPS,
            "@linux_sgx//:sgx_sim": _TRUSTED_SGX_BACKEND_DEPS,
        },
        no_match_error = "Trusted SGX components must be built with an SGX backend selected",
    ) + [
        ":sgx_params",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/strings",
        "//asylo/util:lock_guard",
        "//asylo/platform/primitives/util:message_reader_writer",
        "//asylo/util:cleanup",
        "@com_google_absl//absl/memory",
        "@sgx_dcap//:quote_wrapper_common",
    ],
    alwayslink = 1,
)

cc_library(
    name = "untrusted_sgx",
    srcs = [
        "generated_bridge_u.c",
        "ocalls.cc",
        "signal_dispatcher.cc",
        "untrusted_sgx.cc",
    ],
    hdrs = [
        "generated_bridge_u.h",
        "signal_dispatcher.h",
        "untrusted_sgx.h",
    ],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":exit_handlers",
        ":fork_cc_proto",
        ":loader_cc_proto",
        ":sgx_errors",
        ":sgx_params",
        "//asylo:enclave_cc_proto",
        "//asylo/platform/common:memory",
        "//asylo/platform/primitives:untrusted_primitives",
        "//asylo/platform/primitives/util:dispatch_table",
        "//asylo/platform/primitives/util:message_reader_writer",
        "//asylo/platform/storage/utils:fd_closer",
        "//asylo/platform/system_call/type_conversions",
        "//asylo/util:cleanup",
        "//asylo/util:elf_reader",
        "//asylo/util:file_mapping",
        "//asylo/util:function_deleter",
        "//asylo/util:logging",
        "//asylo/util:posix_errors",
        "//asylo/util:status",
        "//asylo/util:status_helpers",
        "//asylo/util:status_macros",
        "@com_google_absl//absl/base:core_headers",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/strings",
        "@linux_sgx//:public",
        "@linux_sgx//:urts",
        "@sgx_dcap//:pce_wrapper",
        "@sgx_dcap//:quote_wrapper",
    ],
)

proto_library(
    name = "sgx_error_code_proto",
    srcs = ["sgx_error_code.proto"],
)

cc_proto_library(
    name = "sgx_error_code_cc_proto",
    deps = [":sgx_error_code_proto"],
)

cc_library(
    name = "sgx_error_matchers",
    testonly = 1,
    srcs = ["sgx_error_matchers.cc"],
    hdrs = ["sgx_error_matchers.h"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":sgx_errors",
        "//asylo/test/util:status_matchers",
        "//asylo/util:status",
        "@com_google_googletest//:gtest",
        "@linux_sgx//:public",
    ],
)

cc_library(
    name = "sgx_errors",
    srcs = ["sgx_errors.cc"],
    hdrs = ["sgx_errors.h"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":sgx_error_code_cc_proto",
        "//asylo/util:status",
        "//asylo/util:status_helpers",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/strings:cord",
        "@com_google_absl//absl/types:optional",
        "@linux_sgx//:public",
    ],
)

cc_test(
    name = "sgx_errors_test",
    srcs = ["sgx_errors_test.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    enclave_test_name = "sgx_errors_enclave_test",
    deps = [
        ":sgx_error_matchers",
        ":sgx_errors",
        "//asylo/test/util:status_matchers",
        "//asylo/test/util:test_main",
        "//asylo/util:status",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/strings",
        "@com_google_googletest//:gtest",
        "@linux_sgx//:public",
    ],
)

# Message definitions for SGX enclave loader.
proto_library(
    name = "loader_proto",
    srcs = ["loader.proto"],
    visibility = ["//visibility:public"],
    deps = [
        "//asylo:enclave_proto",
    ],
)

cc_proto_library(
    name = "loader_cc_proto",
    visibility = ["//visibility:public"],
    deps = [":loader_proto"],
)

cc_library(
    name = "exit_handlers",
    srcs = ["exit_handlers.cc"],
    hdrs = ["exit_handlers.h"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        "//asylo/platform/primitives:untrusted_primitives",
        "//asylo/platform/primitives/util:message_reader_writer",
        "//asylo/util:logging",
        "//asylo/util:status",
        "//asylo/util:status_macros",
        "//asylo/util:thread",
        "@com_google_absl//absl/status",
    ],
)

cc_library(
    name = "sgx_remote_proxy_lib",
    srcs = ["sgx_remote_proxy.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":loader_cc_proto",
        ":untrusted_sgx",
        "//asylo:enclave_cc_proto",
        "//asylo/platform/arch:untrusted_arch",
        "//asylo/platform/primitives",
        "//asylo/platform/primitives:untrusted_primitives",
        "//asylo/platform/primitives/remote/util:remote_proxy_lib",
        "//asylo/platform/primitives/util:message_reader_writer",
        "//asylo/util:error_codes",
        "//asylo/util:logging",
        "//asylo/util:status",
        "//asylo/util/remote:remote_loader_cc_proto",
        "@com_google_absl//absl/memory",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/strings",
    ],
    alwayslink = 1,
)

# Protobuf used by fork.
proto_library(
    name = "fork_proto",
    srcs = ["fork.proto"],
    visibility = ["//visibility:public"],
    deps = ["//asylo:enclave_proto"],
)

cc_proto_library(
    name = "fork_cc_proto",
    visibility = ["//visibility:public"],
    deps = [":fork_proto"],
)

# Fork related runtime.
_TRUSTED_FORK_HW_DEPS = [
    ":trusted_sgx",
    "@com_google_absl//absl/base:core_headers",
    "//asylo/crypto:aead_cryptor",
    "//asylo/crypto/util:bssl_util",
    "//asylo/crypto/util:byte_container_view",
    "//asylo/crypto/util:trivial_object_util",
    "//asylo/platform/posix/memory:memory",
    "//asylo/util:logging",
    "//asylo/grpc/auth/core:client_ekep_handshaker",
    "//asylo/grpc/auth/core:server_ekep_handshaker",
    "//asylo/identity:descriptions",
    "//asylo/identity:identity_acl_evaluator",
    "//asylo/identity/attestation/sgx:sgx_local_assertion_generator",
    "//asylo/identity/attestation/sgx:sgx_local_assertion_verifier",
    "//asylo/identity/platform/sgx:sgx_identity_expectation_matcher",
    "//asylo/identity/platform/sgx:sgx_identity_util",
    "//asylo/util:cleansing_types",
    "//asylo/util:cleanup",
    "//asylo/util:posix_errors",
    "@boringssl//:crypto",
]

cc_library(
    name = "trusted_fork",
    srcs = ["fork.cc"] + select({
        "@linux_sgx//:sgx_hw": ["fork_sgx_hw.cc"],
        "//conditions:default": ["fork_sgx_sim.cc"],
    }),
    hdrs = [
        "fork.h",
        "fork_internal.h",
    ],
    copts = ASYLO_DEFAULT_COPTS,
    linkstatic = 1,
    tags = [
        "asylo-sgx",
        "manual",
    ],
    deps = [
        ":fork_cc_proto",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/strings",
        "//asylo:enclave_cc_proto",
        "//asylo/platform/core:trusted_core",
        "//asylo/platform/host_call",
        "//asylo/platform/posix/threading:thread_manager",
        "//asylo/platform/primitives/util:status_serializer",
        "//asylo/util:status",
    ] + select(
        {"@com_google_asylo//asylo": [
            "//asylo/platform/primitives:trusted_primitives",
            "//asylo/platform/primitives:trusted_runtime",
        ]},
        no_match_error = "Must be built in Asylo toolchain",
    ) + select({
        "@linux_sgx//:sgx_hw": _TRUSTED_FORK_HW_DEPS,
        "@linux_sgx//:sgx_sim": [":trusted_sgx"],
        "//conditions:default": [],
    }),
)

sgx.enclave_configuration(
    name = "many_threads_enclave_config",
    tcs_num = "1000",
)

cc_enclave_test(
    name = "untrusted_cache_malloc_test",
    srcs = ["untrusted_cache_malloc_test.cc"],
    backends = sgx.backend_labels,
    copts = ASYLO_DEFAULT_COPTS,
    enclave_config = ":many_threads_enclave_config",
    deps = [
        ":trusted_sgx",
        "@com_google_googletest//:gtest",
    ],
)

# Command to invoke the sgx edger8r tool to generate the bridge code.

ASYLO_PREFIX = "external/com_google_asylo/"

SGX_EDGER8R_COMMAND = (
    "./$(location @linux_sgx//:sgx_edger8r) " +
    "$(location bridge.edl) " +
    "--search-path " + ASYLO_PREFIX + "asylo/platform/primitives/sgx " +
    "--search-path asylo/platform/primitives/sgx " +
    "--search-path $(@D) " +  # Reference previously generated files
    "--trusted --trusted-dir $(@D)/ " +
    "--untrusted --untrusted-dir $(@D)/"
)

# Command to update the generated bridge files and header paths for the
# SDK dependencies.

SGX_PREFIX = ""

UPDATE_SDK_DEPS_COMMAND = (
    "for file in $$(ls $(@D)/bridge_*.[ch]); do " +
    "sed -i " +
    "-e '1s!^!// Generated file. See bridge.edl\\n!' " +
    "-e 's!bridge_u.h!generated_bridge_u.h!' " +
    "-e 's!bridge_t.h!generated_bridge_t.h!' " +
    "-e 's!sgx_trts.h!" + SGX_PREFIX + "include/sgx_trts.h!' " +
    "-e 's!sgx_edger8r.h!" + SGX_PREFIX + "include/sgx_edger8r.h!' " +
    "-e 's!sgx_lfence.h!" + SGX_PREFIX + "include/sgx_lfence.h!' " +
    "-e 's!<mbusafecrt.h>!\"" + SGX_PREFIX + "include/se_memcpy.h\"!' " +
    "$$file && " +
    "mv $$file $$(dirname $$file)/generated_$$(basename $$file); " +
    "done"
)

# The bridge code generated by the Intel SGX SDK edger8r tool.
genrule(
    name = "generate_bridge",
    srcs = [
        "bridge.edl",
        "errno.edl",
        "//asylo/third_party/intel:sgx_tstdc.edl",
    ],
    outs = [
        "generated_bridge_t.c",
        "generated_bridge_t.h",
        "generated_bridge_u.c",
        "generated_bridge_u.h",
    ],
    cmd = (SGX_EDGER8R_COMMAND + " && " + UPDATE_SDK_DEPS_COMMAND),
    tools = ["@linux_sgx//:sgx_edger8r"],
)

cc_library(
    name = "trusted_sgx_ecalls",
    srcs = [
        "ecalls.cc",
    ],
    copts = ASYLO_DEFAULT_COPTS,
    linkstatic = 1,
    tags = [
        "asylo-sgx",
        "manual",
    ],
    deps = [
        ":trusted_fork",
        ":trusted_sgx",
        "@com_google_absl//absl/memory",
        "@com_google_absl//absl/strings",
        "//asylo/platform/common:memory",
        "//asylo/platform/core:entry_points",
        "//asylo/platform/core:shared_name",
        "//asylo/platform/host_call",
        "//asylo/platform/primitives:trusted_primitives",
    ] + select(
        {
            "@linux_sgx//:sgx_hw": _TRUSTED_SGX_BACKEND_DEPS,
            "@linux_sgx//:sgx_sim": _TRUSTED_SGX_BACKEND_DEPS,
        },
        no_match_error = "Must be built in SGX backend",
    ),
    alwayslink = 1,
)

# Trusted side of the SGX SDK generated bridge.
_TRUSTED_SGX_BRIDGE_BACKEND_DEPS = ["@linux_sgx//:public"]

cc_library(
    name = "trusted_sgx_bridge",
    srcs = ["generated_bridge_t.c"],
    hdrs = [
        "generated_bridge_t.h",
    ],
    copts = ASYLO_DEFAULT_COPTS,
    linkstatic = 1,
    tags = [
        "asylo-sgx",
        "manual",
    ],
    deps = select(
        {
            "@linux_sgx//:sgx_hw": _TRUSTED_SGX_BRIDGE_BACKEND_DEPS,
            "@linux_sgx//:sgx_sim": _TRUSTED_SGX_BRIDGE_BACKEND_DEPS,
        },
        no_match_error = "Must be built in SGX backend",
    ) + select(
        {"@com_google_asylo//asylo": ["@linux_sgx//:trts"]},
        no_match_error = "Must be built in Asylo toolchain",
    ) + [
        "@sgx_dcap//:quote_wrapper_common",
    ],
)

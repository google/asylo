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

licenses(["notice"])  # Apache v2.0

package(
    default_visibility = ["//asylo:implementation"],
)

exports_files([
    "bridge.edl",
    "errno.edl",
])

load("//asylo/bazel:copts.bzl", "ASYLO_DEFAULT_COPTS")

cc_library(
    name = "sgx_params",
    hdrs = ["sgx_params.h"],
    copts = ASYLO_DEFAULT_COPTS,
)

# Trusted runtime components for SGX.
cc_library(
    name = "trusted_sgx",
    srcs = [
        "exceptions.cc",
        "trusted_runtime.cc",
        "trusted_sgx.cc",
    ] + select(
        {
            "@linux_sgx//:sgx_hw": [
                "hardware_random_sgx_hw.cc",
                "register_signal_sgx_hw.cc",
            ],
            "@linux_sgx//:sgx_sim": [
                "hardware_random_sgx_sim.cc",
                "register_signal_sgx_sim.cc",
            ],
        },
        no_match_error = "Expected an SGX backend configuration (e.g., --config=sgx)",
    ),
    hdrs = ["trusted_sgx.h"],
    copts = select(
        {
            "@linux_sgx//:sgx_hw": [
                "-mrdrnd",  # All SGX chips also support RDRAND
            ],
            "@linux_sgx//:sgx_sim": [],
        },
        "Must be built for SGX hardware or simulation backend",
    ) + ASYLO_DEFAULT_COPTS,
    tags = [
        "asylo-sgx",
        "manual",
    ],
    deps = select(
        {
            "//asylo/platform/primitives:asylo_sgx": [
                "//asylo/platform/primitives",
                "//asylo/util:logging",
                "//asylo/platform/primitives:trusted_primitives",
                "//asylo/platform/primitives:trusted_runtime",
                "//asylo/platform/primitives/util:primitive_locks",
                "//asylo/platform/primitives/util:trusted_runtime_helper",
                "//asylo/platform/primitives/x86:spin_lock",
                "//asylo/util:error_codes",
                "//asylo/platform/arch:trusted_sgx_bridge",
                "//asylo/util:status",
                "//asylo/platform/primitives/sgx:sgx_error_space",
                "@linux_sgx//:public",
                "@linux_sgx//:trts",
                "//asylo/platform/posix/threading:thread_manager",
                "//asylo/platform/common:bridge_types",
                "//asylo/platform/posix/signal:signal_manager",
            ],
        },
        no_match_error = "Trusted SGX components must be built with --define=ASYLO_SGX=1",
    ) + [
        ":sgx_params",
        "@com_google_absl//absl/strings",
        "//asylo/platform/primitives/util:message_reader_writer",
        "//asylo/util:cleanup",
    ],
)

cc_library(
    name = "untrusted_sgx",
    srcs = ["untrusted_sgx.cc"],
    hdrs = ["untrusted_sgx.h"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":exit_handlers",
        ":fork_cc_proto",
        ":sgx_error_space",
        ":sgx_params",
        "//asylo:enclave_cc_proto",
        "//asylo/platform/common:bridge_types",
        "//asylo/platform/primitives:untrusted_primitives",
        "//asylo/platform/primitives/util:message_reader_writer",
        "//asylo/util:cleanup",
        "//asylo/util:elf_reader",
        "//asylo/util:file_mapping",
        "//asylo/util:status",
        "@com_google_absl//absl/strings",
        "@linux_sgx//:public",
        "@linux_sgx//:urts",
    ],
)

# An error space for SGX.
cc_library(
    name = "sgx_error_space",
    srcs = ["sgx_error_space.cc"],
    hdrs = ["sgx_error_space.h"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        "//asylo/util:status",
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
    ],
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
        ":trusted_sgx",
        "@com_google_absl//absl/strings",
        "//asylo:enclave_cc_proto",
        "//asylo/platform/core:status_serializer",
        "//asylo/platform/core:trusted_core",
        "//asylo/platform/host_call",
        "//asylo/platform/posix/threading:thread_manager",
        "//asylo/platform/primitives:trusted_primitives",
        "//asylo/platform/primitives:trusted_runtime",
        "//asylo/util:status",
    ] + select({
        "@linux_sgx//:sgx_hw": [
            "@com_google_absl//absl/base:core_headers",
            "//asylo/crypto:aead_cryptor",
            "//asylo/crypto/util:bssl_util",
            "//asylo/crypto/util:byte_container_view",
            "//asylo/crypto/util:trivial_object_util",
            "//asylo/platform/posix/memory:memory",
            "//asylo/platform/primitives/sgx:sgx_error_space",
            "//asylo/util:logging",
            "//asylo/grpc/auth/core:client_ekep_handshaker",
            "//asylo/grpc/auth/core:server_ekep_handshaker",
            "//asylo/identity:descriptions",
            "//asylo/identity:identity_acl_evaluator",
            "//asylo/identity/sgx:code_identity_util",
            "//asylo/identity/sgx:sgx_identity_expectation_matcher",
            "//asylo/identity/sgx:sgx_local_assertion_generator",
            "//asylo/identity/sgx:sgx_local_assertion_verifier",
            "//asylo/util:cleansing_types",
            "//asylo/util:cleanup",
            "@boringssl//:crypto",
        ],
        "//conditions:default": [],
    }),
)

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

load("//asylo/bazel:asylo.bzl", "ASYLO_ALL_BACKEND_TAGS")
load("//asylo/bazel:copts.bzl", "ASYLO_DEFAULT_COPTS")

licenses(["notice"])

package(
    default_visibility = ["//asylo:implementation"],
)

# Common definitions shared by trusted and untrusted code.
cc_library(
    name = "primitives",
    hdrs = [
        "enclave_type.h",
        "extent.h",
        "primitive_status.h",
        "primitives.h",
    ],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        "//asylo/util:error_codes",
    ],
)

# Target exposing untrusted SGX backend-specific components for the build configuration.
_UNTRUSTED_SGX_DEPS = [
    "//asylo/platform/primitives/sgx:loader_cc_proto",
    "//asylo/platform/primitives/sgx:untrusted_sgx",
]

# Target exposing untrusted remote backend-specific components for the build configuration.
_UNTRUSTED_REMOTE_DEPS = [
    "//asylo/platform/primitives/remote:proxy_client",
    "//asylo/util/remote:remote_loader_cc_proto",
    "//asylo/util/remote:remote_proxy_config",
]

# Loader for Asylo enclaves. The target selects the untrusted backend-specific components
# based on the configuration passed by the user via the command line.
cc_library(
    name = "enclave_loader",
    srcs = select(
        {
            "//asylo/platform/primitives:asylo_remote": [
                "//asylo/platform/primitives/remote:enclave_loader.cc",
            ],
            "//conditions:default": [],
        },
    ),
    hdrs = [
        "enclave_loader.h",
    ],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        "//asylo:enclave_cc_proto",
        ":untrusted_primitives",
    ] + select({
        "//asylo/platform/primitives:asylo_remote": _UNTRUSTED_REMOTE_DEPS + [
            "//asylo/platform/primitives/util:dispatch_table",
            "//asylo/platform/primitives/util:exit_log",
            "//asylo/util:status",
            "//asylo/util:status_macros",
        ],
        "//conditions:default": [":local_enclave_loader"],
    }),
)

# Loader for locally loaded Asylo enclaves. No other target than :enclave_loader
# should depend on this target directly.
cc_library(
    name = "local_enclave_loader",
    srcs = select(
        {
            "@linux_sgx//:sgx_hw": [
                "//asylo/platform/primitives/sgx:enclave_loader.cc",
            ],
            "@linux_sgx//:sgx_sim": [
                "//asylo/platform/primitives/sgx:enclave_loader.cc",
            ],
            "//conditions:default": ["//asylo/platform/primitives:enclave_loader.cc"],
        },
    ),
    hdrs = [
        "enclave_loader.h",
    ],
    copts = ASYLO_DEFAULT_COPTS,
    visibility = ["//visibility:private"],
    deps = [
        ":untrusted_primitives",
        "//asylo:enclave_cc_proto",
        "//asylo/platform/primitives/util:dispatch_table",
        "//asylo/platform/primitives/util:exit_log",
        "//asylo/util:status",
        "//asylo/util:status_macros",
    ] + select({
        "@linux_sgx//:sgx_hw": _UNTRUSTED_SGX_DEPS,
        "@linux_sgx//:sgx_sim": _UNTRUSTED_SGX_DEPS,
        "//conditions:default": [],
    }),
)

# Primitive API headers for untrusted code.
cc_library(
    name = "untrusted_primitives",
    srcs = ["untrusted_primitives.cc"],
    hdrs = ["untrusted_primitives.h"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":primitives",
        "//asylo/platform/primitives/util:message_reader_writer",
        "//asylo/platform/primitives/util:status_conversions",
        "//asylo/util:asylo_macros",
        "//asylo/util:status",
    ],
)

# Target exposing trusted backend-dependent components for the build configuration.
_TRUSTED_BACKEND_SGX_DEPS = [
    "//asylo/platform/primitives/sgx:trusted_sgx",
    "//asylo/platform/primitives/sgx:trusted_fork",
]

cc_library(
    name = "trusted_backend",
    hdrs = [
        "trusted_runtime.h",
        "//asylo/platform/primitives/util:trusted_memory.h",
    ],
    copts = ASYLO_DEFAULT_COPTS,
    tags = ASYLO_ALL_BACKEND_TAGS,
    deps = [":primitives"] + select(
        {
            "@com_google_asylo//asylo": [":trusted_primitives"],
        },
        no_match_error = "Must be built in the Asylo toolchain",
    ) + select({
        "@linux_sgx//:sgx_hw": _TRUSTED_BACKEND_SGX_DEPS,
        "@linux_sgx//:sgx_sim": _TRUSTED_BACKEND_SGX_DEPS,
        ":asylo_dlopen": [],
        "//conditions:default": [],
    }),
)

# Primitive API headers for trusted code.
cc_library(
    name = "trusted_primitives",
    hdrs = ["trusted_primitives.h"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":primitives",
        "//asylo/platform/primitives/util:message_reader_writer",
        "//asylo/util:asylo_macros",
    ],
)

# Primitive API headers for trusted runtime support functions.
cc_library(
    name = "trusted_runtime",
    hdrs = ["trusted_runtime.h"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [":primitives"],
)

# Test extent implementation.
cc_test(
    name = "extent_test",
    size = "small",
    srcs = ["extent_test.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":primitives",
        "//asylo/test/util:test_main",
        "@com_google_absl//absl/base:core_headers",
        "@com_google_googletest//:gtest",
    ],
)

# Test shared type implementation.
cc_test(
    name = "primitive_status_test",
    size = "small",
    srcs = ["primitive_status_test.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":primitives",
        "//asylo/test/util:test_main",
        "@com_google_absl//absl/base:core_headers",
        "@com_google_googletest//:gtest",
    ],
)

# Configuration setting for the primitives/dlopen backend.
config_setting(
    name = "asylo_dlopen",
    values = {
        "define": "ASYLO_DLOPEN=1",
    },
    visibility = ["//visibility:public"],
)

# Configuration setting for remote enclaves.
config_setting(
    name = "asylo_remote",
    values = {
        "define": "ASYLO_REMOTE=1",
    },
    visibility = ["//visibility:public"],
)

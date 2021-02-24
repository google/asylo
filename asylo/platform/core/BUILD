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
load("//asylo/bazel:asylo.bzl", "ASYLO_ALL_BACKEND_TAGS")
load("//asylo/bazel:copts.bzl", "ASYLO_DEFAULT_COPTS")

licenses(["notice"])

package(
    default_visibility = ["//asylo:implementation"],
)

# Core untrusted Asylo components.
cc_library(
    name = "untrusted_core",
    srcs = [
        "enclave_config_util.cc",
        "enclave_config_util.h",
        "enclave_manager.cc",
        "generic_enclave_client.cc",
    ],
    hdrs = [
        "enclave_client.h",
        "enclave_manager.h",
        "generic_enclave_client.h",
    ],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":entry_selectors",
        ":shared_name",
        ":shared_resource_manager",
        "//asylo:enclave_cc_proto",
        "//asylo/platform/common:time_util",
        "//asylo/platform/host_call:host_call_handlers_initializer",
        "//asylo/platform/primitives",
        "//asylo/platform/primitives:enclave_loader",
        "//asylo/platform/primitives:untrusted_primitives",
        "//asylo/platform/primitives/sgx:loader_cc_proto",
        "//asylo/platform/primitives/sgx:untrusted_sgx",
        "//asylo/platform/primitives/util:message_reader_writer",
        "//asylo/util:logging",
        "//asylo/util:status",
        "//asylo/util:status_helpers",
        "//asylo/util:status_macros",
        "@com_google_absl//absl/container:flat_hash_map",
        "@com_google_absl//absl/memory",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/synchronization",
        "@com_google_absl//absl/time",
        "@com_google_absl//absl/types:variant",
    ],
)

# Enclave entry selectors.
cc_library(
    name = "entry_selectors",
    hdrs = [
        "entry_selectors.h",
    ],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        "//asylo/platform/primitives",
    ],
)

# Trusted global state.
cc_library(
    name = "trusted_global_state",
    srcs = select({
        "@com_google_asylo//asylo": ["trusted_global_state.cc"],
        "//conditions:default": ["fake_trusted_global_state.cc"],
    }),
    hdrs = ["trusted_global_state.h"],
    copts = ASYLO_DEFAULT_COPTS,
    linkstatic = 1,
    tags = ASYLO_ALL_BACKEND_TAGS,
    deps = [
        "@com_google_absl//absl/status",
        "//asylo:enclave_cc_proto",
        "//asylo/util:status",
    ] + select({
        "@com_google_asylo//asylo": [],
        "//conditions:default": ["@com_google_absl//absl/base:core_headers"],
    }),
)

# Core trusted Asylo components.
cc_library(
    name = "trusted_core",
    hdrs = [
        "trusted_global_state.h",
    ],
    copts = ASYLO_DEFAULT_COPTS,
    linkstatic = 1,
    tags = ASYLO_ALL_BACKEND_TAGS,
    deps = [
        ":shared_name",
        ":trusted_global_state",
        "//asylo:enclave_cc_proto",
        "//asylo/util:status",
    ],
)

# Trusted application base class for user applications. This target is a
# user-facing leaf in the dependency tree, and no other runtime target may
# depend on it.
cc_library(
    name = "trusted_application",
    srcs = ["trusted_application.cc"],
    hdrs = ["trusted_application.h"],
    copts = ASYLO_DEFAULT_COPTS,
    linkstatic = 1,
    tags = ASYLO_ALL_BACKEND_TAGS,
    deps = [
        ":entry_points",
        ":entry_selectors",
        ":shared_name",
        ":trusted_core",
        "//asylo:enclave_cc_proto",
        "//asylo/identity:init",
        "//asylo/platform/arch:trusted_arch",
        "//asylo/platform/common:enclave_state",
        "//asylo/platform/posix/io:io_manager",
        "//asylo/platform/posix/threading:thread_manager",
        "//asylo/platform/primitives",
        "//asylo/platform/primitives:trusted_primitives",
        "//asylo/platform/primitives:trusted_runtime",
        "//asylo/platform/primitives/util:message_reader_writer",
        "//asylo/platform/primitives/util:status_conversions",
        "//asylo/platform/primitives/util:status_serializer",
        "//asylo/util:logging",
        "//asylo/util:status",
        "@com_google_absl//absl/memory",
        "@com_google_absl//absl/status",
    ],
    alwayslink = 1,
)

# Make sure that the specialized atomic wrappers are only visible to
# our low level synchronization primitives, and aren't reused incorrectly.
package_group(
    name = "synchronization_primitives",
    packages = [
        "//asylo/platform/core/trusted_mutex",
        "//asylo/platform/core/trusted_spin_lock",
        "//asylo/platform/posix",
    ],
)

# Atomic utility functions. Highly specialized for a few specific use
# cases, not intended to be reused without extensive understanding of
# memory orderings. Extremely narrow visibility is on purpose.
cc_library(
    name = "atomic",
    hdrs = ["atomic.h"],
    copts = ASYLO_DEFAULT_COPTS,
    visibility = [":synchronization_primitives"],
)

# Enclave entry points.
cc_library(
    name = "entry_points",
    hdrs = ["entry_points.h"],
    copts = ASYLO_DEFAULT_COPTS,
)

# An untrusted mutex object which depends on host kernel resources.
_untrusted_mutex_sgx_deps = [
    "//asylo/platform/primitives/sgx:trusted_sgx",
]

# An trusted spin lock object.
cc_library(
    name = "trusted_spin_lock",
    srcs = [
        "trusted_spin_lock.cc",
    ],
    hdrs = [
        "trusted_spin_lock.h",
    ],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":atomic",
        "//asylo/platform/primitives:trusted_primitives",
        "//asylo/platform/primitives:trusted_runtime",
    ],
)

# Shared name data type used by both trusted and untrusted code.
cc_library(
    name = "shared_name",
    hdrs = [
        "shared_name.h",
        "shared_name_kind.h",
    ],
    copts = ASYLO_DEFAULT_COPTS,
    deps = ["//asylo/platform/common:hash_combine"],
)

cc_library(
    name = "shared_resource_manager",
    srcs = ["shared_resource_manager.cc"],
    hdrs = ["shared_resource_manager.h"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":shared_name",
        "//asylo/util:status",
        "@com_google_absl//absl/container:flat_hash_map",
        "@com_google_absl//absl/memory",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/synchronization",
    ],
)

cc_library(
    name = "trusted_mutex",
    srcs = ["trusted_mutex.cc"],
    hdrs = ["trusted_mutex.h"],
    copts = ASYLO_DEFAULT_COPTS,
    tags = ASYLO_ALL_BACKEND_TAGS,
    deps = [
        ":atomic",
        ":trusted_spin_lock",
        "//asylo/platform/host_call",
    ],
)

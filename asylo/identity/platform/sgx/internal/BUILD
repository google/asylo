#
# Copyright 2020 Asylo authors
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
load("@rules_cc//cc:defs.bzl", "cc_library", "cc_test")
load("//asylo/bazel:asylo.bzl", "cc_test_and_cc_enclave_test")
load("//asylo/bazel:copts.bzl", "ASYLO_DEFAULT_COPTS")

# This packages contains libraries used to implement the platform/sgx libraries.

licenses(["notice"])

package(default_visibility = ["//asylo/identity/platform/sgx:__subpackages__"])

cc_library(
    name = "code_identity_constants",
    srcs = ["code_identity_constants.cc"],
    hdrs = ["code_identity_constants.h"],
    copts = ASYLO_DEFAULT_COPTS,
    visibility = ["//asylo/identity:__subpackages__"],
)

cc_library(
    name = "sgx_identity_test_util",
    testonly = 1,
    srcs = ["sgx_identity_test_util.cc"],
    hdrs = ["sgx_identity_test_util.h"],
    copts = ASYLO_DEFAULT_COPTS,
    visibility = [
        "//asylo/identity/attestation/sgx/internal:__subpackages__",
        "//asylo/identity/platform/sgx:__subpackages__",
    ],
    deps = [
        ":code_identity_constants",
        ":sgx_identity_util_internal",
        "//asylo/crypto:sha256_hash_cc_proto",
        "//asylo/crypto/util:bytes",
        "//asylo/crypto/util:trivial_object_util",
        "//asylo/identity:descriptions",
        "//asylo/identity:identity_cc_proto",
        "//asylo/identity/platform/sgx:attributes_cc_proto",
        "//asylo/identity/platform/sgx:code_identity_cc_proto",
        "//asylo/identity/platform/sgx:machine_configuration_cc_proto",
        "//asylo/identity/platform/sgx:sgx_identity_cc_proto",
        "//asylo/util:status",
        "@com_google_absl//absl/status",
    ],
)

cc_library(
    name = "sgx_identity_util_internal",
    srcs = [
        "sgx_identity_util_internal.cc",
        "self_identity_internal.h",
    ] + select({
        "@com_google_asylo//asylo": ["self_identity.cc"],
        "//conditions:default": ["fake_self_identity.cc"],
    }),
    hdrs = [
        "self_identity.h",
        "sgx_identity_util_internal.h",
    ],
    copts = ASYLO_DEFAULT_COPTS,
    visibility = [
        "//asylo/identity/attestation/sgx:__subpackages__",
        "//asylo/identity/platform/sgx:__subpackages__",
        "//asylo/identity/sealing/sgx:__subpackages__",
    ],
    deps = [
        ":code_identity_constants",
        ":hardware_interface",
        ":hardware_types",
        ":proto_format",
        "//asylo/crypto:sha256_hash",
        "//asylo/crypto:sha256_hash_cc_proto",
        "//asylo/crypto:sha256_hash_util",
        "//asylo/crypto/util:bssl_util",
        "//asylo/crypto/util:byte_container_util",
        "//asylo/crypto/util:bytes",
        "//asylo/crypto/util:trivial_object_util",
        "//asylo/identity:descriptions",
        "//asylo/identity:identity_cc_proto",
        "//asylo/identity/platform/sgx:attributes_cc_proto",
        "//asylo/identity/platform/sgx:attributes_util",
        "//asylo/identity/platform/sgx:code_identity_cc_proto",
        "//asylo/identity/platform/sgx:machine_configuration_cc_proto",
        "//asylo/identity/platform/sgx:sgx_identity_cc_proto",
        "//asylo/identity/provisioning/sgx/internal:platform_provisioning",
        "//asylo/util:logging",
        "//asylo/util:proto_enum_util",
        "//asylo/util:status",
        "@boringssl//:crypto",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/strings:str_format",
    ],
)

# This test uses FakeEnclave to simulate different enclaves. Since FakeEnclave
# should not be used inside a real enclave, this test is not a
# "cc_test_and_cc_enclave_test" target.
cc_test(
    name = "sgx_identity_util_internal_test",
    srcs = ["sgx_identity_util_internal_test.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":code_identity_constants",
        ":fake_enclave",
        ":hardware_interface",
        ":hardware_types",
        ":proto_format",
        ":sgx_identity_test_util",
        ":sgx_identity_util_internal",
        "//asylo/crypto:sha256_hash_cc_proto",
        "//asylo/crypto:sha256_hash_util",
        "//asylo/crypto/util:bytes",
        "//asylo/crypto/util:trivial_object_util",
        "//asylo/identity:descriptions",
        "//asylo/identity:identity_cc_proto",
        "//asylo/identity/platform/sgx:architecture_bits",
        "//asylo/identity/platform/sgx:attributes_cc_proto",
        "//asylo/identity/platform/sgx:attributes_util",
        "//asylo/identity/platform/sgx:code_identity_cc_proto",
        "//asylo/identity/platform/sgx:machine_configuration_cc_proto",
        "//asylo/identity/platform/sgx:sgx_identity_cc_proto",
        "//asylo/identity/platform/sgx:sgx_identity_expectation_matcher",
        "//asylo/platform/common:singleton",
        "//asylo/test/util:proto_matchers",
        "//asylo/test/util:status_matchers",
        "//asylo/test/util:test_main",
        "//asylo/util:status",
        "@com_google_absl//absl/status",
        "@com_google_googletest//:gtest",
    ],
)

cc_library(
    name = "hardware_types",
    srcs = ["secs_attributes.cc"],
    hdrs = [
        "identity_key_management_structs.h",
        "secs_attributes.h",
    ],
    copts = ASYLO_DEFAULT_COPTS,
    visibility = ["//asylo:implementation"],
    deps = [
        "//asylo/crypto:sha256_hash",
        "//asylo/crypto/util:bytes",
        "//asylo/identity:additional_authenticated_data_generator",
        "//asylo/identity/platform/sgx:architecture_bits",
        "//asylo/identity/platform/sgx:attributes_cc_proto",
        "//asylo/util:aligned_object_ptr",
        "//asylo/util:logging",
        "//asylo/util:status",
        "@boringssl//:crypto",
        "@com_google_absl//absl/base:core_headers",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/strings:str_format",
        "@com_google_absl//absl/types:span",
    ],
)

cc_test_and_cc_enclave_test(
    name = "secs_attributes_test",
    srcs = ["secs_attributes_test.cc"],
    backends = sgx.backend_labels,
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":hardware_types",
        "//asylo/crypto/util:trivial_object_util",
        "//asylo/identity/platform/sgx:architecture_bits",
        "//asylo/identity/platform/sgx:attributes_cc_proto",
        "//asylo/test/util:status_matchers",
        "//asylo/test/util:test_main",
        "//asylo/util:status",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/strings",
        "@com_google_googletest//:gtest",
    ],
)

# This target should not be used inside an enclave. This target should only be
# used directly by tests. It is not marked as "testonly" since
# hardware_interface depends on it.
cc_library(
    name = "fake_enclave",
    srcs = ["fake_enclave.cc"],
    hdrs = ["fake_enclave.h"],
    copts = ASYLO_DEFAULT_COPTS,
    visibility = ["//asylo:implementation"],
    deps = [
        ":hardware_types",
        ":proto_format",
        "//asylo/crypto:sha256_hash",
        "//asylo/crypto:sha256_hash_cc_proto",
        "//asylo/crypto/util:bssl_util",
        "//asylo/crypto/util:bytes",
        "//asylo/crypto/util:trivial_object_util",
        "//asylo/identity/platform/sgx:architecture_bits",
        "//asylo/identity/platform/sgx:attributes_cc_proto",
        "//asylo/identity/platform/sgx:machine_configuration_cc_proto",
        "//asylo/identity/platform/sgx:sgx_identity_cc_proto",
        "//asylo/platform/primitives/sgx:sgx_errors",
        "//asylo/util:logging",
        "//asylo/util:status",
        "@boringssl//:crypto",
        "@com_google_absl//absl/base:core_headers",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/strings",
    ],
)

cc_library(
    name = "hardware_interface",
    srcs = select({
        "@com_google_asylo//asylo": ["real_hardware_interface.cc"],
        "//conditions:default": ["fake_hardware_interface.cc"],
    }),
    hdrs = ["hardware_interface.h"],
    copts = ASYLO_DEFAULT_COPTS,
    visibility = [
        "//asylo/identity/attestation/sgx:__subpackages__",
        "//asylo/identity/platform/sgx:__subpackages__",
        "//asylo/identity/sealing/sgx/internal:__subpackages__",
    ],
    deps = [
        ":hardware_types",
        "@com_google_absl//absl/memory",
        "//asylo/util:status",
    ] + select({
        "@com_google_asylo//asylo": [
            "//asylo/platform/primitives/sgx:sgx_errors",
            "@linux_sgx//:trts",
        ],
        "//conditions:default": [":fake_enclave"],
    }),
)

cc_library(
    name = "mock_hardware_interface",
    testonly = 1,
    hdrs = ["mock_hardware_interface.h"],
    copts = ASYLO_DEFAULT_COPTS,
    visibility = [
        "//asylo/identity/attestation/sgx:__subpackages__",
        "//asylo/identity/platform/sgx:__subpackages__",
    ],
    deps = [
        ":hardware_interface",
        ":hardware_types",
        "//asylo/crypto/util:bytes",
        "//asylo/util:status",
        "@com_google_googletest//:gtest",
    ],
)

cc_test(
    name = "fake_hardware_interface_test",
    srcs = ["fake_hardware_interface_test.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":fake_enclave",
        ":hardware_interface",
        ":hardware_types",
        ":sgx_identity_util_internal",
        "//asylo/crypto:sha256_hash",
        "//asylo/crypto/util:bytes",
        "//asylo/crypto/util:trivial_object_util",
        "//asylo/identity/platform/sgx:architecture_bits",
        "//asylo/identity/platform/sgx:miscselect_util",
        "//asylo/platform/primitives/sgx:sgx_error_matchers",
        "//asylo/test/util:proto_matchers",
        "//asylo/test/util:status_matchers",
        "//asylo/test/util:test_main",
        "@boringssl//:crypto",
        "@com_google_absl//absl/strings",
        "@com_google_googletest//:gtest",
    ],
)

# Test for VerifyHardwareReport in SGX-sim and SGX-hw.
cc_test_and_cc_enclave_test(
    name = "verify_hardware_report_test",
    srcs = ["verify_hardware_report_test.cc"],
    backends = sgx.backend_labels,
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":hardware_interface",
        ":hardware_types",
        ":sgx_identity_util_internal",
        "//asylo/crypto/util:trivial_object_util",
        "//asylo/test/util:status_matchers",
        "//asylo/test/util:test_main",
        "@com_google_googletest//:gtest",
    ],
)

cc_library(
    name = "proto_format",
    srcs = ["proto_format.cc"],
    hdrs = ["proto_format.h"],
    copts = ASYLO_DEFAULT_COPTS,
    visibility = ["//asylo:implementation"],
    deps = [
        "//asylo/crypto:certificate_cc_proto",
        "//asylo/crypto:sha256_hash_cc_proto",
        "//asylo/identity/platform/sgx:attributes_cc_proto",
        "//asylo/identity/platform/sgx:attributes_util",
        "//asylo/identity/platform/sgx:code_identity_cc_proto",
        "//asylo/identity/platform/sgx:machine_configuration_cc_proto",
        "//asylo/identity/platform/sgx:miscselect_cc_proto",
        "//asylo/identity/platform/sgx:miscselect_util",
        "@com_google_absl//absl/memory",
        "@com_google_absl//absl/strings",
        "@com_google_protobuf//:protobuf",
    ],
)

cc_test_and_cc_enclave_test(
    name = "proto_format_test",
    srcs = ["proto_format_test.cc"],
    backends = sgx.backend_labels,
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":hardware_types",
        ":proto_format",
        "//asylo/crypto:sha256_hash_cc_proto",
        "//asylo/identity/platform/sgx:architecture_bits",
        "//asylo/identity/platform/sgx:attributes_util",
        "//asylo/identity/platform/sgx:machine_configuration_cc_proto",
        "//asylo/identity/platform/sgx:miscselect_cc_proto",
        "//asylo/identity/platform/sgx:miscselect_util",
        "//asylo/identity/platform/sgx:sgx_identity_cc_proto",
        "//asylo/identity/platform/sgx:sgx_identity_util",
        "//asylo/identity/provisioning/sgx/internal:platform_provisioning_cc_proto",
        "//asylo/test/util:status_matchers",
        "//asylo/test/util:test_main",
        "@com_google_absl//absl/strings",
        "@com_google_googletest//:gtest",
    ],
)

cc_library(
    name = "ppid_ek",
    srcs = ["ppid_ek.cc"],
    hdrs = ["ppid_ek.h"],
    copts = ASYLO_DEFAULT_COPTS,
    visibility = ["//asylo:implementation"],
    deps = [
        "//asylo/crypto:keys_cc_proto",
        "//asylo/util:proto_parse_util",
        "@com_google_absl//absl/strings",
    ],
)

cc_test_and_cc_enclave_test(
    name = "ppid_ek_test",
    srcs = ["ppid_ek_test.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":ppid_ek",
        "//asylo/crypto:algorithms_cc_proto",
        "//asylo/crypto:keys_cc_proto",
        "//asylo/test/util:test_main",
        "@com_google_googletest//:gtest",
    ],
)

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

# This package defines sgx-specific portions of the enclave-identity and
# key-management library.

# Used to selectively enable gtest tests to run inside an enclave.
load("//asylo/bazel:asylo.bzl", "cc_enclave_test")
load("//asylo/bazel:copts.bzl", "ASYLO_DEFAULT_COPTS")
load("//asylo/bazel:proto.bzl", "asylo_proto_library")

asylo_proto_library(
    name = "code_identity_proto",
    srcs = ["code_identity.proto"],
    deps = [
        "//asylo/identity/util:bit_vector_128_proto",
        "//asylo/identity/util:sha256_hash_proto",
    ],
)

asylo_proto_library(
    name = "local_assertion_proto",
    srcs = ["local_assertion.proto"],
)

asylo_proto_library(
    name = "local_sealed_secret_proto",
    srcs = ["local_sealed_secret.proto"],
)

cc_library(
    name = "code_identity_constants",
    srcs = ["code_identity_constants.cc"],
    hdrs = ["code_identity_constants.h"],
    visibility = ["//visibility:public"],
)

cc_library(
    name = "local_assertion_generator",
    srcs = [
        "local_assertion_generator.cc",
        "local_assertion_generator.h",
    ],
    visibility = ["//visibility:public"],
    deps = [
        ":code_identity_constants",
        ":hardware_interface",
        ":hardware_types",
        ":local_assertion_proto_cc",
        "//asylo/identity:enclave_assertion_generator",
        "//asylo/identity/util:trivial_object_util",
        "//asylo/platform/core:trusted_global_state",
        "//asylo/platform/crypto:sha256_hash",
        "@com_google_absl//absl/synchronization",
    ],
    alwayslink = 1,
)

cc_test(
    name = "local_assertion_generator_test",
    srcs = [
        "local_assertion_generator.h",
        "local_assertion_generator_test.cc",
    ],
    tags = ["regression"],
    deps = [
        ":code_identity_constants",
        ":code_identity_util",
        ":hardware_types",
        ":local_assertion_generator",
        ":local_assertion_proto_cc",
        "//asylo/identity:enclave_assertion_authority",
        "//asylo/identity:enclave_assertion_generator",
        "//asylo/identity:identity_proto_cc",
        "//asylo/identity/util:trivial_object_util",
        "//asylo/platform/core:trusted_global_state",
        "//asylo/platform/crypto:sha256_hash",
        "//asylo/test/util:status_matchers",
        "//asylo/test/util:test_main",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/synchronization",
        "@com_google_googletest//:gtest",
        "@com_google_protobuf//:protobuf",
    ],
)

cc_library(
    name = "local_assertion_verifier",
    srcs = [
        "local_assertion_verifier.cc",
        "local_assertion_verifier.h",
    ],
    visibility = ["//visibility:public"],
    deps = [
        ":code_identity_constants",
        ":code_identity_util",
        ":hardware_types",
        ":local_assertion_proto_cc",
        "//asylo/identity:enclave_assertion_verifier",
        "//asylo/identity/util:trivial_object_util",
        "//asylo/platform/core:trusted_global_state",
        "//asylo/platform/crypto:sha256_hash",
        "@com_google_absl//absl/synchronization",
    ],
    alwayslink = 1,
)

cc_test(
    name = "local_assertion_verifier_test",
    srcs = [
        "local_assertion_verifier.h",
        "local_assertion_verifier_test.cc",
    ],
    tags = ["regression"],
    deps = [
        ":code_identity_constants",
        ":code_identity_util",
        ":hardware_interface",
        ":hardware_types",
        ":local_assertion_proto_cc",
        ":local_assertion_verifier",
        "//asylo/identity:enclave_assertion_authority",
        "//asylo/identity:enclave_assertion_verifier",
        "//asylo/identity:identity_proto_cc",
        "//asylo/identity/util:trivial_object_util",
        "//asylo/platform/core:trusted_global_state",
        "//asylo/platform/crypto:sha256_hash",
        "//asylo/test/util:status_matchers",
        "//asylo/test/util:test_main",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/synchronization",
        "@com_google_googletest//:gtest",
        "@com_google_protobuf//:protobuf",
    ],
)

cc_test(
    name = "local_assertion_authority_test",
    srcs = [
        "local_assertion_authority_test.cc",
        "local_assertion_generator.h",
        "local_assertion_verifier.h",
    ],
    tags = ["regression"],
    deps = [
        ":code_identity_proto_cc",
        ":code_identity_util",
        ":hardware_interface",
        ":local_assertion_generator",
        ":local_assertion_proto_cc",
        ":local_assertion_verifier",
        "//asylo/identity:enclave_assertion_generator",
        "//asylo/identity:enclave_assertion_verifier",
        "//asylo/identity:identity_proto_cc",
        "//asylo/platform/core:trusted_global_state",
        "//asylo/test/util:status_matchers",
        "//asylo/test/util:test_main",
        "@com_google_absl//absl/synchronization",
        "@com_google_googletest//:gtest",
        "@com_google_protobuf//:protobuf",
    ],
)

cc_library(
    name = "code_identity_test_util",
    testonly = 1,
    srcs = ["code_identity_test_util.cc"],
    hdrs = ["code_identity_test_util.h"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":code_identity_proto_cc",
        ":code_identity_util",
        "//asylo/identity:identity_proto_cc",
        "//asylo/identity/util:sha256_hash_proto_cc",
        "//asylo/util:status",
    ],
)

cc_library(
    name = "code_identity_util",
    srcs = [
        "code_identity_util.cc",
        "self_identity_internal.h",
    ] + select({
        "@com_google_asylo//asylo": ["self_identity.cc"],
        "//conditions:default": ["fake_self_identity.cc"],
    }),
    hdrs = [
        "code_identity_util.h",
        "self_identity.h",
    ],
    visibility = ["//asylo:implementation"],
    deps = [
        ":code_identity_constants",
        ":code_identity_proto_cc",
        ":hardware_interface",
        ":hardware_types",
        "//asylo/identity:identity_proto_cc",
        "//asylo/identity/util:bit_vector_128_proto_cc",
        "//asylo/identity/util:bit_vector_128_util",
        "//asylo/identity/util:bytes",
        "//asylo/identity/util:sha256_hash_proto_cc",
        "//asylo/identity/util:sha256_hash_util",
        "//asylo/identity/util:trivial_object_util",
        "//asylo/platform/crypto/util:bssl_util",
        "//asylo/util:status",
        "@boringssl//:crypto",
        "@com_google_absl//absl/strings",
        "@com_google_asylo//asylo/util:logging",
    ],
)

cc_test(
    name = "code_identity_util_test",
    srcs = ["code_identity_util_test.cc"],
    deps = [
        ":code_identity_constants",
        ":code_identity_expectation_matcher",
        ":code_identity_proto_cc",
        ":code_identity_test_util",
        ":code_identity_util",
        ":hardware_interface",
        "//asylo/identity:identity_expectation_matcher",
        "//asylo/identity:identity_proto_cc",
        "//asylo/identity/util:bit_vector_128_proto_cc",
        "//asylo/identity/util:bit_vector_128_util",
        "//asylo/identity/util:sha256_hash_proto_cc",
        "//asylo/identity/util:sha256_hash_util",
        "//asylo/identity/util:trivial_object_util",
        "//asylo/platform/common:singleton",
        "//asylo/test/util:status_matchers",
        "//asylo/test/util:test_main",
        "//asylo/util:status",
        "@com_google_googletest//:gtest",
        "@com_google_protobuf//:protobuf",
    ],
)

cc_library(
    name = "code_identity_expectation_matcher",
    srcs = [
        "code_identity_expectation_matcher.cc",
        "code_identity_expectation_matcher.h",
    ],
    visibility = ["//visibility:public"],
    deps = [
        ":code_identity_constants",
        ":code_identity_util",
        "//asylo/identity:identity_expectation_matcher",
        "//asylo/identity:identity_proto_cc",
    ],
    alwayslink = 1,
)

cc_test(
    name = "code_identity_expectation_matcher_test",
    srcs = [
        "code_identity_expectation_matcher.h",
        "code_identity_expectation_matcher_test.cc",
    ],
    tags = ["regression"],
    deps = [
        ":code_identity_constants",
        ":code_identity_expectation_matcher",
        ":code_identity_proto_cc",
        ":code_identity_test_util",
        "//asylo/identity:identity_expectation_matcher",
        "//asylo/identity:identity_proto_cc",
        "//asylo/test/util:status_matchers",
        "//asylo/test/util:test_main",
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
    deps = [
        "//asylo/identity/util:aligned_object_ptr",
        "//asylo/identity/util:bit_vector_128_proto_cc",
        "//asylo/identity/util:bytes",
        "@boringssl//:crypto",
        "@com_google_asylo//asylo/util:logging",
    ],
)

cc_test(
    name = "secs_attributes_test",
    srcs = ["secs_attributes_test.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    tags = ["regression"],
    deps = [
        ":hardware_types",
        "//asylo/identity/util:bit_vector_128_proto_cc",
        "//asylo/identity/util:trivial_object_util",
        "//asylo/test/util:test_main",
        "@com_google_absl//absl/strings",
        "@com_google_googletest//:gtest",
    ],
)

cc_library(
    name = "hardware_interface",
    srcs = select({
        "@com_google_asylo//asylo": ["hardware_interface.cc"],
        "//conditions:default": [
            "fake_enclave.cc",
            "fake_hardware_interface.cc",
        ],
    }),
    hdrs = ["hardware_interface.h"] + select({
        "@com_google_asylo//asylo": [],
        "//conditions:default": ["fake_enclave.h"],
    }),
    deps = [
        ":hardware_types",
        "@com_google_asylo//asylo/util:logging",
        "//asylo/identity/util:bytes",
        "@boringssl//:crypto",
    ] + select({
        "@linux_sgx//:sgx_sim": [
            "@linux_sgx//:common_inc",
            "@linux_sgx//:trts_inc",
        ],
        "//conditions:default": ["//asylo/identity/util:trivial_object_util"],
    }),
)

cc_test(
    name = "fake_hardware_interface_test",
    srcs = ["fake_hardware_interface_test.cc"],
    tags = ["regression"],
    deps = [
        ":hardware_interface",
        "//asylo/identity/util:trivial_object_util",
        "//asylo/test/util:test_main",
        "@boringssl//:crypto",
        "@com_google_absl//absl/strings",
        "@com_google_googletest//:gtest",
    ],
)

# Test for VerifyHardwareReport in SGX-sim and SGX-hw.
cc_enclave_test(
    name = "verify_hardware_report_test",
    srcs = ["verify_hardware_report_test.cc"],
    tags = ["regression"],
    deps = [
        ":code_identity_util",
        ":hardware_interface",
        "//asylo/identity/util:trivial_object_util",
        "//asylo/test/util:status_matchers",
    ],
)

cc_library(
    name = "local_secret_sealer_helpers",
    srcs = ["local_secret_sealer_helpers.cc"],
    hdrs = ["local_secret_sealer_helpers.h"],
    visibility = ["//visibility:private"],
    deps = [
        ":code_identity_proto_cc",
        ":code_identity_util",
        ":hardware_interface",
        ":hardware_types",
        ":local_sealed_secret_proto_cc",
        "//asylo/identity:identity_acl_proto_cc",
        "//asylo/identity:identity_proto_cc",
        "//asylo/identity:sealed_secret_proto_cc",
        "//asylo/identity/util:byte_container_util",
        "//asylo/identity/util:bytes",
        "//asylo/platform/common:singleton",
        "//asylo/util:cleansing_types",
        "//asylo/util:status",
        "@com_google_absl//absl/strings",
    ],
)

cc_library(
    name = "local_secret_sealer",
    srcs = ["local_secret_sealer.cc"],
    hdrs = ["local_secret_sealer.h"],
    visibility = ["//visibility:public"],
    deps = [
        ":code_identity_proto_cc",
        ":code_identity_util",
        ":hardware_types",
        ":local_secret_sealer_helpers",
        "//asylo/identity:identity_acl_proto_cc",
        "//asylo/identity:identity_proto_cc",
        "//asylo/identity:secret_sealer",
        "//asylo/identity/util:bit_vector_128_proto_cc",
        "//asylo/identity/util:byte_container_util",
        "//asylo/identity/util:byte_container_view",
        "//asylo/identity/util:sha256_hash_proto_cc",
        "//asylo/platform/crypto:aes_gcm_siv",
        "//asylo/util:cleansing_types",
        "//asylo/util:status",
        "@com_google_absl//absl/memory",
    ],
)

cc_test(
    name = "local_secret_sealer_test",
    srcs = ["local_secret_sealer_test.cc"],
    tags = ["regression"],
    deps = [
        ":code_identity_proto_cc",
        ":code_identity_util",
        ":hardware_interface",
        ":local_sealed_secret_proto_cc",
        ":local_secret_sealer",
        ":local_secret_sealer_helpers",
        "//asylo/identity:identity_acl_proto_cc",
        "//asylo/identity:identity_proto_cc",
        "//asylo/identity:sealed_secret_proto_cc",
        "//asylo/identity:secret_sealer",
        "//asylo/identity/util:bytes",
        "//asylo/platform/common:singleton",
        "//asylo/test/util:status_matchers",
        "//asylo/test/util:test_main",
        "//asylo/util:status",
        "@com_google_absl//absl/memory",
        "@com_google_googletest//:gtest",
    ],
)

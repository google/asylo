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
    name = "attributes_proto",
    srcs = ["attributes.proto"],
    visibility = ["//asylo:implementation"],
)

asylo_proto_library(
    name = "code_identity_proto",
    srcs = ["code_identity.proto"],
    visibility = ["//asylo:implementation"],
    deps = [
        ":attributes_proto",
        "//asylo/identity/util:sha256_hash_proto",
    ],
)

asylo_proto_library(
    name = "local_assertion_proto",
    srcs = ["local_assertion.proto"],
)

asylo_proto_library(
    name = "remote_assertion_proto",
    srcs = ["remote_assertion.proto"],
    deps = [
        ":code_identity_proto",
        "//asylo/crypto:algorithms_proto",
    ],
)

asylo_proto_library(
    name = "local_sealed_secret_proto",
    srcs = ["local_sealed_secret.proto"],
)

cc_library(
    name = "remote_assertion_util",
    srcs = ["remote_assertion_util.cc"],
    hdrs = ["remote_assertion_util.h"],
    deps = [
        ":code_identity_proto_cc",
        ":remote_assertion_proto_cc",
        "//asylo/crypto:algorithms_proto_cc",
        "//asylo/crypto:signing_key",
        "//asylo/util:status",
        "@com_google_absl//absl/strings",
    ],
)

cc_test(
    name = "remote_assertion_util_test",
    srcs = ["remote_assertion_util_test.cc"],
    deps = [
        ":code_identity_proto_cc",
        ":code_identity_util",
        ":remote_assertion_proto_cc",
        ":remote_assertion_util",
        "//asylo/crypto:ecdsa_p256_sha256_signing_key",
        "//asylo/test/util:proto_matchers",
        "//asylo/test/util:status_matchers",
        "//asylo/test/util:test_main",
        "@com_google_googletest//:gtest",
    ],
)

cc_library(
    name = "code_identity_constants",
    srcs = ["code_identity_constants.cc"],
    hdrs = ["code_identity_constants.h"],
)

cc_library(
    name = "sgx_local_assertion_generator",
    srcs = [
        "sgx_local_assertion_generator.cc",
        "sgx_local_assertion_generator.h",
    ],
    visibility = ["//visibility:public"],
    deps = [
        ":code_identity_constants",
        ":hardware_interface",
        ":hardware_types",
        ":local_assertion_proto_cc",
        "//asylo/crypto:sha256_hash",
        "//asylo/crypto/util:bytes",
        "//asylo/crypto/util:trivial_object_util",
        "//asylo/identity:enclave_assertion_generator",
        "//asylo/platform/core:trusted_global_state",
        "//asylo/util:status",
        "@com_google_absl//absl/synchronization",
    ],
    alwayslink = 1,
)

cc_test(
    name = "sgx_local_assertion_generator_test",
    srcs = [
        "sgx_local_assertion_generator.h",
        "sgx_local_assertion_generator_test.cc",
    ],
    deps = [
        ":code_identity_constants",
        ":code_identity_util",
        ":hardware_types",
        ":local_assertion_proto_cc",
        ":sgx_local_assertion_generator",
        "//asylo/crypto:sha256_hash",
        "//asylo/crypto/util:bytes",
        "//asylo/crypto/util:trivial_object_util",
        "//asylo/identity:enclave_assertion_authority",
        "//asylo/identity:enclave_assertion_generator",
        "//asylo/identity:identity_proto_cc",
        "//asylo/platform/core:trusted_global_state",
        "//asylo/test/util:proto_matchers",
        "//asylo/test/util:status_matchers",
        "//asylo/test/util:test_main",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/synchronization",
        "@com_google_googletest//:gtest",
        "@com_google_protobuf//:protobuf",
    ],
)

cc_library(
    name = "sgx_local_assertion_verifier",
    srcs = [
        "sgx_local_assertion_verifier.cc",
        "sgx_local_assertion_verifier.h",
    ],
    visibility = ["//visibility:public"],
    deps = [
        ":code_identity_constants",
        ":code_identity_util",
        ":hardware_types",
        ":local_assertion_proto_cc",
        "//asylo/crypto:sha256_hash",
        "//asylo/crypto/util:bytes",
        "//asylo/crypto/util:trivial_object_util",
        "//asylo/identity:enclave_assertion_verifier",
        "//asylo/platform/core:trusted_global_state",
        "//asylo/util:status",
        "@com_google_absl//absl/synchronization",
    ],
    alwayslink = 1,
)

cc_test(
    name = "sgx_local_assertion_verifier_test",
    srcs = [
        "sgx_local_assertion_verifier.h",
        "sgx_local_assertion_verifier_test.cc",
    ],
    deps = [
        ":code_identity_constants",
        ":code_identity_util",
        ":hardware_interface",
        ":hardware_types",
        ":local_assertion_proto_cc",
        ":sgx_local_assertion_verifier",
        "//asylo/crypto:sha256_hash",
        "//asylo/crypto/util:trivial_object_util",
        "//asylo/identity:enclave_assertion_authority",
        "//asylo/identity:enclave_assertion_verifier",
        "//asylo/identity:identity_proto_cc",
        "//asylo/platform/core:trusted_global_state",
        "//asylo/test/util:proto_matchers",
        "//asylo/test/util:status_matchers",
        "//asylo/test/util:test_main",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/synchronization",
        "@com_google_googletest//:gtest",
        "@com_google_protobuf//:protobuf",
    ],
)

cc_test(
    name = "sgx_local_assertion_authority_test",
    srcs = [
        "sgx_local_assertion_authority_test.cc",
        "sgx_local_assertion_generator.h",
        "sgx_local_assertion_verifier.h",
    ],
    deps = [
        ":code_identity_proto_cc",
        ":code_identity_util",
        ":hardware_interface",
        ":local_assertion_proto_cc",
        ":sgx_local_assertion_generator",
        ":sgx_local_assertion_verifier",
        "//asylo/identity:enclave_assertion_generator",
        "//asylo/identity:enclave_assertion_verifier",
        "//asylo/identity:identity_proto_cc",
        "//asylo/platform/core:trusted_global_state",
        "//asylo/test/util:proto_matchers",
        "//asylo/test/util:status_matchers",
        "//asylo/test/util:test_main",
        "@com_google_absl//absl/synchronization",
        "@com_google_googletest//:gtest",
    ],
)

cc_library(
    name = "code_identity_test_util",
    testonly = 1,
    srcs = ["code_identity_test_util.cc"],
    hdrs = ["code_identity_test_util.h"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":attributes_proto_cc",
        ":code_identity_proto_cc",
        ":code_identity_util",
        "//asylo/crypto/util:bytes",
        "//asylo/crypto/util:trivial_object_util",
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
        ":attributes_proto_cc",
        ":attributes_util",
        ":code_identity_constants",
        ":code_identity_proto_cc",
        ":hardware_interface",
        ":hardware_types",
        "//asylo/crypto/util:bssl_util",
        "//asylo/crypto/util:bytes",
        "//asylo/crypto/util:trivial_object_util",
        "//asylo/identity:identity_proto_cc",
        "//asylo/identity/util:sha256_hash_proto_cc",
        "//asylo/identity/util:sha256_hash_util",
        "//asylo/util:logging",
        "//asylo/util:status",
        "@boringssl//:crypto",
        "@com_google_absl//absl/strings",
    ],
)

cc_test(
    name = "code_identity_util_test",
    srcs = ["code_identity_util_test.cc"],
    tags = ["noregression"],
    deps = [
        ":attributes_proto_cc",
        ":attributes_util",
        ":code_identity_constants",
        ":code_identity_proto_cc",
        ":code_identity_test_util",
        ":code_identity_util",
        ":hardware_interface",
        ":hardware_types",
        ":sgx_code_identity_expectation_matcher",
        "//asylo/crypto/util:bytes",
        "//asylo/crypto/util:trivial_object_util",
        "//asylo/identity:identity_proto_cc",
        "//asylo/identity/util:sha256_hash_proto_cc",
        "//asylo/identity/util:sha256_hash_util",
        "//asylo/platform/common:singleton",
        "//asylo/test/util:proto_matchers",
        "//asylo/test/util:status_matchers",
        "//asylo/test/util:test_main",
        "//asylo/util:status",
        "@com_google_googletest//:gtest",
    ],
)

cc_library(
    name = "attributes_util",
    srcs = ["attributes_util.cc"],
    hdrs = ["attributes_util.h"],
    deps = [
        ":attributes_proto_cc",
        "@com_google_protobuf//:protobuf",
    ],
)

cc_test(
    name = "attributes_util_test",
    srcs = ["attributes_util_test.cc"],
    deps = [
        ":attributes_proto_cc",
        ":attributes_util",
        "//asylo/test/util:test_main",
        "@com_google_googletest//:gtest",
    ],
)

cc_library(
    name = "sgx_code_identity_expectation_matcher",
    srcs = [
        "sgx_code_identity_expectation_matcher.cc",
        "sgx_code_identity_expectation_matcher.h",
    ],
    visibility = ["//visibility:public"],
    deps = [
        ":code_identity_util",
        "//asylo/identity:identity_expectation_matcher",
        "//asylo/identity:identity_proto_cc",
    ],
    alwayslink = 1,
)

cc_test(
    name = "sgx_code_identity_expectation_matcher_test",
    srcs = [
        "sgx_code_identity_expectation_matcher.h",
        "sgx_code_identity_expectation_matcher_test.cc",
    ],
    deps = [
        ":code_identity_constants",
        ":code_identity_proto_cc",
        ":code_identity_test_util",
        ":sgx_code_identity_expectation_matcher",
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
    visibility = ["//asylo:implementation"],
    deps = [
        ":attributes_proto_cc",
        "//asylo/crypto/util:bytes",
        "//asylo/identity/util:aligned_object_ptr",
        "//asylo/util:logging",
        "//asylo/util:status",
        "@boringssl//:crypto",
        "@com_google_absl//absl/base:core_headers",
    ],
)

cc_test(
    name = "secs_attributes_test",
    srcs = ["secs_attributes_test.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":attributes_proto_cc",
        ":hardware_types",
        "//asylo/crypto/util:trivial_object_util",
        "//asylo/test/util:status_matchers",
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
        "@com_google_absl//absl/base:core_headers",
        "//asylo/crypto/util:bytes",
        "//asylo/util:logging",
        "@boringssl//:crypto",
    ] + select({
        "@linux_sgx//:sgx_hw": [
            "@linux_sgx//:trts",
            "//asylo/platform/core:trusted_core",
        ],
        "@linux_sgx//:sgx_sim": [
            "@linux_sgx//:trts",
        ],
        "//conditions:default": [
            ":code_identity_proto_cc",
            "//asylo/crypto/util:trivial_object_util",
            "//asylo/identity/util:sha256_hash_proto_cc",
        ],
    }),
)

cc_test(
    name = "fake_hardware_interface_test",
    srcs = ["fake_hardware_interface_test.cc"],
    deps = [
        ":code_identity_util",
        ":hardware_interface",
        "//asylo/crypto/util:bytes",
        "//asylo/crypto/util:trivial_object_util",
        "//asylo/test/util:proto_matchers",
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
    deps = [
        ":code_identity_util",
        ":hardware_interface",
        "//asylo/crypto/util:trivial_object_util",
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
        "//asylo/crypto/util:byte_container_util",
        "//asylo/crypto/util:bytes",
        "//asylo/identity:identity_acl_proto_cc",
        "//asylo/identity:identity_proto_cc",
        "//asylo/identity:sealed_secret_proto_cc",
        "//asylo/platform/common:singleton",
        "//asylo/util:cleansing_types",
        "//asylo/util:status",
        "@com_google_absl//absl/strings",
    ],
)

cc_library(
    name = "sgx_local_secret_sealer",
    srcs = ["sgx_local_secret_sealer.cc"],
    hdrs = ["sgx_local_secret_sealer.h"],
    visibility = ["//visibility:public"],
    deps = [
        ":code_identity_proto_cc",
        ":code_identity_util",
        ":hardware_types",
        ":local_secret_sealer_helpers",
        "//asylo/crypto:aes_gcm_siv",
        "//asylo/crypto/util:byte_container_util",
        "//asylo/crypto/util:byte_container_view",
        "//asylo/crypto/util:bytes",
        "//asylo/identity:identity_acl_proto_cc",
        "//asylo/identity:identity_proto_cc",
        "//asylo/identity:secret_sealer",
        "//asylo/util:cleansing_types",
        "//asylo/util:status",
        "@com_google_absl//absl/memory",
    ],
)

cc_test(
    name = "sgx_local_secret_sealer_test",
    srcs = ["sgx_local_secret_sealer_test.cc"],
    deps = [
        ":code_identity_proto_cc",
        ":code_identity_util",
        ":hardware_interface",
        ":local_sealed_secret_proto_cc",
        ":local_secret_sealer_helpers",
        ":sgx_local_secret_sealer",
        "//asylo/crypto/util:bytes",
        "//asylo/crypto/util:trivial_object_util",
        "//asylo/identity:identity_acl_proto_cc",
        "//asylo/identity:identity_proto_cc",
        "//asylo/identity:sealed_secret_proto_cc",
        "//asylo/platform/common:singleton",
        "//asylo/test/util:status_matchers",
        "//asylo/test/util:test_main",
        "//asylo/util:status",
        "@com_google_absl//absl/memory",
        "@com_google_googletest//:gtest",
    ],
)

cc_library(
    name = "proto_format",
    srcs = ["proto_format.cc"],
    hdrs = ["proto_format.h"],
    visibility = ["//asylo:implementation"],
    deps = [
        ":attributes_proto_cc",
        ":code_identity_proto_cc",
        ":hardware_types",
        "//asylo/identity/util:sha256_hash_proto_cc",
        "@com_google_absl//absl/memory",
        "@com_google_absl//absl/strings",
        "@com_google_protobuf//:protobuf",
    ],
)

cc_test(
    name = "proto_format_test",
    srcs = ["proto_format_test.cc"],
    deps = [
        ":code_identity_proto_cc",
        ":code_identity_util",
        ":hardware_types",
        ":proto_format",
        "//asylo/identity/util:sha256_hash_proto_cc",
        "//asylo/test/util:test_main",
        "@com_google_absl//absl/strings",
        "@com_google_googletest//:gtest",
    ],
)

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
load("@com_github_grpc_grpc//bazel:cc_grpc_library.bzl", "cc_grpc_library")
load("@rules_proto//proto:defs.bzl", "proto_library")
load("@rules_cc//cc:defs.bzl", "cc_library", "cc_test")
load("@rules_cc//cc:defs.bzl", "cc_proto_library")

# Used to enable gtest tests to run inside an enclave.
load("//asylo/bazel:asylo.bzl", "cc_test_and_cc_enclave_test")
load("//asylo/bazel:copts.bzl", "ASYLO_DEFAULT_COPTS")
load("@linux_sgx//:sgx_sdk.bzl", "sgx")

licenses(["notice"])

# This package defines sgx-specific portions of the enclave-identity and
# key-management library.

# This package group contains all packages related to SGX identity. It exists
# to aid in the transition period of moving files from this package to more
# granular packages.
package_group(
    name = "identity_sgx",
    packages = [
        "//asylo/identity/attestation/sgx/...",
        "//asylo/identity/platform/sgx/...",
        "//asylo/identity/provisioning/sgx/...",
        "//asylo/identity/sealing/sgx/...",
    ],
)

package(
    default_visibility = [":identity_sgx"],
)

proto_library(
    name = "attributes_proto",
    srcs = ["attributes.proto"],
    deprecation = "Use //asylo/identity/platform/sgx:attributes_proto",
    visibility = ["//visibility:public"],
    exports = ["//asylo/identity/platform/sgx:attributes_proto"],
    deps = ["//asylo/identity/platform/sgx:attributes_proto"],
)

cc_proto_library(
    name = "attributes_cc_proto",
    deprecation = "Use //asylo/identity/platform/sgx:attributes_cc_proto",
    visibility = ["//visibility:public"],
    deps = [":attributes_proto"],
)

proto_library(
    name = "code_identity_proto",
    srcs = ["code_identity.proto"],
    deprecation = "Use //asylo/identity/platform/sgx:code_identity_proto",
    visibility = ["//visibility:public"],
    exports = ["//asylo/identity/platform/sgx:code_identity_proto"],
    deps = ["//asylo/identity/platform/sgx:code_identity_proto"],
)

cc_proto_library(
    name = "code_identity_cc_proto",
    deprecation = "Use //asylo/identity/platform/sgx:code_identity_cc_proto",
    visibility = ["//visibility:public"],
    deps = [":code_identity_proto"],
)

proto_library(
    name = "machine_configuration_proto",
    srcs = ["machine_configuration.proto"],
    deprecation = "Use //asylo/identity/platform/sgx:machine_configuration_proto",
    visibility = ["//visibility:public"],
    exports = ["//asylo/identity/platform/sgx:machine_configuration_proto"],
    deps = ["//asylo/identity/platform/sgx:machine_configuration_proto"],
)

cc_proto_library(
    name = "machine_configuration_cc_proto",
    deprecation = "Use //asylo/identity/platform/sgx:machine_configuration_cc_proto",
    visibility = ["//visibility:public"],
    deps = [":machine_configuration_proto"],
)

proto_library(
    name = "sgx_identity_proto",
    srcs = ["sgx_identity.proto"],
    deprecation = "Use //asylo/identity/platform/sgx:sgx_identity_proto",
    visibility = ["//visibility:public"],
    exports = ["//asylo/identity/platform/sgx:sgx_identity_proto"],
    deps = ["//asylo/identity/platform/sgx:sgx_identity_proto"],
)

cc_proto_library(
    name = "sgx_identity_cc_proto",
    deprecation = "Use //asylo/identity/platform/sgx:sgx_identity_cc_proto",
    visibility = ["//visibility:public"],
    deps = [":sgx_identity_proto"],
)

proto_library(
    name = "pck_certificates_proto",
    srcs = ["pck_certificates.proto"],
    visibility = ["//asylo:implementation"],
    deps = [
        "//asylo/crypto:certificate_proto",
        "//asylo/identity/provisioning/sgx/internal:tcb_proto",
    ],
)

cc_proto_library(
    name = "pck_certificates_cc_proto",
    visibility = ["//asylo:implementation"],
    deps = [":pck_certificates_proto"],
)

proto_library(
    name = "local_assertion_proto",
    srcs = ["local_assertion.proto"],
)

cc_proto_library(
    name = "local_assertion_cc_proto",
    deps = [":local_assertion_proto"],
)

proto_library(
    name = "sgx_local_assertion_authority_config_proto",
    srcs = ["sgx_local_assertion_authority_config.proto"],
    visibility = ["//visibility:public"],
)

cc_proto_library(
    name = "sgx_local_assertion_authority_config_cc_proto",
    visibility = ["//visibility:public"],
    deps = ["sgx_local_assertion_authority_config_proto"],
)

proto_library(
    name = "sgx_age_remote_assertion_authority_config_proto",
    srcs = ["sgx_age_remote_assertion_authority_config.proto"],
    deprecation = "Use //asylo/identity/attestation/sgx:sgx_age_remote_assertion_authority_config_proto",
    exports = ["//asylo/identity/attestation/sgx:sgx_age_remote_assertion_authority_config_proto"],
    deps = [
        "//asylo/identity/attestation/sgx:sgx_age_remote_assertion_authority_config_proto",
    ],
)

cc_proto_library(
    name = "sgx_age_remote_assertion_authority_config_cc_proto",
    deprecation = "Use //asylo/identity/attestation/sgx:sgx_age_remote_assertion_authority_config_cc_proto",
    visibility = ["//visibility:public"],
    deps = ["sgx_age_remote_assertion_authority_config_proto"],
)

proto_library(
    name = "sgx_remote_assertion_generator_proto",
    srcs = ["sgx_remote_assertion_generator.proto"],
    deps = ["//asylo/identity/attestation/sgx/internal:remote_assertion_proto"],
)

cc_proto_library(
    name = "sgx_remote_assertion_generator_cc_proto",
    deps = [":sgx_remote_assertion_generator_proto"],
)

cc_grpc_library(
    name = "sgx_remote_assertion_generator_service",
    srcs = [":sgx_remote_assertion_generator_proto"],
    generate_mocks = True,
    grpc_only = True,
    deps = [":sgx_remote_assertion_generator_cc_proto"],
)

cc_library(
    name = "sgx_remote_assertion_generator_client",
    srcs = ["sgx_remote_assertion_generator_client.cc"],
    hdrs = ["sgx_remote_assertion_generator_client.h"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":sgx_remote_assertion_generator_service",
        "//asylo/crypto/util:byte_container_view",
        "//asylo/identity/attestation/sgx/internal:remote_assertion_cc_proto",
        "//asylo/util:status",
        "@com_github_grpc_grpc//:grpc++",
    ],
)

cc_test_and_cc_enclave_test(
    name = "sgx_remote_assertion_generator_client_test",
    srcs = ["sgx_remote_assertion_generator_client_test.cc"],
    backends = sgx.backend_labels,
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":sgx_remote_assertion_generator_client",
        ":sgx_remote_assertion_generator_service",
        "//asylo/crypto:algorithms_cc_proto",
        "//asylo/crypto:certificate_cc_proto",
        "//asylo/crypto:keys_cc_proto",
        "//asylo/identity/attestation/sgx/internal:remote_assertion_cc_proto",
        "//asylo/test/util:proto_matchers",
        "//asylo/test/util:status_matchers",
        "//asylo/test/util:test_main",
        "//asylo/util:status",
        "@com_github_grpc_grpc//:grpc++",
        "@com_google_absl//absl/memory",
        "@com_google_googletest//:gtest",
    ],
)

cc_library(
    name = "sgx_remote_assertion_generator_impl",
    srcs = ["sgx_remote_assertion_generator_impl.cc"],
    hdrs = ["sgx_remote_assertion_generator_impl.h"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":sgx_identity_util",
        ":sgx_remote_assertion_generator_service",
        "//asylo/crypto:certificate_cc_proto",
        "//asylo/crypto:signing_key",
        "//asylo/grpc/auth:enclave_auth_context",
        "//asylo/identity:descriptions",
        "//asylo/identity/attestation/sgx/internal:remote_assertion_util",
        "//asylo/util:mutex_guarded",
        "//asylo/util:status",
        "@com_github_grpc_grpc//:grpc++",
    ],
)

sgx.enclave_configuration(
    name = "sgx_remote_assertion_generator_impl_test_enclave_config",
    # Allocate enough threads for the multi-threaded test
    tcs_num = "64",
)

cc_test_and_cc_enclave_test(
    name = "sgx_remote_assertion_generator_impl_test",
    srcs = ["sgx_remote_assertion_generator_impl_test.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    enclave_test_config = ":sgx_remote_assertion_generator_impl_test_enclave_config",
    deps = [
        ":sgx_identity_util_internal",
        ":sgx_remote_assertion_generator_client",
        ":sgx_remote_assertion_generator_impl",
        "//asylo:enclave_cc_proto",
        "//asylo/crypto:certificate_cc_proto",
        "//asylo/crypto:ecdsa_p256_sha256_signing_key",
        "//asylo/crypto:keys_cc_proto",
        "//asylo/crypto:signing_key",
        "//asylo/grpc/auth:grpc++_security_enclave",
        "//asylo/grpc/auth:null_credentials_options",
        "//asylo/grpc/auth:sgx_local_credentials_options",
        "//asylo/identity:enclave_assertion_authority_config_cc_proto",
        "//asylo/identity:init",
        "//asylo/identity/attestation/sgx/internal:remote_assertion_cc_proto",
        "//asylo/identity/platform/sgx:code_identity_cc_proto",
        "//asylo/identity/platform/sgx:sgx_identity_cc_proto",
        "//asylo/test/util:enclave_assertion_authority_configs",
        "//asylo/test/util:proto_matchers",
        "//asylo/test/util:status_matchers",
        "//asylo/test/util:test_main",
        "//asylo/util:status",
        "//asylo/util:thread",
        "@com_github_grpc_grpc//:grpc++",
        "@com_google_absl//absl/memory",
        "@com_google_absl//absl/time",
        "@com_google_googletest//:gtest",
        "@com_google_protobuf//:protobuf",
    ],
)

cc_library(
    name = "code_identity_constants",
    srcs = ["code_identity_constants.cc"],
    hdrs = ["code_identity_constants.h"],
    copts = ASYLO_DEFAULT_COPTS,
    visibility = ["//asylo/identity:__subpackages__"],
)

cc_library(
    name = "sgx_local_assertion_generator",
    srcs = [
        "sgx_local_assertion_generator.cc",
        "sgx_local_assertion_generator.h",
    ],
    copts = ASYLO_DEFAULT_COPTS,
    visibility = ["//visibility:public"],
    deps = [
        ":code_identity_constants",
        ":hardware_interface",
        ":hardware_types",
        ":local_assertion_cc_proto",
        ":sgx_local_assertion_authority_config_cc_proto",
        "//asylo/crypto:sha256_hash",
        "//asylo/crypto/util:bytes",
        "//asylo/crypto/util:trivial_object_util",
        "//asylo/identity/attestation:enclave_assertion_generator",
        "//asylo/util:mutex_guarded",
        "//asylo/util:status",
    ],
    alwayslink = 1,
)

cc_test_and_cc_enclave_test(
    name = "sgx_local_assertion_generator_test",
    srcs = [
        "sgx_local_assertion_generator.h",
        "sgx_local_assertion_generator_test.cc",
    ],
    backends = sgx.backend_labels,
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":code_identity_constants",
        ":hardware_types",
        ":local_assertion_cc_proto",
        ":sgx_identity_util_internal",
        ":sgx_local_assertion_authority_config_cc_proto",
        ":sgx_local_assertion_generator",
        "//asylo/crypto:sha256_hash",
        "//asylo/crypto/util:bytes",
        "//asylo/crypto/util:trivial_object_util",
        "//asylo/identity:enclave_assertion_authority",
        "//asylo/identity:identity_cc_proto",
        "//asylo/identity/attestation:enclave_assertion_generator",
        "//asylo/identity/platform/sgx:sgx_identity_cc_proto",
        "//asylo/test/util:proto_matchers",
        "//asylo/test/util:status_matchers",
        "//asylo/test/util:test_main",
        "//asylo/util:mutex_guarded",
        "//asylo/util:thread",
        "@com_google_absl//absl/strings",
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
    copts = ASYLO_DEFAULT_COPTS,
    visibility = ["//visibility:public"],
    deps = [
        ":code_identity_constants",
        ":hardware_types",
        ":local_assertion_cc_proto",
        ":sgx_identity_util_internal",
        ":sgx_local_assertion_authority_config_cc_proto",
        "//asylo/crypto:sha256_hash",
        "//asylo/crypto/util:bytes",
        "//asylo/crypto/util:trivial_object_util",
        "//asylo/identity:descriptions",
        "//asylo/identity/attestation:enclave_assertion_verifier",
        "//asylo/util:status",
        "@com_google_absl//absl/synchronization",
    ],
    alwayslink = 1,
)

cc_test_and_cc_enclave_test(
    name = "sgx_local_assertion_verifier_test",
    srcs = [
        "sgx_local_assertion_verifier.h",
        "sgx_local_assertion_verifier_test.cc",
    ],
    backends = sgx.backend_labels,
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":code_identity_constants",
        ":hardware_interface",
        ":hardware_types",
        ":local_assertion_cc_proto",
        ":proto_format",
        ":sgx_identity_util_internal",
        ":sgx_local_assertion_authority_config_cc_proto",
        ":sgx_local_assertion_verifier",
        "//asylo/crypto:sha256_hash",
        "//asylo/crypto/util:trivial_object_util",
        "//asylo/identity:enclave_assertion_authority",
        "//asylo/identity:identity_cc_proto",
        "//asylo/identity/attestation:enclave_assertion_verifier",
        "//asylo/identity/platform/sgx:sgx_identity_cc_proto",
        "//asylo/test/util:proto_matchers",
        "//asylo/test/util:status_matchers",
        "//asylo/test/util:test_main",
        "//asylo/util:status",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/synchronization",
        "@com_google_googletest//:gtest",
        "@com_google_protobuf//:protobuf",
    ],
)

# This test uses FakeEnclave to simulate different enclaves. Since FakeEnclave
# should not be used inside a real enclave, this test is not a
# "cc_test_and_cc_enclave_test" target.
cc_test(
    name = "sgx_local_assertion_authority_test",
    srcs = [
        "sgx_local_assertion_authority_test.cc",
        "sgx_local_assertion_generator.h",
        "sgx_local_assertion_verifier.h",
    ],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":fake_enclave",
        ":local_assertion_cc_proto",
        ":proto_format",
        ":sgx_identity_util",
        ":sgx_identity_util_internal",
        ":sgx_local_assertion_generator",
        ":sgx_local_assertion_verifier",
        "//asylo/identity:identity_cc_proto",
        "//asylo/identity/attestation:enclave_assertion_generator",
        "//asylo/identity/attestation:enclave_assertion_verifier",
        "//asylo/identity/platform/sgx:sgx_identity_cc_proto",
        "//asylo/test/util:enclave_assertion_authority_configs",
        "//asylo/test/util:proto_matchers",
        "//asylo/test/util:status_matchers",
        "//asylo/test/util:test_main",
        "//asylo/util:mutex_guarded",
        "//asylo/util:status_macros",
        "@com_google_absl//absl/synchronization",
        "@com_google_googletest//:gtest",
    ],
)

cc_library(
    name = "sgx_age_remote_assertion_generator",
    hdrs = ["sgx_age_remote_assertion_generator.h"],
    copts = ASYLO_DEFAULT_COPTS,
    deprecation = "Use //asylo/identity/attestation/sgx:sgx_age_remote_assertion_generator",
    visibility = ["//visibility:public"],
    deps = ["//asylo/identity/attestation/sgx:sgx_age_remote_assertion_generator"],
)

cc_library(
    name = "sgx_identity_test_util",
    testonly = 1,
    srcs = ["sgx_identity_test_util.cc"],
    hdrs = ["sgx_identity_test_util.h"],
    copts = ASYLO_DEFAULT_COPTS,
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
    deps = [
        ":code_identity_constants",
        ":hardware_interface",
        ":hardware_types",
        ":proto_format",
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
        "//asylo/identity/provisioning/sgx/internal:platform_provisioning_cc_proto",
        "//asylo/util:logging",
        "//asylo/util:proto_enum_util",
        "//asylo/util:status",
        "@boringssl//:crypto",
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
        ":sgx_identity_expectation_matcher",
        ":sgx_identity_test_util",
        ":sgx_identity_util_internal",
        "//asylo/crypto:sha256_hash_cc_proto",
        "//asylo/crypto:sha256_hash_util",
        "//asylo/crypto/util:bytes",
        "//asylo/crypto/util:trivial_object_util",
        "//asylo/identity:descriptions",
        "//asylo/identity:identity_cc_proto",
        "//asylo/identity/platform/sgx:attributes_cc_proto",
        "//asylo/identity/platform/sgx:attributes_util",
        "//asylo/identity/platform/sgx:code_identity_cc_proto",
        "//asylo/identity/platform/sgx:machine_configuration_cc_proto",
        "//asylo/identity/platform/sgx:sgx_identity_cc_proto",
        "//asylo/identity/provisioning/sgx/internal:platform_provisioning_cc_proto",
        "//asylo/platform/common:singleton",
        "//asylo/test/util:proto_matchers",
        "//asylo/test/util:status_matchers",
        "//asylo/test/util:test_main",
        "//asylo/util:status",
        "@com_google_googletest//:gtest",
    ],
)

cc_library(
    name = "sgx_identity_util",
    srcs = ["sgx_identity_util.cc"],
    hdrs = ["sgx_identity_util.h"],
    copts = ASYLO_DEFAULT_COPTS,
    visibility = ["//visibility:public"],
    deps = [
        ":sgx_identity_util_internal",
        "//asylo/identity:identity_cc_proto",
        "//asylo/identity/platform/sgx:sgx_identity_cc_proto",
        "//asylo/util:status",
        "@com_google_absl//absl/strings",
    ],
)

# This test uses FakeEnclave to simulate different enclaves. Since FakeEnclave
# should not be used inside a real enclave, this test is not a
# "cc_test_and_cc_enclave_test" target.
cc_test(
    name = "sgx_identity_util_test",
    srcs = ["sgx_identity_util_test.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":fake_enclave",
        ":proto_format",
        ":sgx_identity_test_util",
        ":sgx_identity_util",
        "//asylo/identity:identity_cc_proto",
        "//asylo/identity/platform/sgx:sgx_identity_cc_proto",
        "//asylo/test/util:proto_matchers",
        "//asylo/test/util:status_matchers",
        "//asylo/test/util:test_main",
        "@com_google_googletest//:gtest",
    ],
)

cc_library(
    name = "sgx_code_identity_expectation_matcher",
    hdrs = ["sgx_code_identity_expectation_matcher.h"],
    copts = ASYLO_DEFAULT_COPTS,
    deprecation = "Use sgx_identity_expectation_matcher instead",
    visibility = ["//visibility:public"],
    deps = [":sgx_identity_expectation_matcher"],
    alwayslink = 1,
)

cc_library(
    name = "sgx_identity_expectation_matcher",
    srcs = ["sgx_identity_expectation_matcher.cc"],
    hdrs = ["sgx_identity_expectation_matcher.h"],
    copts = ASYLO_DEFAULT_COPTS,
    visibility = ["//visibility:public"],
    deps = [
        ":sgx_identity_util_internal",
        "//asylo/identity:descriptions",
        "//asylo/identity:identity_cc_proto",
        "//asylo/identity:identity_expectation_matcher",
        "//asylo/identity/platform/sgx:sgx_identity_cc_proto",
        "//asylo/util:status",
    ],
    alwayslink = 1,
)

cc_test_and_cc_enclave_test(
    name = "sgx_identity_expectation_matcher_test",
    srcs = [
        "sgx_identity_expectation_matcher.h",
        "sgx_identity_expectation_matcher_test.cc",
    ],
    backends = sgx.backend_labels,
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":code_identity_constants",
        ":proto_format",
        ":sgx_identity_expectation_matcher",
        ":sgx_identity_test_util",
        ":sgx_identity_util_internal",
        "//asylo/identity:descriptions",
        "//asylo/identity:identity_cc_proto",
        "//asylo/identity:identity_expectation_matcher",
        "//asylo/identity/platform/sgx:code_identity_cc_proto",
        "//asylo/identity/platform/sgx:machine_configuration_cc_proto",
        "//asylo/identity/platform/sgx:sgx_identity_cc_proto",
        "//asylo/test/util:status_matchers",
        "//asylo/test/util:test_main",
        "//asylo/util:status",
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
        "//asylo/crypto/util:bytes",
        "//asylo/identity:additional_authenticated_data_generator",
        "//asylo/identity/platform/sgx:architecture_bits",
        "//asylo/identity/platform/sgx:attributes_cc_proto",
        "//asylo/util:aligned_object_ptr",
        "//asylo/util:logging",
        "//asylo/util:status",
        "@boringssl//:crypto",
        "@com_google_absl//absl/base:core_headers",
        "@com_google_absl//absl/strings",
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
        "//asylo/crypto:sha256_hash_cc_proto",
        "//asylo/crypto/util:bssl_util",
        "//asylo/crypto/util:bytes",
        "//asylo/crypto/util:trivial_object_util",
        "//asylo/identity/platform/sgx:architecture_bits",
        "//asylo/identity/platform/sgx:attributes_cc_proto",
        "//asylo/identity/platform/sgx:machine_configuration_cc_proto",
        "//asylo/identity/platform/sgx:sgx_identity_cc_proto",
        "//asylo/identity/provisioning/sgx/internal:platform_provisioning_cc_proto",
        "//asylo/platform/primitives/sgx:sgx_error_space",
        "//asylo/util:logging",
        "//asylo/util:status",
        "@boringssl//:crypto",
        "@com_google_absl//absl/base:core_headers",
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
    deps = [
        ":hardware_types",
        "@com_google_absl//absl/memory",
        "//asylo/util:status",
    ] + select({
        "@com_google_asylo//asylo": [
            "//asylo/platform/primitives/sgx:sgx_error_space",
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
        "//asylo/crypto/util:bytes",
        "//asylo/crypto/util:trivial_object_util",
        "//asylo/identity/platform/sgx:architecture_bits",
        "//asylo/platform/primitives/sgx:sgx_error_space",
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

# A utility library associated with SGX PCE protocols.
cc_library(
    name = "pce_util",
    srcs = ["pce_util.cc"],
    hdrs = ["pce_util.h"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":hardware_types",
        "//asylo/crypto:algorithms_cc_proto",
        "//asylo/crypto:keys_cc_proto",
        "//asylo/crypto:rsa_oaep_encryption_key",
        "//asylo/crypto/util:bssl_util",
        "//asylo/crypto/util:trivial_object_util",
        "//asylo/identity:additional_authenticated_data_generator",
        "//asylo/util:proto_enum_util",
        "//asylo/util:status",
        "//asylo/util:status_macros",
        "@boringssl//:crypto",
        "@com_google_absl//absl/base:core_headers",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/types:optional",
        "@com_google_absl//absl/types:span",
        "@sgx_dcap//:pce_constants",
    ],
)

cc_test_and_cc_enclave_test(
    name = "pce_util_test",
    srcs = ["pce_util_test.cc"],
    backends = sgx.backend_labels,
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":hardware_types",
        ":pce_util",
        "//asylo/crypto:algorithms_cc_proto",
        "//asylo/crypto/util:bssl_util",
        "//asylo/crypto/util:bytes",
        "//asylo/crypto/util:trivial_object_util",
        "//asylo/test/util:proto_matchers",
        "//asylo/test/util:status_matchers",
        "//asylo/test/util:test_main",
        "//asylo/util:proto_enum_util",
        "//asylo/util:status_macros",
        "@boringssl//:crypto",
        "@com_google_absl//absl/base:core_headers",
        "@com_google_absl//absl/container:flat_hash_map",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/types:optional",
        "@com_google_googletest//:gtest",
        "@sgx_dcap//:pce_constants",
    ],
)

cc_library(
    name = "pck_certificate_util",
    srcs = ["pck_certificate_util.cc"],
    hdrs = ["pck_certificate_util.h"],
    copts = ASYLO_DEFAULT_COPTS,
    visibility = ["//asylo:implementation"],
    deps = [
        ":hardware_types",
        ":pck_certificates_cc_proto",
        "//asylo/crypto:asn1",
        "//asylo/crypto:asn1_schema",
        "//asylo/crypto:certificate_cc_proto",
        "//asylo/crypto:certificate_util",
        "//asylo/crypto/util:byte_container_view",
        "//asylo/identity/platform/sgx:machine_configuration_cc_proto",
        "//asylo/identity/provisioning/sgx/internal:container_util",
        "//asylo/identity/provisioning/sgx/internal:platform_provisioning",
        "//asylo/identity/provisioning/sgx/internal:platform_provisioning_cc_proto",
        "//asylo/identity/provisioning/sgx/internal:tcb",
        "//asylo/identity/provisioning/sgx/internal:tcb_cc_proto",
        "//asylo/util:logging",
        "//asylo/util:status",
        "@com_google_absl//absl/base",
        "@com_google_absl//absl/container:flat_hash_map",
        "@com_google_absl//absl/container:flat_hash_set",
        "@com_google_absl//absl/hash",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/strings:str_format",
        "@com_google_absl//absl/types:optional",
        "@com_google_protobuf//:protobuf",
    ],
)

cc_test_and_cc_enclave_test(
    name = "pck_certificate_util_test",
    srcs = ["pck_certificate_util_test.cc"],
    backends = sgx.backend_labels,
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":pck_certificate_util",
        ":pck_certificates_cc_proto",
        "//asylo/crypto:asn1",
        "//asylo/crypto:certificate_cc_proto",
        "//asylo/identity/provisioning/sgx/internal:platform_provisioning",
        "//asylo/identity/provisioning/sgx/internal:platform_provisioning_cc_proto",
        "//asylo/identity/provisioning/sgx/internal:tcb",
        "//asylo/identity/provisioning/sgx/internal:tcb_cc_proto",
        "//asylo/test/util:status_matchers",
        "//asylo/test/util:test_main",
        "//asylo/util:logging",
        "//asylo/util:proto_enum_util",
        "//asylo/util:status",
        "@com_google_absl//absl/random",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/strings:str_format",
        "@com_google_googletest//:gtest",
        "@com_google_protobuf//:protobuf",
    ],
)

sgx.enclave_configuration(
    name = "tcb_container_util_enclave_test_config",
    heap_max_size = "0x1000000",
)

cc_library(
    name = "sgx_infrastructural_enclave_manager",
    srcs = ["sgx_infrastructural_enclave_manager.cc"],
    hdrs = ["sgx_infrastructural_enclave_manager.h"],
    copts = ASYLO_DEFAULT_COPTS,
    visibility = ["//asylo:implementation"],
    deps = [
        ":pce_util",
        "//asylo:enclave_cc_proto",
        "//asylo:enclave_client",
        "//asylo/crypto:certificate_cc_proto",
        "//asylo/crypto:keys_cc_proto",
        "//asylo/crypto/util:trivial_object_util",
        "//asylo/identity:enclave_assertion_authority_config_cc_proto",
        "//asylo/identity/attestation/sgx/internal:attestation_key_certificate_impl",
        "//asylo/identity/attestation/sgx/internal:intel_architectural_enclave_interface",
        "//asylo/identity/attestation/sgx/internal:remote_assertion_generator_enclave_cc_proto",
        "//asylo/identity/platform/sgx:machine_configuration_cc_proto",
        "//asylo/identity/platform/sgx:sgx_identity_cc_proto",
        "//asylo/identity/provisioning/sgx/internal:platform_provisioning",
        "//asylo/identity/provisioning/sgx/internal:platform_provisioning_cc_proto",
        "//asylo/identity/sealing:sealed_secret_cc_proto",
        "//asylo/platform/primitives/sgx:loader_cc_proto",
        "//asylo/util:status",
        "//asylo/util:status_macros",
        "@com_google_absl//absl/strings",
    ],
)

cc_test(
    name = "sgx_infrastructural_enclave_manager_test",
    srcs = ["sgx_infrastructural_enclave_manager_test.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":hardware_types",
        ":pce_util",
        ":sgx_identity_test_util",
        ":sgx_infrastructural_enclave_manager",
        "//asylo:enclave_cc_proto",
        "//asylo/crypto:algorithms_cc_proto",
        "//asylo/crypto:certificate_cc_proto",
        "//asylo/crypto:keys_cc_proto",
        "//asylo/crypto/util:trivial_object_util",
        "//asylo/identity/attestation/sgx/internal:attestation_key_certificate_impl",
        "//asylo/identity/attestation/sgx/internal:mock_intel_architectural_enclave_interface",
        "//asylo/identity/attestation/sgx/internal:remote_assertion_generator_enclave_cc_proto",
        "//asylo/identity/platform/sgx:machine_configuration_cc_proto",
        "//asylo/identity/provisioning/sgx/internal:platform_provisioning_cc_proto",
        "//asylo/identity/sealing:sealed_secret_cc_proto",
        "//asylo/test/util:memory_matchers",
        "//asylo/test/util:mock_enclave_client",
        "//asylo/test/util:proto_matchers",
        "//asylo/test/util:status_matchers",
        "//asylo/test/util:test_main",
        "@com_google_absl//absl/memory",
        "@com_google_absl//absl/strings",
        "@com_google_googletest//:gtest",
    ],
)

cc_library(
    name = "mock_sgx_infrastructural_enclave_manager",
    testonly = 1,
    hdrs = [
        "mock_sgx_infrastructural_enclave_manager.h",
        "sgx_infrastructural_enclave_manager.h",
    ],
    copts = ASYLO_DEFAULT_COPTS,
    visibility = ["//asylo:implementation"],
    deps = [
        "//asylo:enclave_client",
        "//asylo/crypto:certificate_cc_proto",
        "//asylo/crypto:keys_cc_proto",
        "//asylo/identity:enclave_assertion_authority_config_cc_proto",
        "//asylo/identity/attestation/sgx/internal:intel_architectural_enclave_interface",
        "//asylo/identity/attestation/sgx/internal:remote_assertion_generator_enclave_cc_proto",
        "//asylo/identity/platform/sgx:machine_configuration_cc_proto",
        "//asylo/identity/platform/sgx:sgx_identity_cc_proto",
        "//asylo/identity/provisioning/sgx/internal:platform_provisioning_cc_proto",
        "//asylo/identity/sealing:sealed_secret_cc_proto",
        "//asylo/util:status",
        "@com_google_googletest//:gtest",
    ],
)

cc_library(
    name = "sgx_local_secret_sealer",
    hdrs = ["sgx_local_secret_sealer.h"],
    copts = ASYLO_DEFAULT_COPTS,
    deprecation = "Use //asylo/identity/sealing/sgx:sgx_local_secret_sealer",
    visibility = ["//visibility:public"],
    deps = ["//asylo/identity/sealing/sgx:sgx_local_secret_sealer"],
)

cc_library(
    name = "proto_format",
    srcs = ["proto_format.cc"],
    hdrs = ["proto_format.h"],
    copts = ASYLO_DEFAULT_COPTS,
    visibility = ["//asylo:implementation"],
    deps = [
        ":hardware_types",
        "//asylo/crypto:sha256_hash_cc_proto",
        "//asylo/identity/platform/sgx:attributes_cc_proto",
        "//asylo/identity/platform/sgx:attributes_util",
        "//asylo/identity/platform/sgx:code_identity_cc_proto",
        "//asylo/identity/platform/sgx:machine_configuration_cc_proto",
        "//asylo/identity/platform/sgx:miscselect_cc_proto",
        "//asylo/identity/platform/sgx:miscselect_util",
        "//asylo/identity/provisioning/sgx/internal:platform_provisioning_cc_proto",
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
        ":sgx_identity_util",
        "//asylo/crypto:sha256_hash_cc_proto",
        "//asylo/identity/platform/sgx:architecture_bits",
        "//asylo/identity/platform/sgx:attributes_util",
        "//asylo/identity/platform/sgx:machine_configuration_cc_proto",
        "//asylo/identity/platform/sgx:miscselect_cc_proto",
        "//asylo/identity/platform/sgx:miscselect_util",
        "//asylo/identity/platform/sgx:sgx_identity_cc_proto",
        "//asylo/identity/provisioning/sgx/internal:platform_provisioning_cc_proto",
        "//asylo/test/util:status_matchers",
        "//asylo/test/util:test_main",
        "@com_google_absl//absl/strings",
        "@com_google_googletest//:gtest",
    ],
)

cc_library(
    name = "pck_certs_from_json",
    srcs = ["pck_certs_from_json.cc"],
    hdrs = ["pck_certs_from_json.h"],
    copts = ASYLO_DEFAULT_COPTS,
    visibility = ["//asylo:implementation"],
    deps = [
        ":hardware_types",
        ":pck_certificates_cc_proto",
        "//asylo/crypto:certificate_cc_proto",
        "//asylo/crypto:certificate_util",
        "//asylo/identity/platform/sgx:machine_configuration_cc_proto",
        "//asylo/identity/provisioning/sgx/internal:platform_provisioning_cc_proto",
        "//asylo/identity/provisioning/sgx/internal:tcb_cc_proto",
        "//asylo/identity/provisioning/sgx/internal:tcb_info_from_json",
        "//asylo/util:error_codes",
        "//asylo/util:function_deleter",
        "//asylo/util:hex_util",
        "//asylo/util:proto_struct_util",
        "//asylo/util:status",
        "//asylo/util:url_util",
        "@com_google_absl//absl/memory",
        "@com_google_absl//absl/strings",
        "@com_google_protobuf//:cc_wkt_protos",
        "@com_google_protobuf//:protobuf",
    ],
)

cc_test(
    name = "pck_certs_from_json_test",
    srcs = ["pck_certs_from_json_test.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":pck_certificates_cc_proto",
        ":pck_certs_from_json",
        "//asylo/test/util:output_collector",
        "//asylo/test/util:proto_matchers",
        "//asylo/test/util:status_matchers",
        "//asylo/test/util:test_main",
        "//asylo/util:error_codes",
        "//asylo/util:status",
        "@com_google_absl//absl/memory",
        "@com_google_googletest//:gtest",
        "@com_google_protobuf//:cc_wkt_protos",
        "@com_google_protobuf//:protobuf",
    ],
)

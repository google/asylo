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

# Used to enable gtest tests to run inside an enclave.
load("//asylo/bazel:asylo.bzl", "cc_test_and_cc_enclave_test", "sgx_enclave_test")
load("//asylo/bazel:copts.bzl", "ASYLO_DEFAULT_COPTS")
load("@linux_sgx//:sgx_sdk.bzl", "sgx")

licenses(["notice"])  # Apache v2.0

# This package defines sgx-specific portions of the enclave-identity and
# key-management library.

proto_library(
    name = "attributes_proto",
    srcs = ["attributes.proto"],
    visibility = ["//asylo:implementation"],
)

cc_proto_library(
    name = "attributes_cc_proto",
    visibility = ["//asylo:implementation"],
    deps = [":attributes_proto"],
)

proto_library(
    name = "code_identity_proto",
    srcs = ["code_identity.proto"],
    visibility = ["//asylo:implementation"],
    deps = [
        ":attributes_proto",
        "//asylo/identity/util:sha256_hash_proto",
    ],
)

cc_proto_library(
    name = "code_identity_cc_proto",
    visibility = ["//asylo:implementation"],
    deps = [":code_identity_proto"],
)

proto_library(
    name = "sgx_identity_proto",
    srcs = ["sgx_identity.proto"],
    visibility = ["//asylo:implementation"],
    deps = [
        ":code_identity_proto",
        ":platform_provisioning_proto",
    ],
)

cc_proto_library(
    name = "sgx_identity_cc_proto",
    visibility = ["//asylo:implementation"],
    deps = [":sgx_identity_proto"],
)

proto_library(
    name = "platform_provisioning_proto",
    srcs = ["platform_provisioning.proto"],
    visibility = ["//asylo:implementation"],
    deps = ["//asylo/crypto:algorithms_proto"],
)

cc_proto_library(
    name = "platform_provisioning_cc_proto",
    visibility = ["//asylo:implementation"],
    deps = [":platform_provisioning_proto"],
)

proto_library(
    name = "attestation_key_proto",
    srcs = ["attestation_key.proto"],
    deps = ["//asylo/crypto:keys_proto"],
)

cc_proto_library(
    name = "attestation_key_cc_proto",
    deps = [":attestation_key_proto"],
)

proto_library(
    name = "attestation_key_certificate_proto",
    srcs = ["attestation_key_certificate.proto"],
    visibility = ["//asylo:implementation"],
    deps = [
        ":platform_provisioning_proto",
        "//asylo/crypto:keys_proto",
    ],
)

cc_proto_library(
    name = "attestation_key_certificate_cc_proto",
    visibility = ["//asylo:implementation"],
    deps = [":attestation_key_certificate_proto"],
)

proto_library(
    name = "pck_certificates_proto",
    srcs = ["pck_certificates.proto"],
    visibility = ["//asylo:implementation"],
    deps = [
        ":tcb_proto",
        "//asylo/crypto:certificate_proto",
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
    name = "miscselect_proto",
    srcs = ["miscselect.proto"],
    visibility = ["//asylo:implementation"],
)

cc_proto_library(
    name = "miscselect_cc_proto",
    visibility = ["//asylo:implementation"],
    deps = [":miscselect_proto"],
)

proto_library(
    name = "remote_assertion_proto",
    srcs = ["remote_assertion.proto"],
    deps = [
        ":sgx_identity_proto",
        "//asylo/crypto:algorithms_proto",
        "//asylo/crypto:certificate_proto",
    ],
)

cc_proto_library(
    name = "remote_assertion_cc_proto",
    deps = [":remote_assertion_proto"],
)

proto_library(
    name = "local_sealed_secret_proto",
    srcs = ["local_sealed_secret.proto"],
)

cc_proto_library(
    name = "local_sealed_secret_cc_proto",
    deps = [":local_sealed_secret_proto"],
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
    name = "tcb_proto",
    srcs = ["tcb.proto"],
    visibility = ["//asylo:implementation"],
    deps = [
        ":platform_provisioning_proto",
        "@com_google_protobuf//:timestamp_proto",
    ],
)

cc_proto_library(
    name = "tcb_cc_proto",
    visibility = ["//asylo:implementation"],
    deps = [":tcb_proto"],
)

proto_library(
    name = "sgx_remote_assertion_generator_proto",
    srcs = ["sgx_remote_assertion_generator.proto"],
    deps = ["remote_assertion_proto"],
)

cc_proto_library(
    name = "sgx_remote_assertion_generator_cc_proto",
    deps = [":sgx_remote_assertion_generator_proto"],
)

proto_library(
    name = "remote_assertion_generator_enclave_proto",
    srcs = ["remote_assertion_generator_enclave.proto"],
    visibility = ["//asylo:implementation"],
    deps = [
        ":platform_provisioning_proto",
        ":remote_assertion_proto",
        ":sgx_identity_proto",
        "//asylo:enclave_proto",
        "//asylo/crypto:certificate_proto",
        "//asylo/crypto:keys_proto",
        "//asylo/identity:identity_proto",
        "//asylo/identity:sealed_secret_proto",
    ],
)

cc_proto_library(
    name = "remote_assertion_generator_enclave_cc_proto",
    visibility = ["//asylo:implementation"],
    deps = ["remote_assertion_generator_enclave_proto"],
)

proto_library(
    name = "remote_assertion_generator_test_util_enclave_proto",
    srcs = ["remote_assertion_generator_test_util_enclave.proto"],
    deps = [
        ":platform_provisioning_proto",
        ":remote_assertion_proto",
        "//asylo:enclave_proto",
        "//asylo/crypto:certificate_proto",
        "//asylo/crypto:keys_proto",
        "//asylo/identity:sealed_secret_proto",
    ],
)

cc_proto_library(
    name = "remote_assertion_generator_test_util_enclave_cc_proto",
    deps = [":remote_assertion_generator_test_util_enclave_proto"],
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
        ":remote_assertion_cc_proto",
        ":sgx_remote_assertion_generator_service",
        "//asylo/crypto/util:byte_container_view",
        "//asylo/util:status",
        "@com_github_grpc_grpc//:grpc++",
    ],
)

cc_test_and_cc_enclave_test(
    name = "sgx_remote_assertion_generator_client_test",
    srcs = ["sgx_remote_assertion_generator_client_test.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":remote_assertion_cc_proto",
        ":sgx_remote_assertion_generator_client",
        ":sgx_remote_assertion_generator_service",
        "//asylo/crypto:algorithms_cc_proto",
        "//asylo/crypto:certificate_cc_proto",
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
        ":remote_assertion_util",
        ":sgx_identity_util",
        ":sgx_remote_assertion_generator_service",
        "//asylo/crypto:certificate_cc_proto",
        "//asylo/crypto:signing_key",
        "//asylo/grpc/auth:enclave_auth_context",
        "//asylo/identity:descriptions",
        "//asylo/util:mutex_guarded",
        "//asylo/util:status",
        "@com_github_grpc_grpc//:grpc++",
    ],
)

# This test can only be run outside an enclave. Consequently, this test is not
# a "cc_test_and_cc_enclave_test" target.
cc_test(
    name = "sgx_remote_assertion_generator_impl_test",
    srcs = ["sgx_remote_assertion_generator_impl_test.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":code_identity_cc_proto",
        ":code_identity_util",
        ":remote_assertion_cc_proto",
        ":sgx_identity_cc_proto",
        ":sgx_remote_assertion_generator_client",
        ":sgx_remote_assertion_generator_impl",
        "//asylo:enclave_cc_proto",
        "//asylo/crypto:certificate_cc_proto",
        "//asylo/crypto:ecdsa_p256_sha256_signing_key",
        "//asylo/crypto:signing_key",
        "//asylo/grpc/auth:grpc++_security_enclave",
        "//asylo/grpc/auth:null_credentials_options",
        "//asylo/grpc/auth:sgx_local_credentials_options",
        "//asylo/identity:enclave_assertion_authority_config_cc_proto",
        "//asylo/identity:init",
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
    name = "remote_assertion_generator_constants",
    srcs = ["remote_assertion_generator_constants.cc"],
    hdrs = ["remote_assertion_generator_constants.h"],
    copts = ASYLO_DEFAULT_COPTS,
)

cc_library(
    name = "attestation_key_certificate_impl",
    srcs = ["attestation_key_certificate_impl.cc"],
    hdrs = ["attestation_key_certificate_impl.h"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":attestation_key_cc_proto",
        ":attestation_key_certificate_cc_proto",
        ":hardware_types",
        ":platform_provisioning",
        ":remote_assertion_generator_constants",
        "//asylo/crypto:algorithms_cc_proto",
        "//asylo/crypto:certificate_cc_proto",
        "//asylo/crypto:certificate_interface",
        "//asylo/crypto:ecdsa_p256_sha256_signing_key",
        "//asylo/crypto:keys_cc_proto",
        "//asylo/crypto:signing_key",
        "//asylo/crypto/util:byte_container_view",
        "//asylo/crypto/util:trivial_object_util",
        "//asylo/identity:additional_authenticated_data_generator",
        "//asylo/util:status",
        "@com_google_absl//absl/memory",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/strings:str_format",
        "@com_google_absl//absl/types:optional",
    ],
)

cc_test_and_cc_enclave_test(
    name = "attestation_key_certificate_impl_test",
    srcs = ["attestation_key_certificate_impl_test.cc"],
    deps = [
        ":attestation_key_cc_proto",
        ":attestation_key_certificate_cc_proto",
        ":attestation_key_certificate_impl",
        ":hardware_types",
        ":platform_provisioning",
        "//asylo/crypto:algorithms_cc_proto",
        "//asylo/crypto:certificate_cc_proto",
        "//asylo/crypto:certificate_interface",
        "//asylo/crypto:ecdsa_p256_sha256_signing_key",
        "//asylo/crypto:fake_certificate",
        "//asylo/crypto:keys_cc_proto",
        "//asylo/crypto:signing_key",
        "//asylo/identity:additional_authenticated_data_generator",
        "//asylo/test/util:status_matchers",
        "//asylo/test/util:test_main",
        "//asylo/util:status",
        "@com_google_absl//absl/strings",
        "@com_google_googletest//:gtest",
    ],
)

cc_library(
    name = "remote_assertion_generator_enclave_util",
    srcs = ["remote_assertion_generator_enclave_util.cc"],
    hdrs = ["remote_assertion_generator_enclave_util.h"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":attestation_key_cc_proto",
        ":hardware_types",
        ":remote_assertion_generator_constants",
        ":remote_assertion_generator_enclave_cc_proto",
        ":sgx_local_secret_sealer",
        ":sgx_remote_assertion_generator_impl",
        "//asylo/crypto:algorithms_cc_proto",
        "//asylo/crypto:certificate_cc_proto",
        "//asylo/crypto:ecdsa_p256_sha256_signing_key",
        "//asylo/crypto:keys_cc_proto",
        "//asylo/crypto:signing_key",
        "//asylo/crypto/util:byte_container_util",
        "//asylo/crypto/util:trivial_object_util",
        "//asylo/grpc/auth:grpc++_security_enclave",
        "//asylo/grpc/auth:sgx_local_credentials_options",
        "//asylo/identity:additional_authenticated_data_generator",
        "//asylo/identity:sealed_secret_cc_proto",
        "//asylo/util:cleansing_types",
        "//asylo/util:status",
        "@com_github_grpc_grpc//:grpc++",
        "@com_google_absl//absl/strings",
        "@com_google_protobuf//:protobuf",
    ],
)

cc_test(
    name = "remote_assertion_generator_enclave_util_test",
    srcs = ["remote_assertion_generator_enclave_util_test.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":attestation_key_cc_proto",
        ":remote_assertion_generator_constants",
        ":remote_assertion_generator_enclave_cc_proto",
        ":remote_assertion_generator_enclave_util",
        ":sgx_local_secret_sealer",
        "//asylo/crypto:certificate_cc_proto",
        "//asylo/crypto:ecdsa_p256_sha256_signing_key",
        "//asylo/crypto:keys_cc_proto",
        "//asylo/crypto/util:trivial_object_util",
        "//asylo/identity:sealed_secret_cc_proto",
        "//asylo/test/util:proto_matchers",
        "//asylo/test/util:status_matchers",
        "//asylo/test/util:test_main",
        "//asylo/util:cleansing_types",
        "@com_google_googletest//:gtest",
        "@com_google_protobuf//:protobuf",
    ],
)

sgx.unsigned_enclave(
    name = "remote_assertion_generator_test_util_enclave_unsigned.so",
    testonly = 1,
    srcs = ["remote_assertion_generator_test_util_enclave.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":code_identity_util",
        ":hardware_types",
        ":platform_provisioning",
        ":remote_assertion_cc_proto",
        ":remote_assertion_generator_enclave_util",
        ":remote_assertion_generator_test_util_enclave_cc_proto",
        ":sgx_remote_assertion_generator_client",
        "//asylo:enclave_cc_proto",
        "//asylo:enclave_runtime",
        "//asylo/crypto:ecdsa_p256_sha256_signing_key",
        "//asylo/grpc/auth:grpc++_security_enclave",
        "//asylo/grpc/auth:sgx_local_credentials_options",
        "//asylo/util:status",
        "@com_github_grpc_grpc//:grpc++",
        "@com_github_grpc_grpc//:grpc_secure",
        "@com_google_protobuf//:protobuf_lite",
    ],
)

sgx.debug_enclave(
    name = "remote_assertion_generator_test_util_enclave.so",
    unsigned = "remote_assertion_generator_test_util_enclave_unsigned.so",
    config = "//asylo/grpc/util:grpc_enclave_config",
    testonly = 1,
)

sgx.enclave_configuration(
    name = "remote_assertion_generator_enclave_config",
    heap_max_size = "0x6400000",  # ~100 MB
    tcs_num = "50",
)

sgx.unsigned_enclave(
    name = "remote_assertion_generator_enclave_unsigned.so",
    srcs = [
        "remote_assertion_generator_enclave.cc",
        "remote_assertion_generator_enclave.h",
    ],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":code_identity_cc_proto",
        ":code_identity_util",
        ":hardware_interface",
        ":hardware_types",
        ":pce_util",
        ":platform_provisioning",
        ":remote_assertion_generator_enclave_cc_proto",
        ":remote_assertion_generator_enclave_util",
        ":sgx_remote_assertion_generator_impl",
        "//asylo:enclave_cc_proto",
        "//asylo:enclave_runtime",
        "//asylo/crypto:certificate_cc_proto",
        "//asylo/crypto:ecdsa_p256_sha256_signing_key",
        "//asylo/crypto:keys_cc_proto",
        "//asylo/crypto:signing_key",
        "//asylo/crypto/util:trivial_object_util",
        "//asylo/util:logging",
        "//asylo/util:mutex_guarded",
        "//asylo/util:status",
    ],
)

sgx.debug_enclave(
    name = "remote_assertion_generator_enclave.so",
    unsigned = "remote_assertion_generator_enclave_unsigned.so",
    config = ":remote_assertion_generator_enclave_config",
)

sgx_enclave_test(
    name = "remote_assertion_generator_enclave_test",
    srcs = ["remote_assertion_generator_enclave_test.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    enclaves = {
        "assertion_generator_enclave": ":remote_assertion_generator_enclave.so",
        "test_util_enclave": ":remote_assertion_generator_test_util_enclave.so",
    },
    test_args = [
        "--remote_assertion_generator_enclave_path='{assertion_generator_enclave}'",
        "--remote_assertion_generator_test_util_enclave_path='{test_util_enclave}'",
    ],
    deps = [
        ":attestation_key_cc_proto",
        ":code_identity_cc_proto",
        ":code_identity_util",
        ":pce_util",
        ":platform_provisioning",
        ":platform_provisioning_cc_proto",
        ":remote_assertion_cc_proto",
        ":remote_assertion_generator_constants",
        ":remote_assertion_generator_enclave_cc_proto",
        ":remote_assertion_generator_enclave_util",
        ":remote_assertion_generator_test_util_enclave_cc_proto",
        "//asylo:enclave_cc_proto",
        "//asylo:enclave_client",
        "//asylo/crypto:algorithms_cc_proto",
        "//asylo/crypto:certificate_cc_proto",
        "//asylo/crypto:ecdsa_p256_sha256_signing_key",
        "//asylo/crypto:keys_cc_proto",
        "//asylo/identity:sealed_secret_cc_proto",
        "//asylo/platform/primitives/sgx:loader_cc_proto",
        "//asylo/test/util:enclave_assertion_authority_configs",
        "//asylo/test/util:status_matchers",
        "//asylo/test/util:test_main",
        "//asylo/util:status",
        "//asylo/util:status_macros",
        "//asylo/util:thread",
        "@com_google_absl//absl/flags:flag",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/synchronization",
        "@com_google_googletest//:gtest",
    ],
)

cc_library(
    name = "remote_assertion_util",
    srcs = ["remote_assertion_util.cc"],
    hdrs = ["remote_assertion_util.h"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":code_identity_cc_proto",
        ":remote_assertion_cc_proto",
        ":sgx_identity_cc_proto",
        "//asylo/crypto:algorithms_cc_proto",
        "//asylo/crypto:certificate_cc_proto",
        "//asylo/crypto:signing_key",
        "//asylo/util:status",
        "@com_google_absl//absl/strings",
    ],
)

cc_test_and_cc_enclave_test(
    name = "remote_assertion_util_test",
    srcs = ["remote_assertion_util_test.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":remote_assertion_cc_proto",
        ":remote_assertion_util",
        ":sgx_identity_cc_proto",
        ":sgx_identity_util",
        "//asylo/crypto:certificate_cc_proto",
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
        "//asylo/identity:enclave_assertion_generator",
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
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":code_identity_constants",
        ":code_identity_util",
        ":hardware_types",
        ":local_assertion_cc_proto",
        ":sgx_identity_cc_proto",
        ":sgx_local_assertion_authority_config_cc_proto",
        ":sgx_local_assertion_generator",
        "//asylo/crypto:sha256_hash",
        "//asylo/crypto/util:bytes",
        "//asylo/crypto/util:trivial_object_util",
        "//asylo/identity:enclave_assertion_authority",
        "//asylo/identity:enclave_assertion_generator",
        "//asylo/identity:identity_cc_proto",
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
        ":code_identity_util",
        ":hardware_types",
        ":local_assertion_cc_proto",
        ":sgx_local_assertion_authority_config_cc_proto",
        "//asylo/crypto:sha256_hash",
        "//asylo/crypto/util:bytes",
        "//asylo/crypto/util:trivial_object_util",
        "//asylo/identity:descriptions",
        "//asylo/identity:enclave_assertion_verifier",
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
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":code_identity_constants",
        ":code_identity_util",
        ":hardware_interface",
        ":hardware_types",
        ":local_assertion_cc_proto",
        ":proto_format",
        ":sgx_identity_cc_proto",
        ":sgx_local_assertion_authority_config_cc_proto",
        ":sgx_local_assertion_verifier",
        "//asylo/crypto:sha256_hash",
        "//asylo/crypto/util:trivial_object_util",
        "//asylo/identity:enclave_assertion_authority",
        "//asylo/identity:enclave_assertion_verifier",
        "//asylo/identity:identity_cc_proto",
        "//asylo/test/util:proto_matchers",
        "//asylo/test/util:status_matchers",
        "//asylo/test/util:test_main",
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
        ":code_identity_util",
        ":fake_enclave",
        ":local_assertion_cc_proto",
        ":proto_format",
        ":sgx_identity_cc_proto",
        ":sgx_identity_util",
        ":sgx_local_assertion_generator",
        ":sgx_local_assertion_verifier",
        "//asylo/identity:enclave_assertion_generator",
        "//asylo/identity:enclave_assertion_verifier",
        "//asylo/identity:identity_cc_proto",
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
    name = "code_identity_test_util",
    testonly = 1,
    srcs = ["code_identity_test_util.cc"],
    hdrs = ["code_identity_test_util.h"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":attributes_cc_proto",
        ":code_identity_cc_proto",
        ":code_identity_constants",
        ":code_identity_util",
        ":platform_provisioning_cc_proto",
        ":sgx_identity_cc_proto",
        "//asylo/crypto/util:bytes",
        "//asylo/crypto/util:trivial_object_util",
        "//asylo/identity:descriptions",
        "//asylo/identity:identity_cc_proto",
        "//asylo/identity/util:sha256_hash_cc_proto",
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
    copts = ASYLO_DEFAULT_COPTS,
    visibility = ["//asylo:implementation"],
    deps = [
        ":attributes_cc_proto",
        ":attributes_util",
        ":code_identity_cc_proto",
        ":code_identity_constants",
        ":hardware_interface",
        ":hardware_types",
        ":platform_provisioning",
        ":platform_provisioning_cc_proto",
        ":proto_format",
        ":sgx_identity_cc_proto",
        "//asylo/crypto/util:bssl_util",
        "//asylo/crypto/util:byte_container_util",
        "//asylo/crypto/util:bytes",
        "//asylo/crypto/util:trivial_object_util",
        "//asylo/identity:descriptions",
        "//asylo/identity:identity_cc_proto",
        "//asylo/identity/util:sha256_hash_cc_proto",
        "//asylo/identity/util:sha256_hash_util",
        "//asylo/util:logging",
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
    name = "code_identity_util_test",
    srcs = ["code_identity_util_test.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":attributes_cc_proto",
        ":attributes_util",
        ":code_identity_cc_proto",
        ":code_identity_constants",
        ":code_identity_test_util",
        ":code_identity_util",
        ":fake_enclave",
        ":hardware_interface",
        ":hardware_types",
        ":platform_provisioning_cc_proto",
        ":proto_format",
        ":sgx_identity_cc_proto",
        ":sgx_identity_expectation_matcher",
        "//asylo/crypto/util:bytes",
        "//asylo/crypto/util:trivial_object_util",
        "//asylo/identity:descriptions",
        "//asylo/identity:identity_cc_proto",
        "//asylo/identity/util:sha256_hash_cc_proto",
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
    name = "sgx_identity_util",
    srcs = ["sgx_identity_util.cc"],
    hdrs = ["sgx_identity_util.h"],
    copts = ASYLO_DEFAULT_COPTS,
    visibility = ["//asylo:implementation"],
    deps = [
        ":code_identity_util",
        ":sgx_identity_cc_proto",
        "//asylo/identity:identity_cc_proto",
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
        ":code_identity_test_util",
        ":fake_enclave",
        ":proto_format",
        ":sgx_identity_cc_proto",
        ":sgx_identity_util",
        "//asylo/identity:identity_cc_proto",
        "//asylo/test/util:proto_matchers",
        "//asylo/test/util:status_matchers",
        "//asylo/test/util:test_main",
        "@com_google_googletest//:gtest",
    ],
)

cc_library(
    name = "attributes_util",
    srcs = ["attributes_util.cc"],
    hdrs = ["attributes_util.h"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":attributes_cc_proto",
        "@com_google_protobuf//:protobuf",
    ],
)

cc_test_and_cc_enclave_test(
    name = "attributes_util_test",
    srcs = ["attributes_util_test.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":attributes_cc_proto",
        ":attributes_util",
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
        ":code_identity_util",
        ":sgx_identity_cc_proto",
        "//asylo/identity:descriptions",
        "//asylo/identity:identity_cc_proto",
        "//asylo/identity:identity_expectation_matcher",
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
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":code_identity_cc_proto",
        ":code_identity_constants",
        ":code_identity_test_util",
        ":code_identity_util",
        ":proto_format",
        ":sgx_identity_cc_proto",
        ":sgx_identity_expectation_matcher",
        "//asylo/identity:descriptions",
        "//asylo/identity:identity_cc_proto",
        "//asylo/identity:identity_expectation_matcher",
        "//asylo/test/util:status_matchers",
        "//asylo/test/util:test_main",
        "//asylo/util:status",
        "@com_google_googletest//:gtest",
    ],
)

cc_library(
    name = "hardware_types",
    srcs = [
        "secs_attributes.cc",
        "secs_miscselect.cc",
    ],
    hdrs = [
        "identity_key_management_structs.h",
        "secs_attributes.h",
        "secs_miscselect.h",
    ],
    copts = ASYLO_DEFAULT_COPTS,
    visibility = ["//asylo:implementation"],
    deps = [
        ":attributes_cc_proto",
        ":miscselect_cc_proto",
        "//asylo/crypto/util:bytes",
        "//asylo/identity/util:aligned_object_ptr",
        "//asylo/util:logging",
        "//asylo/util:status",
        "@boringssl//:crypto",
        "@com_google_absl//absl/base:core_headers",
        "@com_google_absl//absl/strings",
    ],
)

cc_test_and_cc_enclave_test(
    name = "secs_attributes_test",
    srcs = ["secs_attributes_test.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":attributes_cc_proto",
        ":hardware_types",
        "//asylo/crypto/util:trivial_object_util",
        "//asylo/test/util:status_matchers",
        "//asylo/test/util:test_main",
        "@com_google_absl//absl/strings",
        "@com_google_googletest//:gtest",
    ],
)

cc_test_and_cc_enclave_test(
    name = "secs_miscselect_test",
    srcs = ["secs_miscselect_test.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":hardware_types",
        "//asylo/test/util:status_matchers",
        "//asylo/test/util:test_main",
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
        ":attributes_cc_proto",
        ":hardware_types",
        ":platform_provisioning_cc_proto",
        ":proto_format",
        ":sgx_identity_cc_proto",
        "//asylo/crypto/util:bssl_util",
        "//asylo/crypto/util:bytes",
        "//asylo/crypto/util:trivial_object_util",
        "//asylo/identity/util:sha256_hash_cc_proto",
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
        "@com_google_asylo//asylo": ["hardware_interface.cc"],
        "//conditions:default": ["fake_hardware_interface.cc"],
    }),
    hdrs = ["hardware_interface.h"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":hardware_types",
        "@com_google_absl//absl/base:core_headers",
        "//asylo/crypto/util:bytes",
        "//asylo/util:status",
        "@boringssl//:crypto",
    ] + select({
        "@com_google_asylo//asylo": [
            "//asylo/platform/primitives/sgx:sgx_error_space",
            "@linux_sgx//:trts",
        ],
        "//conditions:default": [":fake_enclave"],
    }),
)

cc_test(
    name = "fake_hardware_interface_test",
    srcs = ["fake_hardware_interface_test.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":code_identity_util",
        ":fake_enclave",
        ":hardware_interface",
        ":hardware_types",
        "//asylo/crypto/util:bytes",
        "//asylo/crypto/util:trivial_object_util",
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
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":code_identity_util",
        ":hardware_interface",
        ":hardware_types",
        "//asylo/crypto/util:trivial_object_util",
        "//asylo/test/util:status_matchers",
        "//asylo/test/util:test_main",
        "@com_google_googletest//:gtest",
    ],
)

cc_library(
    name = "platform_provisioning",
    srcs = ["platform_provisioning.cc"],
    hdrs = ["platform_provisioning.h"],
    copts = ASYLO_DEFAULT_COPTS,
    visibility = ["//asylo:implementation"],
    deps = [
        ":hardware_types",
        ":platform_provisioning_cc_proto",
        "//asylo/crypto/util:trivial_object_util",
        "//asylo/util:status",
        "@com_google_absl//absl/strings",
    ],
)

cc_test_and_cc_enclave_test(
    name = "platform_provisioning_test",
    srcs = ["platform_provisioning_test.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":hardware_types",
        ":platform_provisioning",
        ":platform_provisioning_cc_proto",
        "//asylo/crypto/util:trivial_object_util",
        "//asylo/test/util:status_matchers",
        "//asylo/test/util:test_main",
        "//asylo/util:status",
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
    name = "pck_certificates",
    srcs = ["pck_certificates.cc"],
    hdrs = ["pck_certificates.h"],
    copts = ASYLO_DEFAULT_COPTS,
    visibility = ["//asylo:implementation"],
    deps = [
        ":pck_certificates_cc_proto",
        ":platform_provisioning_cc_proto",
        ":tcb",
        ":tcb_cc_proto",
        ":tcb_container_util",
        "//asylo/crypto:certificate_cc_proto",
        "//asylo/crypto:certificate_util",
        "//asylo/util:status",
        "@com_google_absl//absl/container:flat_hash_map",
        "@com_google_absl//absl/container:flat_hash_set",
        "@com_google_protobuf//:protobuf",
    ],
)

cc_test_and_cc_enclave_test(
    name = "pck_certificates_test",
    srcs = ["pck_certificates_test.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":pck_certificates",
        ":pck_certificates_cc_proto",
        ":platform_provisioning",
        ":platform_provisioning_cc_proto",
        ":tcb_cc_proto",
        "//asylo/crypto:certificate_cc_proto",
        "//asylo/test/util:status_matchers",
        "//asylo/test/util:test_main",
        "//asylo/util:logging",
        "//asylo/util:status",
        "@com_google_absl//absl/strings",
        "@com_google_googletest//:gtest",
    ],
)

cc_library(
    name = "tcb",
    srcs = ["tcb.cc"],
    hdrs = ["tcb.h"],
    copts = ASYLO_DEFAULT_COPTS,
    visibility = ["//asylo:implementation"],
    deps = [
        ":hardware_types",
        ":platform_provisioning",
        ":tcb_cc_proto",
        ":tcb_container_util",
        "//asylo/crypto/util:byte_container_view",
        "//asylo/util:status",
        "@com_google_absl//absl/base:core_headers",
        "@com_google_absl//absl/container:flat_hash_map",
        "@com_google_absl//absl/strings",
        "@com_google_protobuf//:cc_wkt_protos",
        "@com_google_protobuf//:protobuf",
    ],
)

cc_test_and_cc_enclave_test(
    name = "tcb_test",
    srcs = ["tcb_test.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":platform_provisioning_cc_proto",
        ":tcb",
        ":tcb_cc_proto",
        "//asylo/test/util:proto_matchers",
        "//asylo/test/util:status_matchers",
        "//asylo/test/util:test_main",
        "//asylo/util:status",
        "@com_google_absl//absl/base:core_headers",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/time",
        "@com_google_googletest//:gtest",
        "@com_google_protobuf//:cc_wkt_protos",
    ],
)

cc_library(
    name = "tcb_container_util",
    srcs = ["tcb_container_util.cc"],
    hdrs = ["tcb_container_util.h"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":platform_provisioning_cc_proto",
        ":tcb_cc_proto",
        "//asylo/crypto/util:byte_container_util",
        "//asylo/crypto/util:byte_container_view",
        "//asylo/util:status",
        "@com_google_protobuf//:protobuf",
    ],
)

sgx.enclave_configuration(
    name = "tcb_container_util_enclave_test_config",
    heap_max_size = "0x1000000",
)

cc_test_and_cc_enclave_test(
    name = "tcb_container_util_test",
    srcs = ["tcb_container_util_test.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    enclave_test_config = ":tcb_container_util_enclave_test_config",
    deps = [
        ":hardware_types",
        ":platform_provisioning",
        ":platform_provisioning_cc_proto",
        ":tcb",
        ":tcb_cc_proto",
        ":tcb_container_util",
        "//asylo/test/util:test_main",
        "@com_google_absl//absl/container:flat_hash_set",
        "@com_google_absl//absl/random",
        "@com_google_googletest//:gtest",
    ],
)

cc_library(
    name = "tcb_info_from_json",
    srcs = ["tcb_info_from_json.cc"],
    hdrs = ["tcb_info_from_json.h"],
    copts = ASYLO_DEFAULT_COPTS,
    visibility = ["//asylo:implementation"],
    deps = [
        ":platform_provisioning",
        ":platform_provisioning_cc_proto",
        ":tcb",
        ":tcb_cc_proto",
        ":tcb_container_util",
        "//asylo/util:logging",
        "//asylo/util:proto_struct_util",
        "//asylo/util:status",
        "@com_google_absl//absl/base",
        "@com_google_absl//absl/container:flat_hash_map",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/strings:str_format",
        "@com_google_absl//absl/time",
        "@com_google_protobuf//:cc_wkt_protos",
        "@com_google_protobuf//:protobuf",
    ],
)

cc_test_and_cc_enclave_test(
    name = "tcb_info_from_json_test",
    srcs = ["tcb_info_from_json_test.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":platform_provisioning_cc_proto",
        ":tcb",
        ":tcb_cc_proto",
        ":tcb_info_from_json",
        "//asylo/test/util:output_collector",
        "//asylo/test/util:proto_matchers",
        "//asylo/test/util:status_matchers",
        "//asylo/test/util:test_main",
        "//asylo/util:logging",
        "//asylo/util:status",
        "@com_google_absl//absl/base:core_headers",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/time",
        "@com_google_googletest//:gtest",
        "@com_google_protobuf//:cc_wkt_protos",
        "@com_google_protobuf//:protobuf",
    ],
)

cc_library(
    name = "provisioning_consistency_checker",
    srcs = ["provisioning_consistency_checker.cc"],
    hdrs = ["provisioning_consistency_checker.h"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":pck_certificates",
        ":pck_certificates_cc_proto",
        ":tcb",
        ":tcb_cc_proto",
        ":tcb_container_util",
        "@com_google_absl//absl/container:flat_hash_map",
        "@com_google_absl//absl/container:flat_hash_set",
        "@com_google_absl//absl/strings",
    ],
)

cc_test_and_cc_enclave_test(
    name = "provisioning_consistency_checker_test",
    srcs = ["provisioning_consistency_checker_test.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":provisioning_consistency_checker",
        ":tcb_cc_proto",
        "//asylo/test/util:test_main",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/types:span",
        "@com_google_googletest//:gtest",
        "@com_google_protobuf//:protobuf",
    ],
)

# Defines an interface for interacting with Intel Architectural Enclaves.
cc_library(
    name = "intel_architectural_enclave_interface",
    hdrs = ["intel_architectural_enclave_interface.h"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":hardware_types",
        "//asylo/crypto:algorithms_cc_proto",
        "//asylo/crypto/util:bytes",
        "//asylo/util:status",
        "@com_google_absl//absl/types:span",
    ],
)

# Implementation of IntelArchitecturalEnclaveInterface using Intel's SGX Data
# Center Attestation Primitives (DCAP) library.
cc_library(
    name = "dcap_intel_architectural_enclave_interface",
    srcs = ["dcap_intel_architectural_enclave_interface.cc"],
    hdrs = ["dcap_intel_architectural_enclave_interface.h"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":hardware_types",
        ":intel_architectural_enclave_interface",
        ":pce_util",
        "//asylo/crypto:algorithms_cc_proto",
        "//asylo/crypto/util:bytes",
        "//asylo/util:status",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/types:span",
        "@linux_sgx//:public",
        "@sgx_dcap//:pce_constants",
        "@sgx_dcap//:pce_wrapper",
        "@sgx_dcap//:quote_wrapper",
    ],
)

proto_library(
    name = "report_oracle_enclave_proto",
    srcs = ["report_oracle_enclave.proto"],
    deps = [
        ":platform_provisioning_proto",
        "//asylo:enclave_proto",
    ],
)

cc_proto_library(
    name = "report_oracle_enclave_cc_proto",
    deps = ["report_oracle_enclave_proto"],
)

sgx.unsigned_enclave(
    name = "report_oracle_enclave_unsigned.so",
    srcs = ["report_oracle_enclave.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":hardware_interface",
        ":platform_provisioning",
        ":report_oracle_enclave_cc_proto",
        "//asylo:enclave_cc_proto",
        "//asylo:enclave_runtime",
        "//asylo/util:status",
    ],
)

sgx.enclave_configuration(
    name = "report_oracle_enclave_config",
    provision_key = "1",
)

sgx.debug_enclave(
    name = "report_oracle_enclave.so",
    unsigned = "report_oracle_enclave_unsigned.so",
    config = ":report_oracle_enclave_config",
)

sgx_enclave_test(
    name = "dcap_intel_architectural_enclave_interface_e2e_test",
    srcs = ["dcap_intel_architectural_enclave_interface_e2e_test.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    enclaves = {
        "report_oracle_enclave_path": ":report_oracle_enclave.so",
    },
    tags = ["noregression"],
    test_args = [
        "--report_oracle_enclave_path='{report_oracle_enclave_path}'",
    ],
    deps = [
        ":code_identity_util",
        ":dcap_intel_architectural_enclave_interface",
        ":hardware_types",
        ":pce_util",
        ":platform_provisioning",
        ":platform_provisioning_cc_proto",
        ":report_oracle_enclave_cc_proto",
        "//asylo:enclave_cc_proto",
        "//asylo:enclave_client",
        "//asylo/crypto:algorithms_cc_proto",
        "//asylo/crypto:keys_cc_proto",
        "//asylo/crypto:rsa_oaep_encryption_key",
        "//asylo/crypto/util:trivial_object_util",
        "//asylo/platform/primitives/sgx:loader_cc_proto",
        "//asylo/test/util:status_matchers",
        "//asylo/test/util:test_main",
        "//asylo/util:cleansing_types",
        "//asylo/util:status",
        "@com_google_absl//absl/flags:flag",
        "@com_google_absl//absl/memory",
        "@com_google_absl//absl/strings",
        "@com_google_googletest//:gtest",
        "@sgx_dcap//:pce_constants",
    ],
)

# Since the DCAP interface is never used in an enclave, this test is not a
# "cc_test_and_cc_enclave_test" target.
cc_test(
    name = "dcap_intel_architectural_enclave_interface_test",
    srcs = ["dcap_intel_architectural_enclave_interface_test.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":dcap_intel_architectural_enclave_interface",
        ":hardware_types",
        ":pce_util",
        "//asylo/crypto:algorithms_cc_proto",
        "//asylo/crypto/util:byte_container_view",
        "//asylo/crypto/util:trivial_object_util",
        "//asylo/test/util:status_matchers",
        "//asylo/test/util:test_main",
        "//asylo/util:status",
        "@com_google_absl//absl/memory",
        "@com_google_googletest//:gtest",
        "@sgx_dcap//:pce_constants",
        "@sgx_dcap//:pce_wrapper",
    ],
)

cc_library(
    name = "mock_intel_architectural_enclave_interface",
    testonly = 1,
    hdrs = ["mock_intel_architectural_enclave_interface.h"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":hardware_types",
        ":intel_architectural_enclave_interface",
        "//asylo/crypto:algorithms_cc_proto",
        "//asylo/crypto/util:bytes",
        "//asylo/util:status",
        "@com_google_absl//absl/types:span",
        "@com_google_googletest//:gtest",
    ],
)

cc_library(
    name = "sgx_infrastructural_enclave_manager",
    srcs = ["sgx_infrastructural_enclave_manager.cc"],
    hdrs = ["sgx_infrastructural_enclave_manager.h"],
    copts = ASYLO_DEFAULT_COPTS,
    visibility = ["//asylo:implementation"],
    deps = [
        ":code_identity_cc_proto",
        ":intel_architectural_enclave_interface",
        ":pce_util",
        ":platform_provisioning",
        ":platform_provisioning_cc_proto",
        ":remote_assertion_generator_enclave_cc_proto",
        ":sgx_identity_cc_proto",
        "//asylo:enclave_cc_proto",
        "//asylo:enclave_client",
        "//asylo/crypto:certificate_cc_proto",
        "//asylo/crypto:keys_cc_proto",
        "//asylo/crypto/util:trivial_object_util",
        "//asylo/identity:sealed_secret_cc_proto",
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
        ":code_identity_test_util",
        ":hardware_types",
        ":mock_intel_architectural_enclave_interface",
        ":pce_util",
        ":platform_provisioning_cc_proto",
        ":remote_assertion_generator_enclave_cc_proto",
        ":sgx_identity_cc_proto",
        ":sgx_infrastructural_enclave_manager",
        "//asylo:enclave_cc_proto",
        "//asylo/crypto:algorithms_cc_proto",
        "//asylo/crypto:certificate_cc_proto",
        "//asylo/crypto:keys_cc_proto",
        "//asylo/crypto/util:trivial_object_util",
        "//asylo/identity:sealed_secret_cc_proto",
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
        ":intel_architectural_enclave_interface",
        ":platform_provisioning_cc_proto",
        ":remote_assertion_generator_enclave_cc_proto",
        ":sgx_identity_cc_proto",
        "//asylo:enclave_client",
        "//asylo/crypto:certificate_cc_proto",
        "//asylo/crypto:keys_cc_proto",
        "//asylo/identity:sealed_secret_cc_proto",
        "//asylo/util:status",
        "@com_google_googletest//:gtest",
    ],
)

cc_library(
    name = "local_secret_sealer_helpers",
    srcs = ["local_secret_sealer_helpers.cc"],
    hdrs = ["local_secret_sealer_helpers.h"],
    copts = ASYLO_DEFAULT_COPTS,
    visibility = ["//visibility:private"],
    deps = [
        ":code_identity_cc_proto",
        ":code_identity_util",
        ":hardware_interface",
        ":hardware_types",
        ":local_sealed_secret_cc_proto",
        ":platform_provisioning_cc_proto",
        ":sgx_identity_cc_proto",
        "//asylo/crypto:aead_cryptor",
        "//asylo/crypto:algorithms_cc_proto",
        "//asylo/crypto:sha256_hash",
        "//asylo/crypto/util:byte_container_util",
        "//asylo/crypto/util:byte_container_view",
        "//asylo/crypto/util:bytes",
        "//asylo/crypto/util:trivial_object_util",
        "//asylo/identity:identity_acl_cc_proto",
        "//asylo/identity:identity_cc_proto",
        "//asylo/identity:sealed_secret_cc_proto",
        "//asylo/platform/common:singleton",
        "//asylo/util:cleansing_types",
        "//asylo/util:status",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/types:span",
    ],
)

cc_library(
    name = "sgx_local_secret_sealer",
    srcs = ["sgx_local_secret_sealer.cc"],
    hdrs = ["sgx_local_secret_sealer.h"],
    copts = ASYLO_DEFAULT_COPTS,
    visibility = ["//visibility:public"],
    deps = [
        ":code_identity_cc_proto",
        ":code_identity_util",
        ":hardware_types",
        ":local_secret_sealer_helpers",
        ":sgx_identity_cc_proto",
        "//asylo/crypto:aead_cryptor",
        "//asylo/crypto:algorithms_cc_proto",
        "//asylo/crypto/util:byte_container_util",
        "//asylo/crypto/util:byte_container_view",
        "//asylo/crypto/util:bytes",
        "//asylo/identity:identity_acl_cc_proto",
        "//asylo/identity:identity_cc_proto",
        "//asylo/identity:sealed_secret_cc_proto",
        "//asylo/identity:secret_sealer",
        "//asylo/util:cleansing_types",
        "//asylo/util:status",
        "@com_google_absl//absl/memory",
    ],
)

proto_library(
    name = "local_secret_sealer_test_data_proto",
    testonly = 1,
    srcs = ["local_secret_sealer_test_data.proto"],
    deps = [
        ":code_identity_proto",
        ":sgx_identity_proto",
        "//asylo/identity:sealed_secret_proto",
    ],
)

cc_proto_library(
    name = "local_secret_sealer_test_data_cc_proto",
    testonly = 1,
    deps = ["local_secret_sealer_test_data_proto"],
)

cc_binary(
    name = "generate_local_secret_sealer_test_data",
    testonly = 1,
    srcs = ["generate_local_secret_sealer_test_data.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":code_identity_cc_proto",
        ":fake_enclave",
        ":hardware_types",
        ":local_secret_sealer_test_data_cc_proto",
        ":sgx_identity_util",
        ":sgx_local_secret_sealer",
        "//asylo/crypto/util:trivial_object_util",
        "//asylo/util:logging",
        "//asylo/util:status",
        "@com_google_absl//absl/flags:flag",
        "@com_google_absl//absl/flags:parse",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/time",
        "@com_google_protobuf//:protobuf",
    ],
)

# This test uses FakeEnclave to simulate different enclaves. Since FakeEnclave
# should not be used inside a real enclave, this test is not a
# "cc_test_and_cc_enclave_test" target.
cc_test(
    name = "sgx_local_secret_sealer_test",
    srcs = ["sgx_local_secret_sealer_test.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    data = [":testdata/local_secret_sealer_test_data"],
    deps = [
        ":code_identity_cc_proto",
        ":code_identity_util",
        ":fake_enclave",
        ":hardware_types",
        ":local_sealed_secret_cc_proto",
        ":local_secret_sealer_helpers",
        ":local_secret_sealer_test_data_cc_proto",
        ":platform_provisioning_cc_proto",
        ":proto_format",
        ":sgx_local_secret_sealer",
        "//asylo/crypto:algorithms_cc_proto",
        "//asylo/crypto/util:byte_container_view",
        "//asylo/crypto/util:bytes",
        "//asylo/crypto/util:trivial_object_util",
        "//asylo/identity:identity_acl_cc_proto",
        "//asylo/identity:identity_cc_proto",
        "//asylo/identity:sealed_secret_cc_proto",
        "//asylo/platform/common:singleton",
        "//asylo/test/util:status_matchers",
        "//asylo/test/util:test_main",
        "//asylo/util:path",
        "//asylo/util:status",
        "@com_google_absl//absl/memory",
        "@com_google_googletest//:gtest",
        "@com_google_protobuf//:protobuf",
    ],
)

cc_library(
    name = "proto_format",
    srcs = ["proto_format.cc"],
    hdrs = ["proto_format.h"],
    copts = ASYLO_DEFAULT_COPTS,
    visibility = ["//asylo:implementation"],
    deps = [
        ":attributes_cc_proto",
        ":code_identity_cc_proto",
        ":hardware_types",
        ":miscselect_cc_proto",
        ":platform_provisioning_cc_proto",
        "//asylo/identity/util:sha256_hash_cc_proto",
        "@com_google_absl//absl/memory",
        "@com_google_absl//absl/strings",
        "@com_google_protobuf//:protobuf",
    ],
)

cc_test_and_cc_enclave_test(
    name = "proto_format_test",
    srcs = ["proto_format_test.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":hardware_types",
        ":miscselect_cc_proto",
        ":platform_provisioning_cc_proto",
        ":proto_format",
        ":sgx_identity_cc_proto",
        ":sgx_identity_util",
        "//asylo/identity/util:sha256_hash_cc_proto",
        "//asylo/test/util:status_matchers",
        "//asylo/test/util:test_main",
        "@com_google_absl//absl/strings",
        "@com_google_googletest//:gtest",
    ],
)

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

load("@com_google_asylo_backend_provider//:transitions.bzl", "transitions")
load("@linux_sgx//:sgx_sdk.bzl", "sgx")
load("@rules_cc//cc:defs.bzl", "cc_library", "cc_proto_library", "cc_test")
load("@rules_proto//proto:defs.bzl", "proto_library")
load(
    "//asylo/bazel:asylo.bzl",
    "cc_enclave_test",
    "cc_test_and_cc_enclave_test",
    "enclave_test",
)
load("//asylo/bazel:copts.bzl", "ASYLO_DEFAULT_COPTS")
load(
    "//asylo/bazel:sgx_rules.bzl",
    "sgx_cc_unsigned_enclave",
    "sgx_debug_sign_enclave",
    "sgx_enclave_test",
)

licenses(["notice"])

proto_library(
    name = "sgx_age_remote_assertion_authority_config_proto",
    srcs = ["sgx_age_remote_assertion_authority_config.proto"],
    visibility = ["//visibility:public"],
    deps = [
        "//asylo/crypto:certificate_proto",
        "//asylo/identity:identity_acl_proto",
    ],
)

cc_proto_library(
    name = "sgx_age_remote_assertion_authority_config_cc_proto",
    visibility = ["//visibility:public"],
    deps = ["sgx_age_remote_assertion_authority_config_proto"],
)

proto_library(
    name = "sgx_intel_ecdsa_qe_remote_assertion_authority_config_proto",
    srcs = ["sgx_intel_ecdsa_qe_remote_assertion_authority_config.proto"],
    visibility = ["//visibility:public"],
    deps = [
        "//asylo/crypto:certificate_proto",
        "//asylo/identity:identity_acl_proto",
    ],
)

cc_proto_library(
    name = "sgx_intel_ecdsa_qe_remote_assertion_authority_config_cc_proto",
    visibility = ["//visibility:public"],
    deps = ["sgx_intel_ecdsa_qe_remote_assertion_authority_config_proto"],
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
    name = "sgx_remote_assertion_generator_test_enclave_proto",
    srcs = ["sgx_remote_assertion_generator_test_enclave.proto"],
    deps = [
        "//asylo:enclave_proto",
        "//asylo/crypto:certificate_proto",
        "//asylo/identity:identity_proto",
        "//asylo/identity/platform/sgx:sgx_identity_proto",
    ],
)

cc_proto_library(
    name = "sgx_remote_assertion_generator_test_enclave_cc_proto",
    deps = ["sgx_remote_assertion_generator_test_enclave_proto"],
)

cc_library(
    name = "sgx_age_remote_assertion_generator",
    srcs = ["sgx_age_remote_assertion_generator.cc"],
    hdrs = ["sgx_age_remote_assertion_generator.h"],
    copts = ASYLO_DEFAULT_COPTS,
    visibility = ["//visibility:public"],
    deps = [
        ":sgx_age_remote_assertion_authority_config_cc_proto",
        "//asylo/crypto:certificate_cc_proto",
        "//asylo/crypto:certificate_interface",
        "//asylo/crypto:certificate_util",
        "//asylo/grpc/auth:grpc++_security_enclave",
        "//asylo/grpc/auth:sgx_local_credentials_options",
        "//asylo/identity:identity_cc_proto",
        "//asylo/identity/attestation:enclave_assertion_generator",
        "//asylo/identity/attestation/sgx/internal:certificate_util",
        "//asylo/identity/attestation/sgx/internal:remote_assertion_cc_proto",
        "//asylo/identity/attestation/sgx/internal:sgx_remote_assertion_generator_client",
        "//asylo/identity/platform/sgx/internal:code_identity_constants",
        "//asylo/util:mutex_guarded",
        "//asylo/util:status",
        "@com_google_absl//absl/memory",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/time",
        "@com_google_protobuf//:protobuf",
        "@com_google_protobuf//:protobuf_lite",
    ],
    alwayslink = 1,
)

sgx_cc_unsigned_enclave(
    name = "sgx_remote_assertion_generator_test_enclave_unsigned.so",
    testonly = 1,
    srcs = ["sgx_remote_assertion_generator_test_enclave.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":sgx_age_remote_assertion_generator",
        ":sgx_intel_ecdsa_qe_remote_assertion_generator",
        ":sgx_remote_assertion_generator_test_enclave_cc_proto",
        "//asylo:enclave_cc_proto",
        "//asylo:enclave_runtime",
        "//asylo/identity/platform/sgx:sgx_identity_util",
        "//asylo/util:status_macros",
    ],
)

sgx_debug_sign_enclave(
    name = "sgx_remote_assertion_generator_test_enclave.so",
    testonly = 1,
    config = "//asylo/grpc/util:grpc_enclave_config",
    unsigned = "sgx_remote_assertion_generator_test_enclave_unsigned.so",
)

cc_library(
    name = "sgx_remote_assertion_generator_test_enclave_wrapper",
    testonly = 1,
    srcs = ["sgx_remote_assertion_generator_test_enclave_wrapper.cc"],
    hdrs = ["sgx_remote_assertion_generator_test_enclave_wrapper.h"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":sgx_remote_assertion_generator_test_enclave_cc_proto",
        "//asylo:enclave_cc_proto",
        "//asylo:enclave_client",
        "//asylo/identity:identity_cc_proto",
        "//asylo/identity/platform/sgx:sgx_identity_cc_proto",
        "//asylo/platform/core:untrusted_core",
        "//asylo/platform/primitives/sgx:loader_cc_proto",
        "//asylo/test/util:enclave_assertion_authority_configs",
        "//asylo/util:status",
        "@com_google_absl//absl/memory",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/strings",
    ],
)

enclave_test(
    name = "sgx_age_remote_assertion_generator_test",
    srcs = [
        "sgx_age_remote_assertion_generator.h",
        "sgx_age_remote_assertion_generator_test.cc",
    ],
    backends = sgx.backend_labels,
    copts = ASYLO_DEFAULT_COPTS,
    enclaves = {
        "assertion_generator_enclave": "//asylo/identity/attestation/sgx/internal:remote_assertion_generator_enclave_no_flc.so",
        "sgx_remote_assertion_generator_test_enclave": ":sgx_remote_assertion_generator_test_enclave.so",
    },
    test_args = [
        "--assertion_generator_enclave_path='{assertion_generator_enclave}'",
        "--generator_test_enclave_path='{sgx_remote_assertion_generator_test_enclave}'",
    ],
    deps = [
        ":sgx_age_remote_assertion_authority_config_cc_proto",
        ":sgx_age_remote_assertion_generator",
        ":sgx_remote_assertion_generator_test_enclave_cc_proto",
        ":sgx_remote_assertion_generator_test_enclave_wrapper",
        "//asylo:enclave_cc_proto",
        "//asylo:enclave_client",
        "//asylo/crypto:certificate_cc_proto",
        "//asylo/crypto:certificate_util",
        "//asylo/identity:descriptions",
        "//asylo/identity:enclave_assertion_authority",
        "//asylo/identity:identity_cc_proto",
        "//asylo/identity:init",
        "//asylo/identity/attestation:enclave_assertion_generator",
        "//asylo/identity/attestation/sgx/internal:fake_pce",
        "//asylo/identity/attestation/sgx/internal:remote_assertion_generator_enclave_cc_proto",
        "//asylo/identity/attestation/sgx/internal:sgx_infrastructural_enclave_manager",
        "//asylo/identity/attestation/sgx/internal:sgx_remote_assertion_generator_client",
        "//asylo/identity/attestation/sgx/internal:sgx_remote_assertion_generator_impl",
        "//asylo/identity/platform/sgx:sgx_identity_cc_proto",
        "//asylo/identity/platform/sgx:sgx_identity_util",
        "//asylo/identity/platform/sgx/internal:code_identity_constants",
        "//asylo/identity/provisioning/sgx/internal:fake_sgx_pki",
        "//asylo/platform/primitives/sgx:loader_cc_proto",
        "//asylo/test/util:enclave_assertion_authority_configs",
        "//asylo/test/util:proto_matchers",
        "//asylo/test/util:status_matchers",
        "//asylo/test/util:test_main",
        "//asylo/util:mutex_guarded",
        "//asylo/util:status",
        "//asylo/util:thread",
        "@com_google_absl//absl/flags:flag",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/synchronization",
        "@com_google_absl//absl/types:span",
        "@com_google_googletest//:gtest",
        "@com_google_protobuf//:protobuf",
    ],
)

cc_library(
    name = "sgx_age_remote_assertion_verifier",
    srcs = ["sgx_age_remote_assertion_verifier.cc"],
    hdrs = ["sgx_age_remote_assertion_verifier.h"],
    copts = ASYLO_DEFAULT_COPTS,
    visibility = ["//visibility:public"],
    deps = [
        ":sgx_age_remote_assertion_authority_config_cc_proto",
        "//asylo/crypto:certificate_cc_proto",
        "//asylo/crypto:certificate_interface",
        "//asylo/crypto:certificate_util",
        "//asylo/crypto:x509_certificate",
        "//asylo/identity:identity_acl_cc_proto",
        "//asylo/identity:identity_cc_proto",
        "//asylo/identity/attestation:enclave_assertion_verifier",
        "//asylo/identity/attestation/sgx/internal:attestation_key_certificate_impl",
        "//asylo/identity/attestation/sgx/internal:certificate_util",
        "//asylo/identity/attestation/sgx/internal:remote_assertion_cc_proto",
        "//asylo/identity/attestation/sgx/internal:remote_assertion_util",
        "//asylo/identity/platform/sgx:sgx_identity_util",
        "//asylo/identity/platform/sgx/internal:code_identity_constants",
        "//asylo/util:cleanup",
        "//asylo/util:mutex_guarded",
        "//asylo/util:status",
        "@com_google_absl//absl/memory",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/strings",
    ],
    alwayslink = 1,
)

cc_test_and_cc_enclave_test(
    name = "sgx_age_remote_assertion_verifier_test",
    srcs = ["sgx_age_remote_assertion_verifier_test.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":sgx_age_remote_assertion_authority_config_cc_proto",
        ":sgx_age_remote_assertion_verifier",
        "//asylo/crypto:certificate_cc_proto",
        "//asylo/crypto:ecdsa_p256_sha256_signing_key",
        "//asylo/identity:descriptions",
        "//asylo/identity:identity_cc_proto",
        "//asylo/identity/attestation/sgx/internal:remote_assertion_cc_proto",
        "//asylo/identity/attestation/sgx/internal:remote_assertion_util",
        "//asylo/identity/attestation/sgx/internal/intel_certs:intel_sgx_root_ca_cert",
        "//asylo/identity/platform/sgx:machine_configuration_cc_proto",
        "//asylo/identity/platform/sgx:sgx_identity_cc_proto",
        "//asylo/identity/platform/sgx:sgx_identity_util",
        "//asylo/identity/platform/sgx/internal:code_identity_constants",
        "//asylo/identity/provisioning/sgx/internal:fake_sgx_pki",
        "//asylo/test/util:proto_matchers",
        "//asylo/test/util:status_matchers",
        "//asylo/test/util:test_main",
        "//asylo/util:proto_parse_util",
        "//asylo/util:status_macros",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/strings",
        "@com_google_googletest//:gtest",
    ],
)

cc_library(
    name = "sgx_intel_ecdsa_qe_remote_assertion_generator",
    srcs = ["sgx_intel_ecdsa_qe_remote_assertion_generator.cc"],
    hdrs = ["sgx_intel_ecdsa_qe_remote_assertion_generator.h"],
    copts = ASYLO_DEFAULT_COPTS,
    tags = sgx.tags(),
    visibility = ["//visibility:public"],
    deps = [
        ":sgx_intel_ecdsa_qe_remote_assertion_authority_config_cc_proto",
        "//asylo/crypto:certificate_cc_proto",
        "//asylo/crypto:certificate_interface",
        "//asylo/crypto:certificate_util",
        "//asylo/crypto:sha256_hash",
        "//asylo/crypto:x509_certificate",
        "//asylo/identity:additional_authenticated_data_generator",
        "//asylo/identity:identity_cc_proto",
        "//asylo/identity/attestation:enclave_assertion_generator",
        "//asylo/identity/attestation/sgx/internal:dcap_intel_architectural_enclave_interface",
        "//asylo/identity/attestation/sgx/internal:dcap_library_interface",
        "//asylo/identity/attestation/sgx/internal:enclave_dcap_library_interface",
        "//asylo/identity/attestation/sgx/internal:intel_architectural_enclave_interface",
        "//asylo/identity/attestation/sgx/internal:intel_ecdsa_quote",
        "//asylo/identity/platform/sgx/internal:code_identity_constants",
        "//asylo/identity/platform/sgx/internal:hardware_interface",
        "//asylo/identity/platform/sgx/internal:hardware_types",
        "//asylo/util:error_codes",
        "//asylo/util:mutex_guarded",
        "//asylo/util:status",
        "@com_google_absl//absl/memory",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/strings:str_format",
        "@com_google_absl//absl/synchronization",
        "@com_google_absl//absl/types:variant",
        "@sgx_dcap//:quote_constants",
    ],
)

cc_enclave_test(
    name = "sgx_intel_ecdsa_qe_remote_assertion_generator_test",
    srcs = ["sgx_intel_ecdsa_qe_remote_assertion_generator_test.cc"],
    backends = sgx.backend_labels,
    copts = ASYLO_DEFAULT_COPTS,
    tags = sgx.tags(),
    deps = [
        ":sgx_intel_ecdsa_qe_remote_assertion_generator",
        "//asylo/crypto/util:byte_container_util",
        "//asylo/crypto/util:byte_container_view",
        "//asylo/crypto/util:bytes",
        "//asylo/crypto/util:trivial_object_util",
        "//asylo/identity:additional_authenticated_data_generator",
        "//asylo/identity:enclave_assertion_authority_configs",
        "//asylo/identity:identity_cc_proto",
        "//asylo/identity/attestation/sgx/internal:intel_ecdsa_quote",
        "//asylo/identity/attestation/sgx/internal:mock_intel_architectural_enclave_interface",
        "//asylo/identity/platform/sgx/internal:code_identity_constants",
        "//asylo/identity/platform/sgx/internal:mock_hardware_interface",
        "//asylo/identity/provisioning/sgx/internal:fake_sgx_pki",
        "//asylo/test/util:memory_matchers",
        "//asylo/test/util:proto_matchers",
        "//asylo/test/util:status_matchers",
        "//asylo/util:mutex_guarded",
        "//asylo/util:proto_parse_util",
        "//asylo/util:status",
        "//asylo/util:thread",
        "@com_google_absl//absl/memory",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/strings:str_format",
        "@com_google_absl//absl/synchronization",
        "@com_google_googletest//:gtest",
        "@sgx_dcap//:quote_constants",
    ],
)

enclave_test(
    name = "sgx_intel_ecdsa_qe_remote_assertion_e2e_test",
    srcs = ["sgx_intel_ecdsa_qe_remote_assertion_e2e_test.cc"],
    backends = sgx.backend_labels,
    copts = ASYLO_DEFAULT_COPTS,
    enclaves = {
        "sgx_remote_assertion_generator_test_enclave": ":sgx_remote_assertion_generator_test_enclave.so",
    },
    tags = [
        "noregression",
        # To manually run this test, first copy the libsgx_pce.signed.so and
        # libsgx_qe3.signed.so binaries to the output directory where
        # the host driver is, then run it. The prebuilt binaries may be
        # downloaded using the script from Intel's DCAP library github repo:
        # https://github.com/intel/SGXDataCenterAttestationPrimitives/blob/master/QuoteGeneration/download_prebuilt.sh
        "manual",
    ],
    test_args = [
        "--generator_test_enclave_path='{sgx_remote_assertion_generator_test_enclave}'",
    ],
    deps = [
        ":sgx_intel_ecdsa_qe_remote_assertion_authority_config_cc_proto",
        ":sgx_intel_ecdsa_qe_remote_assertion_verifier",
        ":sgx_remote_assertion_generator_test_enclave_cc_proto",
        ":sgx_remote_assertion_generator_test_enclave_wrapper",
        "//asylo/crypto:certificate_cc_proto",
        "//asylo/identity:descriptions",
        "//asylo/identity:enclave_assertion_authority_config_cc_proto",
        "//asylo/identity:enclave_assertion_authority_configs",
        "//asylo/identity:identity_cc_proto",
        "//asylo/identity/attestation/sgx/internal:dcap_intel_architectural_enclave_path_setter",
        "//asylo/identity/attestation/sgx/internal:host_dcap_library_interface",
        "//asylo/identity/attestation/sgx/internal/intel_certs:qe_identity",
        "//asylo/platform/core:untrusted_core",
        "//asylo/test/util:proto_matchers",
        "//asylo/test/util:status_matchers",
        "//asylo/test/util:test_main",
        "//asylo/util:proto_parse_util",
        "//asylo/util:status",
        "@com_google_absl//absl/flags:flag",
        "@com_google_absl//absl/status",
        "@com_google_googletest//:gtest",
        "@com_google_protobuf//:protobuf",
    ],
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
        ":sgx_local_assertion_authority_config_cc_proto",
        "//asylo/crypto/util:bytes",
        "//asylo/crypto/util:trivial_object_util",
        "//asylo/identity:additional_authenticated_data_generator",
        "//asylo/identity/attestation:enclave_assertion_generator",
        "//asylo/identity/attestation/sgx/internal:local_assertion_cc_proto",
        "//asylo/identity/platform/sgx/internal:code_identity_constants",
        "//asylo/identity/platform/sgx/internal:hardware_interface",
        "//asylo/identity/platform/sgx/internal:hardware_types",
        "//asylo/util:mutex_guarded",
        "//asylo/util:status",
        "@com_google_absl//absl/status",
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
        ":sgx_local_assertion_authority_config_cc_proto",
        ":sgx_local_assertion_generator",
        "//asylo/crypto:sha256_hash",
        "//asylo/crypto/util:bytes",
        "//asylo/crypto/util:trivial_object_util",
        "//asylo/identity:additional_authenticated_data_generator",
        "//asylo/identity:enclave_assertion_authority",
        "//asylo/identity:identity_cc_proto",
        "//asylo/identity/attestation:enclave_assertion_generator",
        "//asylo/identity/attestation/sgx/internal:local_assertion_cc_proto",
        "//asylo/identity/platform/sgx:sgx_identity_cc_proto",
        "//asylo/identity/platform/sgx/internal:code_identity_constants",
        "//asylo/identity/platform/sgx/internal:hardware_types",
        "//asylo/identity/platform/sgx/internal:sgx_identity_util_internal",
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
        ":sgx_local_assertion_authority_config_cc_proto",
        "//asylo/crypto/util:bytes",
        "//asylo/crypto/util:trivial_object_util",
        "//asylo/identity:additional_authenticated_data_generator",
        "//asylo/identity:descriptions",
        "//asylo/identity/attestation:enclave_assertion_verifier",
        "//asylo/identity/attestation/sgx/internal:local_assertion_cc_proto",
        "//asylo/identity/platform/sgx/internal:code_identity_constants",
        "//asylo/identity/platform/sgx/internal:hardware_types",
        "//asylo/identity/platform/sgx/internal:sgx_identity_util_internal",
        "//asylo/util:status",
        "@com_google_absl//absl/status",
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
        ":sgx_local_assertion_authority_config_cc_proto",
        ":sgx_local_assertion_verifier",
        "//asylo/crypto/util:trivial_object_util",
        "//asylo/identity:additional_authenticated_data_generator",
        "//asylo/identity:enclave_assertion_authority",
        "//asylo/identity:identity_cc_proto",
        "//asylo/identity/attestation:enclave_assertion_verifier",
        "//asylo/identity/attestation/sgx/internal:local_assertion_cc_proto",
        "//asylo/identity/platform/sgx:sgx_identity_cc_proto",
        "//asylo/identity/platform/sgx/internal:code_identity_constants",
        "//asylo/identity/platform/sgx/internal:hardware_interface",
        "//asylo/identity/platform/sgx/internal:hardware_types",
        "//asylo/identity/platform/sgx/internal:proto_format",
        "//asylo/identity/platform/sgx/internal:sgx_identity_util_internal",
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
        ":sgx_local_assertion_generator",
        ":sgx_local_assertion_verifier",
        "//asylo/identity:additional_authenticated_data_generator",
        "//asylo/identity:identity_cc_proto",
        "//asylo/identity/attestation:enclave_assertion_generator",
        "//asylo/identity/attestation:enclave_assertion_verifier",
        "//asylo/identity/attestation/sgx/internal:local_assertion_cc_proto",
        "//asylo/identity/platform/sgx:sgx_identity_cc_proto",
        "//asylo/identity/platform/sgx:sgx_identity_util",
        "//asylo/identity/platform/sgx/internal:fake_enclave",
        "//asylo/identity/platform/sgx/internal:proto_format",
        "//asylo/identity/platform/sgx/internal:sgx_identity_util_internal",
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

transitions.cc_binary(
    name = "age_main",
    testonly = 1,
    srcs = ["age_main.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    linkstatic = 1,
    deps = [
        "//asylo:enclave_cc_proto",
        "//asylo:enclave_client",
        "//asylo/crypto:certificate_cc_proto",
        "//asylo/crypto:keys_cc_proto",
        "//asylo/crypto:rsa_oaep_encryption_key",
        "//asylo/identity:enclave_assertion_authority_config_cc_proto",
        "//asylo/identity:enclave_assertion_authority_configs",
        "//asylo/identity/attestation/sgx/internal:dcap_intel_architectural_enclave_interface",
        "//asylo/identity/attestation/sgx/internal:fake_pce",
        "//asylo/identity/attestation/sgx/internal:host_dcap_library_interface",
        "//asylo/identity/attestation/sgx/internal:intel_architectural_enclave_interface",
        "//asylo/identity/attestation/sgx/internal:sgx_infrastructural_enclave_manager",
        "//asylo/identity/platform/sgx/internal:ppid_ek",
        "//asylo/identity/provisioning/sgx/internal:fake_sgx_pki",
        "//asylo/identity/provisioning/sgx/internal:pck_certificate_util",
        "//asylo/identity/provisioning/sgx/internal:platform_provisioning",
        "//asylo/identity/provisioning/sgx/internal:platform_provisioning_cc_proto",
        "//asylo/platform/primitives/sgx:loader_cc_proto",
        "//asylo/util:cleansing_types",
        "//asylo/util:proto_flag",
        "//asylo/util:proto_parse_util",
        "//asylo/util:status",
        "@com_google_absl//absl/flags:flag",
        "@com_google_absl//absl/flags:parse",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/time",
        "@com_google_protobuf//:protobuf",
    ],
)

sgx_enclave_test(
    name = "age_main_test",
    srcs = ["age_main_test.cc"],
    backend_dependent_data = [":age_main"],
    copts = ASYLO_DEFAULT_COPTS,
    enclaves = {
        "age": "//asylo/identity/attestation/sgx/internal:remote_assertion_generator_enclave_no_flc.so",
    },
    test_args = [
        "--age_path='{age}'",
        "--loader_path=$(rootpath :age_main)",
    ],
    deps = [
        "//asylo/test/util:exec_tester",
        "//asylo/test/util:status_matchers",
        "//asylo/test/util:test_main",
        "@com_google_absl//absl/flags:flag",
        "@com_google_absl//absl/flags:parse",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/time",
        "@com_google_googletest//:gtest",
    ],
)

cc_library(
    name = "sgx_intel_ecdsa_qe_remote_assertion_verifier",
    srcs = ["sgx_intel_ecdsa_qe_remote_assertion_verifier.cc"],
    hdrs = ["sgx_intel_ecdsa_qe_remote_assertion_verifier.h"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":sgx_intel_ecdsa_qe_remote_assertion_authority_config_cc_proto",
        "//asylo/crypto:algorithms_cc_proto",
        "//asylo/crypto:certificate_cc_proto",
        "//asylo/crypto:certificate_interface",
        "//asylo/crypto:certificate_util",
        "//asylo/crypto:ecdsa_p256_sha256_signing_key",
        "//asylo/crypto:keys_cc_proto",
        "//asylo/crypto:sha256_hash",
        "//asylo/crypto:sha256_hash_cc_proto",
        "//asylo/crypto:x509_certificate",
        "//asylo/crypto/util:byte_container_util",
        "//asylo/crypto/util:bytes",
        "//asylo/crypto/util:trivial_object_util",
        "//asylo/identity:additional_authenticated_data_generator",
        "//asylo/identity:descriptions",
        "//asylo/identity:enclave_assertion_authority",
        "//asylo/identity:enclave_assertion_authority_config_verifiers",
        "//asylo/identity:identity_acl_cc_proto",
        "//asylo/identity:identity_acl_evaluator",
        "//asylo/identity:identity_cc_proto",
        "//asylo/identity/attestation:enclave_assertion_verifier",
        "//asylo/identity/attestation/sgx/internal:intel_ecdsa_quote",
        "//asylo/identity/attestation/sgx/internal:pce_util",
        "//asylo/identity/platform/sgx:code_identity_cc_proto",
        "//asylo/identity/platform/sgx:machine_configuration_cc_proto",
        "//asylo/identity/platform/sgx:sgx_identity_cc_proto",
        "//asylo/identity/platform/sgx:sgx_identity_expectation_matcher",
        "//asylo/identity/platform/sgx:sgx_identity_util",
        "//asylo/identity/platform/sgx/internal:code_identity_constants",
        "//asylo/identity/platform/sgx/internal:hardware_types",
        "//asylo/identity/platform/sgx/internal:sgx_identity_util_internal",
        "//asylo/identity/provisioning/sgx/internal:pck_certificate_util",
        "//asylo/platform/common:static_map",
        "//asylo/util:error_codes",
        "//asylo/util:mutex_guarded",
        "//asylo/util:status",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/strings:str_format",
        "@sgx_dcap//:quote_constants",
        "@sgx_dcap//:quote_wrapper_common",
    ],
)

cc_test_and_cc_enclave_test(
    name = "sgx_intel_ecdsa_qe_remote_assertion_verifier_test",
    srcs = ["sgx_intel_ecdsa_qe_remote_assertion_verifier_test.cc"],
    backends = sgx.backend_labels,
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":sgx_intel_ecdsa_qe_remote_assertion_authority_config_cc_proto",
        ":sgx_intel_ecdsa_qe_remote_assertion_verifier",
        "//asylo/crypto:certificate_cc_proto",
        "//asylo/crypto:ecdsa_p256_sha256_signing_key",
        "//asylo/crypto:keys_cc_proto",
        "//asylo/crypto:sha256_hash",
        "//asylo/crypto:sha256_hash_cc_proto",
        "//asylo/crypto/util:byte_container_util",
        "//asylo/crypto/util:byte_container_view",
        "//asylo/crypto/util:bytes",
        "//asylo/crypto/util:trivial_object_util",
        "//asylo/identity:additional_authenticated_data_generator",
        "//asylo/identity:enclave_assertion_authority",
        "//asylo/identity:identity_cc_proto",
        "//asylo/identity/attestation:enclave_assertion_verifier",
        "//asylo/identity/attestation/sgx/internal:fake_pce",
        "//asylo/identity/attestation/sgx/internal:intel_ecdsa_quote",
        "//asylo/identity/platform/sgx:code_identity_cc_proto",
        "//asylo/identity/platform/sgx:machine_configuration_cc_proto",
        "//asylo/identity/platform/sgx:sgx_identity_util",
        "//asylo/identity/platform/sgx/internal:code_identity_constants",
        "//asylo/identity/platform/sgx/internal:hardware_types",
        "//asylo/identity/platform/sgx/internal:sgx_identity_util_internal",
        "//asylo/identity/provisioning/sgx/internal:fake_sgx_pki",
        "//asylo/platform/common:static_map",
        "//asylo/test/util:memory_matchers",
        "//asylo/test/util:proto_matchers",
        "//asylo/test/util:status_matchers",
        "//asylo/test/util:test_main",
        "//asylo/util:error_codes",
        "//asylo/util:proto_parse_util",
        "//asylo/util:status",
        "@com_google_absl//absl/status",
        "@com_google_googletest//:gtest",
        "@sgx_dcap//:quote_constants",
    ],
)

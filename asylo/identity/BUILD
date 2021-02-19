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

load("@rules_cc//cc:defs.bzl", "cc_library", "cc_proto_library", "cc_test")
load("@rules_proto//proto:defs.bzl", "proto_library")
load("//asylo/bazel:copts.bzl", "ASYLO_DEFAULT_COPTS")

licenses(["notice"])  # Apache v2.0

# This package defines libraries used in enclave auth{N,Z}.

proto_library(
    name = "identity_proto",
    srcs = ["identity.proto"],
    visibility = ["//visibility:public"],
)

cc_proto_library(
    name = "identity_cc_proto",
    visibility = ["//visibility:public"],
    deps = ["identity_proto"],
)

proto_library(
    name = "identity_acl_proto",
    srcs = ["identity_acl.proto"],
    visibility = ["//visibility:public"],
    deps = [":identity_proto"],
)

cc_proto_library(
    name = "identity_acl_cc_proto",
    visibility = ["//visibility:public"],
    deps = [":identity_acl_proto"],
)

proto_library(
    name = "enclave_assertion_authority_config_proto",
    srcs = ["enclave_assertion_authority_config.proto"],
    visibility = ["//visibility:public"],
    deps = [":identity_proto"],
)

cc_proto_library(
    name = "enclave_assertion_authority_config_cc_proto",
    visibility = ["//visibility:public"],
    deps = ["enclave_assertion_authority_config_proto"],
)

cc_library(
    name = "init",
    srcs = [
        "init.cc",
        "init_internal.h",
    ],
    hdrs = ["init.h"],
    copts = ASYLO_DEFAULT_COPTS,
    visibility = ["//visibility:public"],
    deps = [
        ":enclave_assertion_authority",
        ":enclave_assertion_authority_config_cc_proto",
        ":identity_cc_proto",
        "//asylo/identity/attestation:enclave_assertion_generator",
        "//asylo/identity/attestation:enclave_assertion_verifier",
        "//asylo/util:logging",
        "//asylo/util:status",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/strings",
    ],
)

cc_test(
    name = "init_test",
    srcs = ["init_test.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":enclave_assertion_authority_config_cc_proto",
        ":init",
        "//asylo/identity/attestation/null:null_assertion_generator",
        "//asylo/identity/attestation/null:null_assertion_verifier",
        "//asylo/test/util:status_matchers",
        "//asylo/test/util:test_main",
        "//asylo/util:proto_parse_util",
        "@com_google_googletest//:gtest",
        "@com_google_protobuf//:protobuf",
    ],
)

cc_library(
    name = "descriptions",
    hdrs = ["descriptions.h"],
    copts = ASYLO_DEFAULT_COPTS,
    visibility = ["//visibility:public"],
    deps = [
        ":identity_cc_proto",
        "//asylo/identity/attestation/null/internal:null_identity_constants",
        "//asylo/identity/platform/sgx/internal:code_identity_constants",
    ],
)

cc_library(
    name = "enclave_assertion_authority_configs",
    srcs = ["enclave_assertion_authority_configs.cc"],
    hdrs = ["enclave_assertion_authority_configs.h"],
    copts = ASYLO_DEFAULT_COPTS,
    visibility = ["//visibility:public"],
    deps = [
        ":descriptions",
        ":enclave_assertion_authority_config_cc_proto",
        ":enclave_assertion_authority_config_verifiers",
        ":identity_acl_cc_proto",
        ":identity_cc_proto",
        "//asylo/crypto:certificate_cc_proto",
        "//asylo/daemon/identity:attestation_domain",
        "//asylo/identity/attestation/sgx:sgx_age_remote_assertion_authority_config_cc_proto",
        "//asylo/identity/attestation/sgx:sgx_intel_ecdsa_qe_remote_assertion_authority_config_cc_proto",
        "//asylo/identity/attestation/sgx:sgx_local_assertion_authority_config_cc_proto",
        "//asylo/identity/attestation/sgx/internal/intel_certs:intel_sgx_root_ca_cert",
        "//asylo/identity/attestation/sgx/internal/intel_certs:qe_identity",
        "//asylo/identity/platform/sgx:sgx_identity_cc_proto",
        "//asylo/identity/platform/sgx:sgx_identity_util",
        "//asylo/util:proto_enum_util",
        "//asylo/util:proto_parse_util",
        "//asylo/util:status",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/strings:str_format",
        "@com_google_protobuf//:protobuf",
    ],
)

cc_test(
    name = "enclave_assertion_authority_configs_test",
    srcs = ["enclave_assertion_authority_configs_test.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":descriptions",
        ":enclave_assertion_authority_config_cc_proto",
        ":enclave_assertion_authority_configs",
        ":identity_acl_cc_proto",
        ":identity_cc_proto",
        "//asylo/crypto:certificate_cc_proto",
        "//asylo/daemon/identity:attestation_domain",
        "//asylo/identity/attestation/sgx:sgx_age_remote_assertion_authority_config_cc_proto",
        "//asylo/identity/attestation/sgx:sgx_intel_ecdsa_qe_remote_assertion_authority_config_cc_proto",
        "//asylo/identity/attestation/sgx:sgx_local_assertion_authority_config_cc_proto",
        "//asylo/identity/attestation/sgx/internal/intel_certs:intel_sgx_root_ca_cert",
        "//asylo/identity/attestation/sgx/internal/intel_certs:qe_identity",
        "//asylo/identity/platform/sgx:sgx_identity_cc_proto",
        "//asylo/identity/platform/sgx:sgx_identity_util",
        "//asylo/test/util:proto_matchers",
        "//asylo/test/util:status_matchers",
        "//asylo/test/util:test_main",
        "//asylo/util:error_codes",
        "//asylo/util:proto_enum_util",
        "//asylo/util:proto_parse_util",
        "//asylo/util:status",
        "@com_google_absl//absl/container:flat_hash_set",
        "@com_google_absl//absl/status",
        "@com_google_googletest//:gtest",
    ],
)

cc_library(
    name = "enclave_assertion_authority_config_verifiers",
    srcs = ["enclave_assertion_authority_config_verifiers.cc"],
    hdrs = ["enclave_assertion_authority_config_verifiers.h"],
    copts = ASYLO_DEFAULT_COPTS,
    visibility = ["//asylo:implementation"],
    deps = [
        ":enclave_assertion_authority_config_cc_proto",
        ":identity_acl_cc_proto",
        "//asylo/crypto:certificate_cc_proto",
        "//asylo/crypto:certificate_util",
        "//asylo/daemon/identity:attestation_domain",
        "//asylo/identity/attestation/sgx:sgx_age_remote_assertion_authority_config_cc_proto",
        "//asylo/identity/attestation/sgx:sgx_intel_ecdsa_qe_remote_assertion_authority_config_cc_proto",
        "//asylo/identity/attestation/sgx:sgx_local_assertion_authority_config_cc_proto",
        "//asylo/identity/platform/sgx:sgx_identity_cc_proto",
        "//asylo/identity/platform/sgx:sgx_identity_util",
        "//asylo/util:error_codes",
        "//asylo/util:status",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/strings:str_format",
    ],
)

cc_test(
    name = "enclave_assertion_authority_config_verifiers_test",
    srcs = ["enclave_assertion_authority_config_verifiers_test.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":enclave_assertion_authority_config_verifiers",
        "//asylo/identity/attestation/sgx:sgx_age_remote_assertion_authority_config_cc_proto",
        "//asylo/identity/attestation/sgx:sgx_intel_ecdsa_qe_remote_assertion_authority_config_cc_proto",
        "//asylo/identity/attestation/sgx:sgx_local_assertion_authority_config_cc_proto",
        "//asylo/identity/provisioning/sgx/internal:fake_sgx_pki",
        "//asylo/test/util:status_matchers",
        "//asylo/test/util:test_main",
        "//asylo/util:error_codes",
        "//asylo/util:proto_enum_util",
        "//asylo/util:proto_parse_util",
        "//asylo/util:status",
        "@com_google_absl//absl/status",
        "@com_google_googletest//:gtest",
    ],
)

cc_library(
    name = "identity_acl_evaluator",
    srcs = ["identity_acl_evaluator.cc"],
    hdrs = ["identity_acl_evaluator.h"],
    copts = ASYLO_DEFAULT_COPTS,
    visibility = ["//visibility:public"],
    deps = [
        ":identity_acl_cc_proto",
        ":identity_cc_proto",
        ":identity_expectation_matcher",
        "//asylo/util:status",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/strings:str_format",
        "@com_google_protobuf//:protobuf_lite",
    ],
)

cc_library(
    name = "identity_expectation_matcher",
    srcs = [
        "delegating_identity_expectation_matcher.cc",
        "named_identity_expectation_matcher.cc",
    ],
    hdrs = [
        "delegating_identity_expectation_matcher.h",
        "identity_expectation_matcher.h",
        "named_identity_expectation_matcher.h",
    ],
    copts = ASYLO_DEFAULT_COPTS,
    visibility = ["//visibility:public"],
    deps = [
        ":identity_cc_proto",
        "//asylo/crypto/util:byte_container_util",
        "//asylo/crypto/util:byte_container_view",
        "//asylo/platform/common:static_map",
        "//asylo/util:status",
        "@com_google_absl//absl/base:core_headers",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/strings:str_format",
        "@com_google_protobuf//:protobuf",
    ],
)

cc_test(
    name = "identity_expectation_matcher_test",
    srcs = ["identity_expectation_matcher_test.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":identity_cc_proto",
        ":identity_expectation_matcher",
        "//asylo/platform/common:static_map",
        "//asylo/test/util:status_matchers",
        "//asylo/test/util:test_main",
        "//asylo/util:status",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/strings:str_format",
        "@com_google_googletest//:gtest",
        "@com_google_protobuf//:protobuf",
    ],
)

cc_library(
    name = "additional_authenticated_data_generator",
    srcs = ["additional_authenticated_data_generator.cc"],
    hdrs = ["additional_authenticated_data_generator.h"],
    copts = ASYLO_DEFAULT_COPTS,
    visibility = ["//asylo/identity:__subpackages__"],
    deps = [
        "//asylo/crypto:sha256_hash",
        "//asylo/crypto/util:byte_container_util",
        "//asylo/crypto/util:byte_container_view",
        "//asylo/crypto/util:bytes",
        "//asylo/crypto/util:trivial_object_util",
        "//asylo/util:status",
        "//asylo/util:status_macros",
        "@com_google_absl//absl/memory",
        "@com_google_absl//absl/status",
    ],
)

cc_test(
    name = "additional_authenticated_data_generator_test",
    srcs = ["additional_authenticated_data_generator_test.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":additional_authenticated_data_generator",
        "//asylo/crypto:sha256_hash",
        "//asylo/crypto/util:bytes",
        "//asylo/test/util:status_matchers",
        "//asylo/test/util:test_main",
        "@boringssl//:crypto",
        "@com_google_absl//absl/strings",
        "@com_google_googletest//:gtest",
    ],
)

cc_library(
    name = "assertion_description_util",
    srcs = ["assertion_description_util.cc"],
    hdrs = ["assertion_description_util.h"],
    copts = ASYLO_DEFAULT_COPTS,
    visibility = ["//asylo:implementation"],
    deps = [
        ":identity_cc_proto",
        "//asylo/crypto/util:byte_container_util",
        "//asylo/crypto/util:byte_container_view",
        "//asylo/util:status",
        "@com_google_absl//absl/container:flat_hash_set",
    ],
)

cc_test(
    name = "assertion_description_util_test",
    srcs = ["assertion_description_util_test.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":assertion_description_util",
        ":identity_cc_proto",
        "//asylo/test/util:proto_matchers",
        "//asylo/test/util:test_main",
        "@com_google_googletest//:gtest",
    ],
)

cc_library(
    name = "enclave_assertion_authority",
    hdrs = ["enclave_assertion_authority.h"],
    copts = ASYLO_DEFAULT_COPTS,
    visibility = ["//visibility:public"],
    deps = [
        ":identity_cc_proto",
        "//asylo/crypto/util:byte_container_util",
        "//asylo/util:status",
    ],
)

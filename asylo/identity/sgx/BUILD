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
    name = "sgx_local_assertion_authority_config_proto",
    srcs = ["sgx_local_assertion_authority_config.proto"],
    visibility = ["//visibility:public"],
)

cc_proto_library(
    name = "sgx_local_assertion_authority_config_cc_proto",
    visibility = ["//visibility:public"],
    deps = ["sgx_local_assertion_authority_config_proto"],
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
        "//asylo/crypto:sha256_hash",
        "//asylo/crypto/util:bytes",
        "//asylo/crypto/util:trivial_object_util",
        "//asylo/identity/attestation:enclave_assertion_generator",
        "//asylo/identity/attestation/sgx/internal:local_assertion_cc_proto",
        "//asylo/identity/platform/sgx/internal:code_identity_constants",
        "//asylo/identity/platform/sgx/internal:hardware_interface",
        "//asylo/identity/platform/sgx/internal:hardware_types",
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
        ":sgx_local_assertion_authority_config_cc_proto",
        ":sgx_local_assertion_generator",
        "//asylo/crypto:sha256_hash",
        "//asylo/crypto/util:bytes",
        "//asylo/crypto/util:trivial_object_util",
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
        "//asylo/crypto:sha256_hash",
        "//asylo/crypto/util:bytes",
        "//asylo/crypto/util:trivial_object_util",
        "//asylo/identity:descriptions",
        "//asylo/identity/attestation:enclave_assertion_verifier",
        "//asylo/identity/attestation/sgx/internal:local_assertion_cc_proto",
        "//asylo/identity/platform/sgx/internal:code_identity_constants",
        "//asylo/identity/platform/sgx/internal:hardware_types",
        "//asylo/identity/platform/sgx/internal:sgx_identity_util_internal",
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
        ":sgx_local_assertion_authority_config_cc_proto",
        ":sgx_local_assertion_verifier",
        "//asylo/crypto:sha256_hash",
        "//asylo/crypto/util:trivial_object_util",
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
        ":sgx_identity_util",
        ":sgx_local_assertion_generator",
        ":sgx_local_assertion_verifier",
        "//asylo/identity:identity_cc_proto",
        "//asylo/identity/attestation:enclave_assertion_generator",
        "//asylo/identity/attestation:enclave_assertion_verifier",
        "//asylo/identity/attestation/sgx/internal:local_assertion_cc_proto",
        "//asylo/identity/platform/sgx:sgx_identity_cc_proto",
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

cc_library(
    name = "sgx_identity_util",
    srcs = ["sgx_identity_util.cc"],
    hdrs = ["sgx_identity_util.h"],
    copts = ASYLO_DEFAULT_COPTS,
    visibility = ["//visibility:public"],
    deps = [
        "//asylo/identity:identity_cc_proto",
        "//asylo/identity/platform/sgx:sgx_identity_cc_proto",
        "//asylo/identity/platform/sgx/internal:sgx_identity_util_internal",
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
        ":sgx_identity_util",
        "//asylo/identity:identity_cc_proto",
        "//asylo/identity/platform/sgx:sgx_identity_cc_proto",
        "//asylo/identity/platform/sgx/internal:fake_enclave",
        "//asylo/identity/platform/sgx/internal:proto_format",
        "//asylo/identity/platform/sgx/internal:sgx_identity_test_util",
        "//asylo/test/util:proto_matchers",
        "//asylo/test/util:status_matchers",
        "//asylo/test/util:test_main",
        "@com_google_googletest//:gtest",
    ],
)

cc_library(
    name = "sgx_identity_expectation_matcher",
    srcs = ["sgx_identity_expectation_matcher.cc"],
    hdrs = ["sgx_identity_expectation_matcher.h"],
    copts = ASYLO_DEFAULT_COPTS,
    visibility = ["//visibility:public"],
    deps = [
        "//asylo/identity:descriptions",
        "//asylo/identity:identity_cc_proto",
        "//asylo/identity:identity_expectation_matcher",
        "//asylo/identity/platform/sgx:sgx_identity_cc_proto",
        "//asylo/identity/platform/sgx/internal:sgx_identity_util_internal",
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
        ":sgx_identity_expectation_matcher",
        "//asylo/identity:descriptions",
        "//asylo/identity:identity_cc_proto",
        "//asylo/identity:identity_expectation_matcher",
        "//asylo/identity/platform/sgx:code_identity_cc_proto",
        "//asylo/identity/platform/sgx:machine_configuration_cc_proto",
        "//asylo/identity/platform/sgx:sgx_identity_cc_proto",
        "//asylo/identity/platform/sgx/internal:code_identity_constants",
        "//asylo/identity/platform/sgx/internal:proto_format",
        "//asylo/identity/platform/sgx/internal:sgx_identity_test_util",
        "//asylo/identity/platform/sgx/internal:sgx_identity_util_internal",
        "//asylo/test/util:status_matchers",
        "//asylo/test/util:test_main",
        "//asylo/util:status",
        "@com_google_googletest//:gtest",
    ],
)

cc_library(
    name = "pck_certificate_util",
    srcs = ["pck_certificate_util.cc"],
    hdrs = ["pck_certificate_util.h"],
    copts = ASYLO_DEFAULT_COPTS,
    visibility = ["//asylo:implementation"],
    deps = [
        ":pck_certificates_cc_proto",
        "//asylo/crypto:asn1",
        "//asylo/crypto:asn1_schema",
        "//asylo/crypto:certificate_cc_proto",
        "//asylo/crypto:certificate_interface",
        "//asylo/crypto:certificate_util",
        "//asylo/crypto:x509_certificate",
        "//asylo/crypto/util:byte_container_view",
        "//asylo/identity/platform/sgx:machine_configuration_cc_proto",
        "//asylo/identity/platform/sgx/internal:hardware_types",
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
        "@com_google_absl//absl/types:span",
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
        "//asylo/crypto:certificate_interface",
        "//asylo/crypto:certificate_util",
        "//asylo/crypto:x509_certificate",
        "//asylo/identity/attestation/sgx/internal:attestation_key_certificate_impl",
        "//asylo/identity/provisioning/sgx/internal:fake_sgx_pki",
        "//asylo/identity/provisioning/sgx/internal:platform_provisioning",
        "//asylo/identity/provisioning/sgx/internal:platform_provisioning_cc_proto",
        "//asylo/identity/provisioning/sgx/internal:tcb",
        "//asylo/identity/provisioning/sgx/internal:tcb_cc_proto",
        "//asylo/test/util:proto_matchers",
        "//asylo/test/util:status_matchers",
        "//asylo/test/util:test_main",
        "//asylo/util:logging",
        "//asylo/util:proto_enum_util",
        "//asylo/util:proto_parse_util",
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
    name = "pck_certs_from_json",
    srcs = ["pck_certs_from_json.cc"],
    hdrs = ["pck_certs_from_json.h"],
    copts = ASYLO_DEFAULT_COPTS,
    visibility = ["//asylo:implementation"],
    deps = [
        ":pck_certificates_cc_proto",
        "//asylo/crypto:certificate_cc_proto",
        "//asylo/crypto:certificate_util",
        "//asylo/identity/platform/sgx:machine_configuration_cc_proto",
        "//asylo/identity/platform/sgx/internal:hardware_types",
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

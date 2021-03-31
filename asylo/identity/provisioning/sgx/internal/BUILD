load("@linux_sgx//:sgx_sdk.bzl", "sgx")
load("@rules_cc//cc:defs.bzl", "cc_library", "cc_proto_library", "cc_test")
load("@rules_proto//proto:defs.bzl", "proto_library")

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
load(
    "//asylo/bazel:asylo.bzl",
    "cc_test_and_cc_enclave_test",
    "enclave_loader",
    "enclave_test",
)
load("//asylo/bazel:copts.bzl", "ASYLO_DEFAULT_COPTS")

# This package defines Asylo-internal targets for SGX provisioning.

licenses(["notice"])

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
    name = "platform_provisioning_proto",
    srcs = ["platform_provisioning.proto"],
    visibility = ["//asylo:implementation"],
)

cc_proto_library(
    name = "platform_provisioning_cc_proto",
    visibility = ["//asylo:implementation"],
    deps = [":platform_provisioning_proto"],
)

proto_library(
    name = "sgx_pcs_client_proto",
    srcs = ["sgx_pcs_client.proto"],
    visibility = ["//asylo:implementation"],
)

cc_proto_library(
    name = "sgx_pcs_client_cc_proto",
    visibility = ["//asylo:implementation"],
    deps = [":sgx_pcs_client_proto"],
)

proto_library(
    name = "tcb_proto",
    srcs = ["tcb.proto"],
    visibility = ["//asylo:implementation"],
    deps = [
        ":platform_provisioning_proto",
        "//asylo/identity/platform/sgx:machine_configuration_proto",
        "@com_google_protobuf//:timestamp_proto",
    ],
)

cc_proto_library(
    name = "tcb_cc_proto",
    visibility = ["//asylo:implementation"],
    deps = [":tcb_proto"],
)

cc_library(
    name = "container_util",
    hdrs = ["container_util.h"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":platform_provisioning_cc_proto",
        ":tcb_cc_proto",
        "//asylo/identity/platform/sgx:machine_configuration_cc_proto",
        "//asylo/util:logging",
        "@com_google_protobuf//:protobuf",
        "@com_google_protobuf//:protobuf_lite",
    ],
)

cc_test_and_cc_enclave_test(
    name = "container_util_test",
    srcs = ["container_util_test.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":container_util",
        ":platform_provisioning",
        ":platform_provisioning_cc_proto",
        ":tcb",
        ":tcb_cc_proto",
        "//asylo/identity/platform/sgx:machine_configuration_cc_proto",
        "//asylo/identity/platform/sgx/internal:hardware_types",
        "//asylo/test/util:test_main",
        "@com_google_absl//absl/hash:hash_testing",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/types:optional",
        "@com_google_googletest//:gtest",
    ],
)

cc_library(
    name = "fake_sgx_pcs_client",
    testonly = 1,
    srcs = ["fake_sgx_pcs_client.cc"],
    hdrs = ["fake_sgx_pcs_client.h"],
    copts = ASYLO_DEFAULT_COPTS,
    visibility = ["//asylo:implementation"],
    deps = [
        ":container_util",
        ":fake_sgx_pki",
        ":pck_certificate_util",
        ":pck_certificates_cc_proto",
        ":platform_provisioning",
        ":platform_provisioning_cc_proto",
        ":sgx_pcs_client",
        ":sgx_pcs_client_cc_proto",
        ":tcb",
        ":tcb_cc_proto",
        "//asylo/crypto:asn1",
        "//asylo/crypto:bignum_util",
        "//asylo/crypto:certificate_cc_proto",
        "//asylo/crypto:certificate_interface",
        "//asylo/crypto:ecdsa_p256_sha256_signing_key",
        "//asylo/crypto:signing_key",
        "//asylo/crypto:x509_certificate",
        "//asylo/crypto/util:bytes",
        "//asylo/crypto/util:trivial_object_util",
        "//asylo/identity/platform/sgx:machine_configuration_cc_proto",
        "//asylo/identity/platform/sgx/internal:hardware_types",
        "//asylo/util:cleansing_types",
        "//asylo/util:logging",
        "//asylo/util:mutex_guarded",
        "//asylo/util:proto_enum_util",
        "//asylo/util:status",
        "//asylo/util:status_helpers",
        "//asylo/util:time_conversions",
        "@com_google_absl//absl/base:core_headers",
        "@com_google_absl//absl/container:flat_hash_map",
        "@com_google_absl//absl/container:flat_hash_set",
        "@com_google_absl//absl/hash",
        "@com_google_absl//absl/random",
        "@com_google_absl//absl/random:distributions",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/strings:str_format",
        "@com_google_absl//absl/time",
        "@com_google_absl//absl/types:optional",
        "@com_google_absl//absl/types:span",
        "@com_google_protobuf//:protobuf",
    ],
)

cc_test(
    name = "fake_sgx_pcs_client_test",
    srcs = ["fake_sgx_pcs_client_test.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":fake_sgx_pcs_client",
        ":fake_sgx_pki",
        ":pck_certificate_util",
        ":pck_certificates_cc_proto",
        ":platform_provisioning_cc_proto",
        ":sgx_pcs_client",
        ":sgx_pcs_client_cc_proto",
        ":tcb",
        ":tcb_cc_proto",
        ":tcb_info_from_json",
        ":tcb_info_reader",
        "//asylo/crypto:asn1",
        "//asylo/crypto:certificate_cc_proto",
        "//asylo/crypto:certificate_interface",
        "//asylo/crypto:certificate_util",
        "//asylo/crypto:ecdsa_p256_sha256_signing_key",
        "//asylo/crypto:signing_key",
        "//asylo/crypto:x509_certificate",
        "//asylo/identity/platform/sgx:machine_configuration_cc_proto",
        "//asylo/test/util:proto_matchers",
        "//asylo/test/util:status_matchers",
        "//asylo/test/util:test_main",
        "//asylo/util:logging",
        "//asylo/util:status",
        "//asylo/util:time_conversions",
        "@com_google_absl//absl/memory",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/strings:str_format",
        "@com_google_absl//absl/time",
        "@com_google_absl//absl/types:optional",
        "@com_google_absl//absl/types:span",
        "@com_google_googletest//:gtest",
        "@com_google_protobuf//:protobuf",
    ],
)

cc_library(
    name = "fake_sgx_pki",
    testonly = 1,
    srcs = ["fake_sgx_pki.cc"],
    hdrs = ["fake_sgx_pki.h"],
    copts = ASYLO_DEFAULT_COPTS,
    visibility = ["//asylo:implementation"],
    deps = [
        ":pck_certificate_util",
        "//asylo/crypto:certificate_cc_proto",
        "@com_google_absl//absl/strings",
    ],
)

# Tests that the fake Intel PKI is verifiable.
cc_test_and_cc_enclave_test(
    name = "fake_sgx_pki_test",
    srcs = ["fake_sgx_pki_test.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":fake_sgx_pki",
        "//asylo/crypto:certificate_cc_proto",
        "//asylo/crypto:certificate_interface",
        "//asylo/crypto:certificate_util",
        "//asylo/crypto:ecdsa_p256_sha256_signing_key",
        "//asylo/crypto:signing_key",
        "//asylo/crypto:x509_certificate",
        "//asylo/identity/platform/sgx:machine_configuration_cc_proto",
        "//asylo/test/util:proto_matchers",
        "//asylo/test/util:status_matchers",
        "//asylo/test/util:test_main",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/time",
        "@com_google_absl//absl/types:span",
        "@com_google_googletest//:gtest",
        "@com_google_protobuf//:protobuf",
    ],
)

cc_library(
    name = "mock_sgx_pcs_client",
    testonly = 1,
    hdrs = ["mock_sgx_pcs_client.h"],
    copts = ASYLO_DEFAULT_COPTS,
    visibility = ["//asylo:implementation"],
    deps = [
        ":platform_provisioning_cc_proto",
        ":sgx_pcs_client",
        "//asylo/identity/platform/sgx:machine_configuration_cc_proto",
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
        ":container_util",
        ":pck_certificates_cc_proto",
        ":platform_provisioning",
        ":platform_provisioning_cc_proto",
        ":tcb",
        ":tcb_cc_proto",
        "//asylo/crypto:asn1",
        "//asylo/crypto:asn1_schema",
        "//asylo/crypto:certificate_cc_proto",
        "//asylo/crypto:certificate_interface",
        "//asylo/crypto:certificate_util",
        "//asylo/crypto:x509_certificate",
        "//asylo/crypto/util:byte_container_view",
        "//asylo/identity/platform/sgx:machine_configuration_cc_proto",
        "//asylo/identity/platform/sgx/internal:hardware_types",
        "//asylo/util:logging",
        "//asylo/util:status",
        "//asylo/util:status_helpers",
        "@com_google_absl//absl/base",
        "@com_google_absl//absl/container:flat_hash_map",
        "@com_google_absl//absl/container:flat_hash_set",
        "@com_google_absl//absl/hash",
        "@com_google_absl//absl/status",
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
        ":fake_sgx_pki",
        ":pck_certificate_util",
        ":pck_certificates_cc_proto",
        ":platform_provisioning",
        ":platform_provisioning_cc_proto",
        ":tcb",
        ":tcb_cc_proto",
        "//asylo/crypto:asn1",
        "//asylo/crypto:certificate_cc_proto",
        "//asylo/crypto:certificate_interface",
        "//asylo/crypto:certificate_util",
        "//asylo/crypto:x509_certificate",
        "//asylo/identity/attestation/sgx/internal:attestation_key_certificate_impl",
        "//asylo/test/util:proto_matchers",
        "//asylo/test/util:status_matchers",
        "//asylo/test/util:test_main",
        "//asylo/util:logging",
        "//asylo/util:proto_enum_util",
        "//asylo/util:proto_parse_util",
        "//asylo/util:status",
        "@com_google_absl//absl/random",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/strings:str_format",
        "@com_google_googletest//:gtest",
        "@com_google_protobuf//:protobuf",
    ],
)

cc_binary(
    name = "pck_certificate_tool",
    srcs = ["pck_certificate_tool.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    features = ["fully_static_link"],
    deps = [
        ":pck_certificate_util",
        "//asylo/crypto:certificate_interface",
        "//asylo/crypto:x509_certificate",
        "//asylo/util:logging",
        "//asylo/util:proto_enum_util",
        "@com_google_absl//absl/flags:flag",
        "@com_google_absl//absl/strings",
    ],
)

cc_library(
    name = "pck_certs_from_json",
    srcs = ["pck_certs_from_json.cc"],
    hdrs = ["pck_certs_from_json.h"],
    copts = ASYLO_DEFAULT_COPTS,
    visibility = ["//asylo:implementation"],
    deps = [
        ":pck_certificates_cc_proto",
        ":platform_provisioning_cc_proto",
        ":tcb_cc_proto",
        ":tcb_info_from_json",
        "//asylo/crypto:certificate_cc_proto",
        "//asylo/crypto:certificate_util",
        "//asylo/identity/platform/sgx:machine_configuration_cc_proto",
        "//asylo/identity/platform/sgx/internal:hardware_types",
        "//asylo/util:error_codes",
        "//asylo/util:function_deleter",
        "//asylo/util:hex_util",
        "//asylo/util:proto_struct_util",
        "//asylo/util:status",
        "//asylo/util:url_util",
        "@com_google_absl//absl/memory",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/strings",
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
        "@com_google_absl//absl/status",
        "@com_google_googletest//:gtest",
        "@com_google_protobuf//:protobuf",
    ],
)

cc_library(
    name = "platform_provisioning",
    srcs = ["platform_provisioning.cc"],
    hdrs = ["platform_provisioning.h"],
    copts = ASYLO_DEFAULT_COPTS,
    visibility = ["//asylo:implementation"],
    deps = [
        ":platform_provisioning_cc_proto",
        "//asylo/crypto/util:trivial_object_util",
        "//asylo/identity/platform/sgx:machine_configuration_cc_proto",
        "//asylo/identity/platform/sgx/internal:hardware_types",
        "//asylo/util:status",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/strings",
    ],
)

cc_test_and_cc_enclave_test(
    name = "platform_provisioning_test",
    srcs = ["platform_provisioning_test.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":platform_provisioning",
        ":platform_provisioning_cc_proto",
        "//asylo/crypto/util:bytes",
        "//asylo/crypto/util:trivial_object_util",
        "//asylo/identity/platform/sgx/internal:hardware_types",
        "//asylo/test/util:proto_matchers",
        "//asylo/test/util:status_matchers",
        "//asylo/test/util:test_main",
        "//asylo/util:status",
        "@com_google_absl//absl/status",
        "@com_google_googletest//:gtest",
    ],
)

cc_library(
    name = "sgx_pcs_client",
    hdrs = ["sgx_pcs_client.h"],
    copts = ASYLO_DEFAULT_COPTS,
    visibility = ["//asylo:implementation"],
    deps = [
        ":pck_certificates_cc_proto",
        ":platform_provisioning_cc_proto",
        ":sgx_pcs_client_cc_proto",
        ":tcb_cc_proto",
        "//asylo/crypto:certificate_cc_proto",
        "//asylo/identity/platform/sgx:machine_configuration_cc_proto",
        "//asylo/util:status",
    ],
)

cc_library(
    name = "sgx_pcs_client_impl",
    srcs = ["sgx_pcs_client_impl.cc"],
    hdrs = ["sgx_pcs_client_impl.h"],
    copts = ASYLO_DEFAULT_COPTS,
    visibility = ["//asylo:implementation"],
    deps = [
        ":pck_certs_from_json",
        ":platform_provisioning",
        ":platform_provisioning_cc_proto",
        ":sgx_pcs_client",
        ":sgx_pcs_client_cc_proto",
        ":signed_tcb_info_from_json",
        ":tcb",
        "//asylo/crypto:algorithms_cc_proto",
        "//asylo/crypto:asymmetric_encryption_key",
        "//asylo/crypto:certificate_util",
        "//asylo/identity/platform/sgx:machine_configuration_cc_proto",
        "//asylo/util:function_deleter",
        "//asylo/util:hex_util",
        "//asylo/util:http_fetcher",
        "//asylo/util:logging",
        "//asylo/util:proto_enum_util",
        "//asylo/util:status",
        "//asylo/util:url_util",
        "@com_github_curl_curl//:curl",
        "@com_google_absl//absl/container:flat_hash_map",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/strings:str_format",
    ],
)

cc_test(
    name = "sgx_pcs_client_impl_test",
    srcs = ["sgx_pcs_client_impl_test.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":platform_provisioning_cc_proto",
        ":sgx_pcs_client",
        ":sgx_pcs_client_cc_proto",
        ":sgx_pcs_client_impl",
        "//asylo/crypto:algorithms_cc_proto",
        "//asylo/crypto/util:byte_container_view",
        "//asylo/identity/platform/sgx:machine_configuration_cc_proto",
        "//asylo/test/util:proto_matchers",
        "//asylo/test/util:status_matchers",
        "//asylo/test/util:test_main",
        "//asylo/util:error_codes",
        "//asylo/util:status",
        "@com_google_absl//absl/memory",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/strings",
        "@com_google_googletest//:gtest",
        "@com_google_protobuf//:protobuf",
    ],
)

cc_library(
    name = "sgx_pcs_tool_lib",
    srcs = ["sgx_pcs_tool_lib.cc"],
    hdrs = ["sgx_pcs_tool_lib.h"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":platform_provisioning",
        ":platform_provisioning_cc_proto",
        ":sgx_pcs_client",
        ":sgx_pcs_client_impl",
        "//asylo/crypto:algorithms_cc_proto",
        "//asylo/crypto:asymmetric_encryption_key",
        "//asylo/crypto:rsa_oaep_encryption_key",
        "//asylo/crypto:x509_certificate",
        "//asylo/identity/attestation/sgx/internal:dcap_intel_architectural_enclave_interface",
        "//asylo/identity/attestation/sgx/internal:host_dcap_library_interface",
        "//asylo/identity/attestation/sgx/internal:pce_util",
        "//asylo/identity/attestation/sgx/internal:report_oracle_enclave_wrapper",
        "//asylo/identity/platform/sgx:machine_configuration_cc_proto",
        "//asylo/identity/platform/sgx/internal:hardware_types",
        "//asylo/identity/platform/sgx/internal:ppid_ek",
        "//asylo/util:cleansing_types",
        "//asylo/util:http_fetcher_impl",
        "//asylo/util:logging",
        "//asylo/util:posix_errors",
        "//asylo/util:proto_parse_util",
        "//asylo/util:status",
        "@com_google_absl//absl/base",
        "@com_google_absl//absl/flags:flag",
        "@com_google_absl//absl/memory",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/strings",
        "@com_google_protobuf//:protobuf",
    ],
)

enclave_test(
    name = "sgx_pcs_tool_lib_test",
    srcs = ["sgx_pcs_tool_lib_test.cc"],
    backends = sgx.sim_backend_labels,  # Don't require FLC to run the test
    copts = ASYLO_DEFAULT_COPTS,
    embedded_enclaves = {
        "report_oracle": "//asylo/identity/attestation/sgx/internal:report_oracle_enclave.so",
    },
    deps = [
        ":platform_provisioning",
        ":sgx_pcs_client",
        ":sgx_pcs_tool_lib",
        "//asylo/identity/attestation/sgx/internal:dcap_intel_architectural_enclave_path_setter",
        "//asylo/test/util:memory_matchers",
        "//asylo/test/util:proto_matchers",
        "//asylo/test/util:status_matchers",
        "//asylo/test/util:test_main",
        "//asylo/util:posix_error_matchers",
        "//asylo/util:proto_parse_util",
        "@com_google_absl//absl/flags:flag",
        "@com_google_absl//absl/flags:reflection",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/strings",
        "@com_google_googletest//:gtest",
        "@com_google_protobuf//:protobuf",
    ],
)

enclave_loader(
    name = "sgx_pcs_tool",
    srcs = ["sgx_pcs_tool.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    embedded_enclaves = {
        "report_oracle": "//asylo/identity/attestation/sgx/internal:report_oracle_enclave.so",
    },
    features = ["fully_static_link"],
    deps = [
        ":platform_provisioning",
        ":platform_provisioning_cc_proto",
        ":sgx_pcs_client",
        ":sgx_pcs_tool_lib",
        "//asylo/identity/attestation/sgx/internal:dcap_intel_architectural_enclave_interface",
        "//asylo/identity/attestation/sgx/internal:dcap_library_interface",
        "//asylo/identity/attestation/sgx/internal:host_dcap_library_interface",
        "//asylo/identity/platform/sgx:machine_configuration_cc_proto",
        "//asylo/util:logging",
        "//asylo/util:status",
        "@com_google_absl//absl/flags:flag",
        "@com_google_absl//absl/strings",
    ],
)

cc_library(
    name = "signed_tcb_info_from_json",
    srcs = ["signed_tcb_info_from_json.cc"],
    hdrs = ["signed_tcb_info_from_json.h"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":sgx_pcs_client_cc_proto",
        "//asylo/util:error_codes",
        "//asylo/util:hex_util",
        "//asylo/util:proto_struct_util",
        "//asylo/util:status",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/strings",
        "@com_google_protobuf//:protobuf",
        "@com_googlesource_code_re2//:re2",
    ],
)

cc_test_and_cc_enclave_test(
    name = "signed_tcb_info_from_json_test",
    srcs = ["signed_tcb_info_from_json_test.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":sgx_pcs_client_cc_proto",
        ":signed_tcb_info_from_json",
        "//asylo/test/util:proto_matchers",
        "//asylo/test/util:status_matchers",
        "//asylo/test/util:test_main",
        "//asylo/util:error_codes",
        "//asylo/util:proto_enum_util",
        "//asylo/util:status",
        "@com_google_absl//absl/status",
        "@com_google_googletest//:gtest",
        "@com_google_protobuf//:protobuf",
    ],
)

cc_library(
    name = "tcb",
    srcs = ["tcb.cc"],
    hdrs = ["tcb.h"],
    copts = ASYLO_DEFAULT_COPTS,
    visibility = ["//asylo:implementation"],
    deps = [
        ":container_util",
        ":platform_provisioning",
        ":tcb_cc_proto",
        "//asylo/crypto/util:byte_container_view",
        "//asylo/identity/platform/sgx/internal:hardware_types",
        "//asylo/util:hex_util",
        "//asylo/util:proto_enum_util",
        "//asylo/util:status",
        "@com_google_absl//absl/base:core_headers",
        "@com_google_absl//absl/container:flat_hash_map",
        "@com_google_absl//absl/hash",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/strings:str_format",
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
        "//asylo/identity/platform/sgx:machine_configuration_cc_proto",
        "//asylo/test/util:proto_matchers",
        "//asylo/test/util:status_matchers",
        "//asylo/test/util:test_main",
        "//asylo/util:logging",
        "//asylo/util:status",
        "@com_google_absl//absl/base:core_headers",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/time",
        "@com_google_absl//absl/types:span",
        "@com_google_googletest//:gtest",
        "@com_google_protobuf//:protobuf",
    ],
)

cc_library(
    name = "tcb_info_from_json",
    srcs = ["tcb_info_from_json.cc"],
    hdrs = ["tcb_info_from_json.h"],
    copts = ASYLO_DEFAULT_COPTS,
    visibility = ["//asylo:implementation"],
    deps = [
        ":container_util",
        ":platform_provisioning",
        ":platform_provisioning_cc_proto",
        ":tcb",
        ":tcb_cc_proto",
        "//asylo/util:hex_util",
        "//asylo/util:logging",
        "//asylo/util:proto_struct_util",
        "//asylo/util:status",
        "@com_google_absl//absl/base",
        "@com_google_absl//absl/container:flat_hash_map",
        "@com_google_absl//absl/hash",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/strings:str_format",
        "@com_google_absl//absl/time",
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
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/time",
        "@com_google_absl//absl/types:span",
        "@com_google_googletest//:gtest",
        "@com_google_protobuf//:protobuf",
    ],
)

cc_library(
    name = "tcb_info_reader",
    srcs = ["tcb_info_reader.cc"],
    hdrs = ["tcb_info_reader.h"],
    copts = ASYLO_DEFAULT_COPTS,
    visibility = ["//asylo:implementation"],
    deps = [
        ":container_util",
        ":pck_certificate_util",
        ":pck_certificates_cc_proto",
        ":platform_provisioning",
        ":platform_provisioning_cc_proto",
        ":tcb",
        ":tcb_cc_proto",
        "//asylo/identity/platform/sgx:machine_configuration_cc_proto",
        "//asylo/util:proto_enum_util",
        "//asylo/util:status",
        "@com_google_absl//absl/container:flat_hash_set",
        "@com_google_absl//absl/hash",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/strings",
    ],
)

cc_test_and_cc_enclave_test(
    name = "tcb_info_reader_test",
    srcs = ["tcb_info_reader_test.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":platform_provisioning_cc_proto",
        ":tcb_info_reader",
        "//asylo/identity/platform/sgx:machine_configuration_cc_proto",
        "//asylo/identity/platform/sgx/internal:hardware_types",
        "//asylo/test/util:proto_matchers",
        "//asylo/test/util:status_matchers",
        "//asylo/test/util:test_main",
        "//asylo/util:status",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/types:span",
        "@com_google_googletest//:gtest",
        "@com_google_protobuf//:protobuf",
    ],
)

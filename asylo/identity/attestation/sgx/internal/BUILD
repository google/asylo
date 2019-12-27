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

# This packages contains libraries used to implement SGX local and remote
# attestation.

load("//asylo/bazel:copts.bzl", "ASYLO_DEFAULT_COPTS")
load(
    "//asylo/bazel:sgx_rules.bzl",
    "sgx_cc_unsigned_enclave",
    "sgx_debug_sign_enclave",
    "sgx_enclave_test",
)
load("@linux_sgx//:sgx_sdk.bzl", "sgx")

package(default_visibility = ["//asylo/identity/attestation/sgx:__subpackages__"])

licenses(["notice"])

# Defines an interface for interacting with Intel Architectural Enclaves.
cc_library(
    name = "intel_architectural_enclave_interface",
    hdrs = ["intel_architectural_enclave_interface.h"],
    copts = ASYLO_DEFAULT_COPTS,
    visibility = ["//asylo/identity/sgx:__pkg__"],
    deps = [
        "//asylo/crypto:algorithms_cc_proto",
        "//asylo/crypto/util:bytes",
        "//asylo/identity/sgx:hardware_types",
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
        ":dcap_library_interface",
        ":intel_architectural_enclave_interface",
        "//asylo/crypto:algorithms_cc_proto",
        "//asylo/crypto/util:bytes",
        "//asylo/identity/sgx:hardware_types",
        "//asylo/identity/sgx:pce_util",
        "//asylo/util:proto_enum_util",
        "//asylo/util:status",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/types:span",
        "@linux_sgx//:public",
        "@sgx_dcap//:quote_wrapper_common",
    ],
)

cc_library(
    name = "dcap_library_interface",
    hdrs = ["dcap_library_interface.h"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        "@linux_sgx//:public",
        "@sgx_dcap//:quote_wrapper_common",
    ],
)

cc_library(
    name = "host_dcap_library_interface",
    srcs = ["host_dcap_library_interface.cc"],
    hdrs = ["host_dcap_library_interface.h"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":dcap_library_interface",
        "@linux_sgx//:public",
        "@sgx_dcap//:quote_wrapper",
        "@sgx_dcap//:quote_wrapper_common",
    ],
)

cc_library(
    name = "enclave_dcap_library_interface",
    srcs = ["enclave_dcap_library_interface.cc"],
    hdrs = ["enclave_dcap_library_interface.h"],
    copts = ASYLO_DEFAULT_COPTS,
    tags = [
        "manual",
    ],
    deps = [
        "//asylo/identity/attestation/sgx/internal:dcap_library_interface",
        "//asylo/platform/primitives/sgx:trusted_sgx",
    ],
)

proto_library(
    name = "report_oracle_enclave_proto",
    srcs = ["report_oracle_enclave.proto"],
    deps = [
        "//asylo:enclave_proto",
        "//asylo/identity/provisioning/sgx/internal:platform_provisioning_proto",
    ],
)

cc_proto_library(
    name = "report_oracle_enclave_cc_proto",
    deps = ["report_oracle_enclave_proto"],
)

sgx_cc_unsigned_enclave(
    name = "report_oracle_enclave_unsigned.so",
    srcs = ["report_oracle_enclave.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":report_oracle_enclave_cc_proto",
        "//asylo:enclave_cc_proto",
        "//asylo:enclave_runtime",
        "//asylo/identity/provisioning/sgx/internal:platform_provisioning",
        "//asylo/identity/sgx:hardware_interface",
        "//asylo/util:status",
    ],
)

sgx.enclave_configuration(
    name = "report_oracle_enclave_config",
    provision_key = "1",
)

sgx_debug_sign_enclave(
    name = "report_oracle_enclave.so",
    config = ":report_oracle_enclave_config",
    unsigned = "report_oracle_enclave_unsigned.so",
)

sgx_enclave_test(
    name = "dcap_intel_architectural_enclave_interface_e2e_test",
    srcs = ["dcap_intel_architectural_enclave_interface_e2e_test.cc"],
    enclaves = {
        "report_oracle_enclave_path": ":report_oracle_enclave.so",
    },
    tags = ["noregression"],
    test_args = ["--report_oracle_enclave_path='{report_oracle_enclave_path}'"],
    deps = [
        ":dcap_intel_architectural_enclave_interface",
        ":host_dcap_library_interface",
        ":intel_ecdsa_quote",
        ":report_oracle_enclave_cc_proto",
        "//asylo:enclave_cc_proto",
        "//asylo:enclave_client",
        "//asylo/crypto:algorithms_cc_proto",
        "//asylo/crypto:keys_cc_proto",
        "//asylo/crypto:rsa_oaep_encryption_key",
        "//asylo/crypto/util:trivial_object_util",
        "//asylo/identity/provisioning/sgx/internal:platform_provisioning",
        "//asylo/identity/provisioning/sgx/internal:platform_provisioning_cc_proto",
        "//asylo/identity/sgx:hardware_types",
        "//asylo/identity/sgx:pce_util",
        "//asylo/platform/primitives/sgx:loader_cc_proto",
        "//asylo/test/util:memory_matchers",
        "//asylo/test/util:status_matchers",
        "//asylo/test/util:test_main",
        "//asylo/util:cleansing_types",
        "//asylo/util:status",
        "@com_google_absl//absl/flags:flag",
        "@com_google_absl//absl/memory",
        "@com_google_googletest//:gtest",
        "@sgx_dcap//:pce_constants",
        "@sgx_dcap//:quote_constants",
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
        ":dcap_library_interface",
        "//asylo/crypto:algorithms_cc_proto",
        "//asylo/crypto/util:byte_container_util",
        "//asylo/crypto/util:byte_container_view",
        "//asylo/crypto/util:bytes",
        "//asylo/crypto/util:trivial_object_util",
        "//asylo/identity/sgx:hardware_types",
        "//asylo/identity/sgx:pce_util",
        "//asylo/test/util:memory_matchers",
        "//asylo/test/util:status_matchers",
        "//asylo/test/util:test_main",
        "//asylo/util:status",
        "@com_google_absl//absl/memory",
        "@com_google_googletest//:gtest",
        "@sgx_dcap//:pce_constants",
        "@sgx_dcap//:quote_wrapper_common",
    ],
)

cc_library(
    name = "mock_intel_architectural_enclave_interface",
    testonly = 1,
    hdrs = ["mock_intel_architectural_enclave_interface.h"],
    copts = ASYLO_DEFAULT_COPTS,
    visibility = ["//asylo/identity/sgx:__pkg__"],
    deps = [
        ":intel_architectural_enclave_interface",
        "//asylo/crypto:algorithms_cc_proto",
        "//asylo/crypto/util:bytes",
        "//asylo/identity/sgx:hardware_types",
        "//asylo/util:status",
        "@com_google_absl//absl/types:span",
        "@com_google_googletest//:gtest",
    ],
)

cc_library(
    name = "intel_ecdsa_quote",
    srcs = ["intel_ecdsa_quote.cc"],
    hdrs = ["intel_ecdsa_quote.h"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        "//asylo/crypto/util:byte_container_reader",
        "//asylo/crypto/util:byte_container_view",
        "//asylo/crypto/util:bytes",
        "//asylo/identity/sgx:hardware_types",
        "//asylo/util:status",
        "@com_google_absl//absl/base:core_headers",
        "@com_google_absl//absl/strings",
        "@sgx_dcap//:quote_constants",
    ],
)

cc_test(
    name = "intel_ecdsa_quote_test",
    srcs = ["intel_ecdsa_quote_test.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":intel_ecdsa_quote",
        "//asylo/crypto/util:byte_container_util",
        "//asylo/crypto/util:trivial_object_util",
        "//asylo/test/util:memory_matchers",
        "//asylo/test/util:status_matchers",
        "//asylo/test/util:test_main",
        "@com_google_googletest//:gtest",
        "@sgx_dcap//:quote_constants",
    ],
)

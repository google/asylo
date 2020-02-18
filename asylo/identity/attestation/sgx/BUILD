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

load(
    "//asylo/bazel:asylo.bzl",
    "cc_enclave_test",
    "enclave_test",
)
load("//asylo/bazel:asylo_copy_from_host.bzl", "copy_from_host")
load("//asylo/bazel:copts.bzl", "ASYLO_DEFAULT_COPTS")
load(
    "//asylo/bazel:sgx_rules.bzl",
    "sgx_cc_unsigned_enclave",
    "sgx_debug_sign_enclave",
    "sgx_enclave_test",
)
load("@com_google_asylo_backend_provider//:transitions.bzl", "transitions")
load("@rules_proto//proto:defs.bzl", "proto_library")
load("@linux_sgx//:sgx_sdk.bzl", "sgx")
load("@rules_cc//cc:defs.bzl", "cc_proto_library")

licenses(["notice"])

proto_library(
    name = "sgx_age_remote_assertion_authority_config_proto",
    srcs = ["sgx_age_remote_assertion_authority_config.proto"],
    visibility = ["//asylo:implementation"],
    deps = ["//asylo/crypto:certificate_proto"],
)

cc_proto_library(
    name = "sgx_age_remote_assertion_authority_config_cc_proto",
    visibility = ["//asylo:implementation"],
    deps = ["sgx_age_remote_assertion_authority_config_proto"],
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
        "//asylo/crypto:certificate_util",
        "//asylo/grpc/auth:grpc++_security_enclave",
        "//asylo/grpc/auth:sgx_local_credentials_options",
        "//asylo/identity:identity_cc_proto",
        "//asylo/identity/attestation:enclave_assertion_generator",
        "//asylo/identity/attestation/sgx/internal:remote_assertion_cc_proto",
        "//asylo/identity/sgx:code_identity_constants",
        "//asylo/identity/sgx:sgx_remote_assertion_generator_client",
        "//asylo/util:mutex_guarded",
        "//asylo/util:status",
        "@com_google_absl//absl/memory",
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
        "//asylo/identity/sgx:sgx_identity_util",
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
        "//asylo/identity:descriptions",
        "//asylo/identity:enclave_assertion_authority",
        "//asylo/identity:identity_cc_proto",
        "//asylo/identity:init",
        "//asylo/identity/attestation:enclave_assertion_generator",
        "//asylo/identity/attestation/sgx/internal:fake_pce",
        "//asylo/identity/attestation/sgx/internal:remote_assertion_generator_enclave_cc_proto",
        "//asylo/identity/attestation/sgx/internal:remote_assertion_generator_enclave_test_util",
        "//asylo/identity/platform/sgx:sgx_identity_cc_proto",
        "//asylo/identity/sgx:code_identity_constants",
        "//asylo/identity/sgx:sgx_identity_util",
        "//asylo/identity/sgx:sgx_infrastructural_enclave_manager",
        "//asylo/identity/sgx:sgx_remote_assertion_generator_client",
        "//asylo/identity/sgx:sgx_remote_assertion_generator_impl",
        "//asylo/platform/primitives/sgx:loader_cc_proto",
        "//asylo/test/util:enclave_assertion_authority_configs",
        "//asylo/test/util:proto_matchers",
        "//asylo/test/util:status_matchers",
        "//asylo/test/util:test_main",
        "//asylo/util:mutex_guarded",
        "//asylo/util:status",
        "//asylo/util:thread",
        "@com_google_absl//absl/flags:flag",
        "@com_google_absl//absl/synchronization",
        "@com_google_absl//absl/types:span",
        "@com_google_googletest//:gtest",
        "@com_google_protobuf//:protobuf",
    ],
)

cc_library(
    name = "sgx_intel_ecdsa_qe_remote_assertion_generator",
    srcs = ["sgx_intel_ecdsa_qe_remote_assertion_generator.cc"],
    hdrs = ["sgx_intel_ecdsa_qe_remote_assertion_generator.h"],
    copts = ASYLO_DEFAULT_COPTS,
    tags = sgx.tags(),
    deps = [
        "//asylo/crypto:sha256_hash",
        "//asylo/identity:additional_authenticated_data_generator",
        "//asylo/identity:identity_cc_proto",
        "//asylo/identity/attestation:enclave_assertion_generator",
        "//asylo/identity/attestation/sgx/internal:dcap_intel_architectural_enclave_interface",
        "//asylo/identity/attestation/sgx/internal:dcap_library_interface",
        "//asylo/identity/attestation/sgx/internal:enclave_dcap_library_interface",
        "//asylo/identity/attestation/sgx/internal:intel_architectural_enclave_interface",
        "//asylo/identity/sgx:code_identity_constants",
        "//asylo/identity/sgx:hardware_interface",
        "//asylo/identity/sgx:hardware_types",
        "//asylo/util:error_codes",
        "//asylo/util:mutex_guarded",
        "//asylo/util:status",
        "@com_google_absl//absl/memory",
        "@com_google_absl//absl/strings:str_format",
        "@com_google_absl//absl/synchronization",
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
        "//asylo/identity:identity_cc_proto",
        "//asylo/identity/attestation/sgx/internal:mock_intel_architectural_enclave_interface",
        "//asylo/identity/sgx:code_identity_constants",
        "//asylo/identity/sgx:mock_hardware_interface",
        "//asylo/test/util:memory_matchers",
        "//asylo/test/util:proto_matchers",
        "//asylo/test/util:status_matchers",
        "//asylo/util:mutex_guarded",
        "//asylo/util:status",
        "//asylo/util:thread",
        "@com_google_absl//absl/memory",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/strings:str_format",
        "@com_google_absl//absl/synchronization",
        "@com_google_googletest//:gtest",
    ],
)

enclave_test(
    name = "sgx_intel_ecdsa_qe_remote_assertion_e2e_test",
    srcs = ["sgx_intel_ecdsa_qe_remote_assertion_e2e_test.cc"],
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
        ":sgx_remote_assertion_generator_test_enclave_cc_proto",
        ":sgx_remote_assertion_generator_test_enclave_wrapper",
        "//asylo/identity:descriptions",
        "//asylo/identity/attestation/sgx/internal:dcap_intel_architectural_enclave_path_setter",
        "//asylo/identity/attestation/sgx/internal:host_dcap_library_interface",
        "//asylo/platform/core:untrusted_core",
        "//asylo/test/util:proto_matchers",
        "//asylo/test/util:status_matchers",
        "//asylo/test/util:test_main",
        "//asylo/util:status",
        "@com_google_absl//absl/flags:flag",
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
        "//asylo/identity:enclave_assertion_authority_config_cc_proto",
        "//asylo/identity:enclave_assertion_authority_configs",
        "//asylo/identity/attestation/sgx/internal:dcap_intel_architectural_enclave_interface",
        "//asylo/identity/attestation/sgx/internal:fake_pce",
        "//asylo/identity/attestation/sgx/internal:host_dcap_library_interface",
        "//asylo/identity/attestation/sgx/internal:intel_architectural_enclave_interface",
        "//asylo/identity/attestation/sgx/internal:remote_assertion_generator_enclave_test_util",
        "//asylo/identity/sgx:sgx_infrastructural_enclave_manager",
        "//asylo/platform/primitives/sgx:loader_cc_proto",
        "//asylo/util:status",
        "@com_google_absl//absl/flags:flag",
        "@com_google_absl//absl/flags:parse",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/time",
        "@com_google_protobuf//:protobuf",
    ],
)

copy_from_host(
    output = "age_main_host_bin",
    target = "age_main",
)

sgx_enclave_test(
    name = "age_main_test",
    srcs = ["age_main_test.cc"],
    backend_dependent_data = [
        ":age_main_host_bin",
    ],
    copts = ASYLO_DEFAULT_COPTS,
    enclaves = {
        "age": "//asylo/identity/attestation/sgx/internal:remote_assertion_generator_enclave.so",
    },
    test_args = [
        "--age_path='{age}'",
        "--loader_path=$(rootpath :age_main_host_bin)",
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

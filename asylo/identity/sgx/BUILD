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

load("@rules_cc//cc:defs.bzl", "cc_library", "cc_proto_library")

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

# Used to enable gtest tests to run inside an enclave.
load("//asylo/bazel:copts.bzl", "ASYLO_DEFAULT_COPTS")

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
    deprecation = "Use //asylo/identity/attestation/sgx:sgx_local_assertion_authority_config_proto",
    visibility = ["//visibility:public"],
    exports = ["//asylo/identity/attestation/sgx:sgx_local_assertion_authority_config_proto"],
    deps = ["//asylo/identity/attestation/sgx:sgx_local_assertion_authority_config_proto"],
)

cc_proto_library(
    name = "sgx_local_assertion_authority_config_cc_proto",
    deprecation = "Use //asylo/identity/attestation/sgx:sgx_local_assertion_authority_config_cc_proto",
    visibility = ["//visibility:public"],
    deps = ["sgx_local_assertion_authority_config_proto"],
)

cc_library(
    name = "sgx_local_assertion_generator",
    copts = ASYLO_DEFAULT_COPTS,
    deprecation = "Use //asylo/identity/attestation/sgx:sgx_local_assertion_generator",
    visibility = ["//visibility:public"],
    deps = ["//asylo/identity/attestation/sgx:sgx_local_assertion_generator"],
    alwayslink = 1,
)

cc_library(
    name = "sgx_local_assertion_verifier",
    copts = ASYLO_DEFAULT_COPTS,
    deprecation = "Use //asylo/identity/attestation/sgx:sgx_local_assertion_verifier",
    visibility = ["//visibility:public"],
    deps = ["//asylo/identity/attestation/sgx:sgx_local_assertion_verifier"],
    alwayslink = 1,
)

cc_library(
    name = "sgx_identity_util",
    hdrs = ["sgx_identity_util.h"],
    copts = ASYLO_DEFAULT_COPTS,
    deprecation = "Use //asylo/identity/platform/sgx:sgx_identity_util",
    visibility = ["//visibility:public"],
    deps = ["//asylo/identity/platform/sgx:sgx_identity_util"],
)

cc_library(
    name = "sgx_identity_expectation_matcher",
    hdrs = ["sgx_identity_expectation_matcher.h"],
    copts = ASYLO_DEFAULT_COPTS,
    deprecation = "Use //asylo/identity/platform/sgx:sgx_identity_expectation_matcher",
    visibility = ["//visibility:public"],
    deps = ["//asylo/identity/platform/sgx:sgx_identity_expectation_matcher"],
    alwayslink = 1,
)

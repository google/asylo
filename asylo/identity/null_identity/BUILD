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

load("//asylo/bazel:copts.bzl", "ASYLO_DEFAULT_COPTS")
load("@rules_cc//cc:defs.bzl", "cc_library")

licenses(["notice"])  # Apache v2.0

# Contains libraries related to null identity and null assertion.

# Implementation of the EnclaveAssertionGenerator interface for null
# assertions.
cc_library(
    name = "null_assertion_generator",
    copts = ASYLO_DEFAULT_COPTS,
    deprecation = "Use //asylo/identity/attestation/null:null_assertion_generator",
    visibility = ["//visibility:public"],
    deps = ["//asylo/identity/attestation/null:null_assertion_generator"],
    alwayslink = 1,
)

# Implementation of the EnclaveAssertionVerifier interface for null assertions.
cc_library(
    name = "null_assertion_verifier",
    copts = ASYLO_DEFAULT_COPTS,
    deprecation = "Use //asylo/identity/attestation/null:null_assertion_verifier",
    visibility = ["//visibility:public"],
    deps = ["//asylo/identity/attestation/null:null_assertion_verifier"],
    alwayslink = 1,
)

# Implementation of the MappableIdentityExpectationMatcher interface for the
# null identity.
cc_library(
    name = "null_identity_expectation_matcher",
    copts = ASYLO_DEFAULT_COPTS,
    deprecation = "Use //asylo/identity/attestation/null:null_identity_expectation_matcher",
    visibility = ["//visibility:public"],
    deps = ["//asylo/identity/attestation/null:null_identity_expectation_matcher"],
    alwayslink = 1,
)

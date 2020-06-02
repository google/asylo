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

# This package contains constants for Intel SGX ECDSA PKI certificates.

load("@rules_cc//cc:defs.bzl", "cc_library")
load(
    "//asylo/bazel:asylo.bzl",
    cc_test = "cc_test_and_cc_enclave_test",
)
load("//asylo/bazel:copts.bzl", "ASYLO_DEFAULT_COPTS")

licenses(["notice"])

cc_library(
    name = "intel_sgx_root_ca_cert",
    srcs = ["intel_sgx_root_ca_cert.cc"],
    hdrs = ["intel_sgx_root_ca_cert.h"],
    copts = ASYLO_DEFAULT_COPTS,
    visibility = ["//asylo:implementation"],
    deps = [
        "//asylo/crypto:certificate_cc_proto",
    ],
)

cc_test(
    name = "intel_sgx_root_ca_cert_test",
    srcs = ["intel_sgx_root_ca_cert_test.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":intel_sgx_root_ca_cert",
        "//asylo/crypto:asn1",
        "//asylo/crypto:certificate_cc_proto",
        "//asylo/crypto:x509_certificate",
        "//asylo/test/util:status_matchers",
        "//asylo/test/util:test_main",
        "@com_google_googletest//:gtest",
    ],
)

cc_library(
    name = "qe_identity",
    srcs = ["qe_identity.cc"],
    hdrs = ["qe_identity.h"],
    copts = ASYLO_DEFAULT_COPTS,
    visibility = ["//asylo:implementation"],
)

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

licenses(["notice"])  # Apache v2.0

package(default_visibility = ["//asylo:implementation"])

load("//asylo/bazel:proto.bzl", "asylo_proto_library")
load("//asylo/bazel:asylo.bzl", "cc_test")

# Asylo Crypto library

# Defines an enum for various hashing algorithms.
asylo_proto_library(
    name = "algorithms_proto",
    srcs = ["algorithms.proto"],
)

# Defines a C++ interface for hash functions.
cc_library(
    name = "hash_interface",
    hdrs = ["hash_interface.h"],
    deps = [":algorithms_proto_cc"],
)

# Implementation of HashInterface for SHA256.
cc_library(
    name = "sha256_hash",
    srcs = ["sha256_hash.cc"],
    hdrs = ["sha256_hash.h"],
    deps = [
        ":hash_interface",
        "@boringssl//:crypto",
    ],
)

# Tests for the Sha256Hash wrapper class.
cc_test(
    name = "sha256_hash_test",
    srcs = ["sha256_hash_test.cc"],
    enclave_test_name = "sha256_hash_enclave_test",
    tags = ["regression"],
    deps = [
        ":sha256_hash",
        "//asylo/test/util:test_main",
        "@boringssl//:crypto",
        "@com_google_absl//absl/strings",
        "@com_google_googletest//:gtest",
    ],
)

# AES-GCM-SIV cryptor
cc_library(
    name = "aes_gcm_siv",
    srcs = ["aes_gcm_siv.cc"],
    hdrs = [
        "aes_gcm_siv.h",
        "nonce_generator.h",
    ],
    visibility = ["//visibility:public"],
    deps = [
        "//asylo/crypto/util:bssl_util",
        "//asylo/identity/util:bytes",
        "//asylo/util:cleansing_types",
        "//asylo/util:status",
        "@boringssl//:crypto",
        "@com_google_absl//absl/strings",
        "@com_google_asylo//asylo/util:logging",
    ],
)

cc_test(
    name = "aes_gcm_siv_test",
    srcs = ["aes_gcm_siv_test.cc"],
    tags = ["regression"],
    deps = [
        ":aes_gcm_siv",
        "//asylo/identity/util:byte_container_view",
        "//asylo/identity/util:bytes",
        "//asylo/identity/util:trivial_object_util",
        "//asylo/test/util:status_matchers",
        "//asylo/test/util:test_main",
        "//asylo/util:status",
        "@com_google_absl//absl/strings",
        "@com_google_googletest//:gtest",
    ],
)

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

load(
    "//asylo/bazel:asylo.bzl",
    cc_test = "cc_test_and_cc_enclave_test",
)
load("//asylo/bazel:copts.bzl", "ASYLO_DEFAULT_COPTS")

# Asylo Crypto library

# Defines an enum for various hashing algorithms.
proto_library(
    name = "algorithms_proto",
    srcs = ["algorithms.proto"],
    visibility = ["//asylo:implementation"],
)

cc_proto_library(
    name = "algorithms_cc_proto",
    visibility = ["//asylo:implementation"],
    deps = ["algorithms_proto"],
)

# Defines key structures for various asymmetric key types.
proto_library(
    name = "keys_proto",
    srcs = ["keys.proto"],
    visibility = ["//asylo:implementation"],
    deps = [":algorithms_proto"],
)

cc_proto_library(
    name = "keys_cc_proto",
    visibility = ["//asylo:implementation"],
    deps = [":keys_proto"],
)

# Defines messages for certificates and certificate chains.
proto_library(
    name = "certificate_proto",
    srcs = ["certificate.proto"],
    visibility = ["//asylo:implementation"],
)

cc_proto_library(
    name = "certificate_cc_proto",
    visibility = ["//asylo:implementation"],
    deps = [":certificate_proto"],
)

# A generic cryptor wrapping an AEAD key and a NonceGeneratorInterface.
cc_library(
    name = "aead_cryptor",
    srcs = ["aead_cryptor.cc"],
    hdrs = ["aead_cryptor.h"],
    copts = ASYLO_DEFAULT_COPTS,
    visibility = ["//visibility:public"],
    deps = [
        ":aead_key",
        ":algorithms_cc_proto",
        ":nonce_generator_interface",
        ":random_nonce_generator",
        "//asylo/crypto/util:byte_container_view",
        "//asylo/util:status",
        "@com_google_absl//absl/memory",
        "@com_google_absl//absl/types:span",
    ],
)

# Tests for AeadCryptor class.
cc_test(
    name = "aead_cryptor_test",
    srcs = ["aead_cryptor_test.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":aead_cryptor",
        ":aead_test_vector",
        "//asylo/test/util:status_matchers",
        "//asylo/test/util:test_main",
        "//asylo/util:cleansing_types",
        "@com_google_absl//absl/types:span",
        "@com_google_googletest//:gtest",
    ],
)

# Implementation of AeadKey.
cc_library(
    name = "aead_key",
    srcs = ["aead_key.cc"],
    hdrs = ["aead_key.h"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":algorithms_cc_proto",
        "//asylo/crypto/util:bssl_util",
        "//asylo/crypto/util:byte_container_view",
        "//asylo/util:cleansing_types",
        "//asylo/util:cleanup",
        "//asylo/util:status",
        "@boringssl//:crypto",
        "@com_google_absl//absl/memory",
        "@com_google_absl//absl/strings",
    ],
)

# A class wrapping the setup for AEAD test vectors.
cc_library(
    name = "aead_test_vector",
    testonly = 1,
    srcs = ["aead_test_vector.cc"],
    hdrs = ["aead_test_vector.h"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        "//asylo/util:cleansing_types",
        "@com_google_absl//absl/strings",
    ],
)

# Tests for AeadKey class.
cc_test(
    name = "aead_key_test",
    srcs = ["aead_key_test.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":aead_key",
        ":aead_test_vector",
        ":algorithms_cc_proto",
        "//asylo/crypto/util:bytes",
        "//asylo/test/util:status_matchers",
        "//asylo/test/util:test_main",
        "//asylo/util:cleansing_types",
        "//asylo/util:status",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/types:span",
        "@com_google_googletest//:gtest",
    ],
)

# Library to use with ASN.1 data structures.
cc_library(
    name = "asn1",
    srcs = ["asn1.cc"],
    hdrs = ["asn1.h"],
    copts = ASYLO_DEFAULT_COPTS,
    visibility = ["//asylo:implementation"],
    deps = [
        ":bignum_util",
        "//asylo/crypto/util:bssl_util",
        "//asylo/crypto/util:byte_container_view",
        "//asylo/util:logging",
        "//asylo/util:status",
        "@boringssl//:crypto",
        "@com_google_absl//absl/base:core_headers",
        "@com_google_absl//absl/strings:str_format",
        "@com_google_absl//absl/types:optional",
        "@com_google_absl//absl/types:span",
    ],
)

# Test for ASN.1 library.
cc_test(
    name = "asn1_test",
    srcs = ["asn1_test.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":asn1",
        ":bignum_util",
        "//asylo/crypto/util:bssl_util",
        "//asylo/crypto/util:byte_container_view",
        "//asylo/test/util:status_matchers",
        "//asylo/test/util:test_main",
        "//asylo/util:status",
        "@boringssl//:crypto",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/strings:str_format",
        "@com_google_absl//absl/types:optional",
        "@com_google_absl//absl/types:span",
        "@com_google_googletest//:gtest",
    ],
)

# Utility library for OpenSSL BIGNUMs.
cc_library(
    name = "bignum_util",
    srcs = ["bignum_util.cc"],
    hdrs = ["bignum_util.h"],
    copts = ASYLO_DEFAULT_COPTS,
    visibility = ["//asylo:implementation"],
    deps = [
        "//asylo/crypto/util:bssl_util",
        "//asylo/crypto/util:byte_container_view",
        "//asylo/util:status",
        "@boringssl//:crypto",
        "@com_google_absl//absl/base",
    ],
)

# Tests for BIGNUM utilities library.
cc_test(
    name = "bignum_util_test",
    srcs = ["bignum_util_test.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":bignum_util",
        "//asylo/crypto/util:bssl_util",
        "//asylo/test/util:status_matchers",
        "//asylo/test/util:test_main",
        "//asylo/util:status",
        "@boringssl//:crypto",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/types:span",
        "@com_google_googletest//:gtest",
    ],
)

# Library to use with certificates.
cc_library(
    name = "certificate_util",
    srcs = ["certificate_util.cc"],
    hdrs = ["certificate_util.h"],
    copts = ASYLO_DEFAULT_COPTS,
    visibility = ["//asylo:implementation"],
    deps = [
        ":certificate_cc_proto",
        ":certificate_interface",
        "//asylo/util:status",
        "@com_google_absl//absl/container:flat_hash_map",
        "@com_google_absl//absl/types:optional",
        "@com_google_absl//absl/types:span",
    ],
)

# Test for certificate util library.
cc_test(
    name = "certificate_util_test",
    srcs = ["certificate_util_test.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":certificate_cc_proto",
        ":certificate_interface",
        ":certificate_util",
        "//asylo/test/util:status_matchers",
        "//asylo/test/util:test_main",
        "//asylo/util:status",
        "@com_google_absl//absl/memory",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/types:optional",
        "@com_google_googletest//:gtest",
    ],
)

# Interface for performing operations on certificates.
cc_library(
    name = "certificate_interface",
    hdrs = ["certificate_interface.h"],
    copts = ASYLO_DEFAULT_COPTS,
    visibility = ["//asylo:implementation"],
    deps = [
        "//asylo/util:status",
        "@com_google_absl//absl/types:optional",
    ],
)

# X.509 certificate wrapper.
cc_library(
    name = "x509_certificate",
    srcs = ["x509_certificate.cc"],
    hdrs = ["x509_certificate.h"],
    copts = ASYLO_DEFAULT_COPTS,
    visibility = ["//asylo:implementation"],
    deps = [
        ":certificate_cc_proto",
        ":certificate_interface",
        "//asylo/crypto/util:bssl_util",
        "//asylo/crypto/util:byte_container_view",
        "//asylo/util:logging",
        "//asylo/util:status",
        "@boringssl//:crypto",
        "@com_google_absl//absl/memory",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/types:optional",
    ],
)

# Tests for X.509 certificate wrapper.
cc_test(
    name = "x509_certificate_test",
    srcs = ["x509_certificate_test.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":certificate_cc_proto",
        ":certificate_interface",
        ":x509_certificate",
        "//asylo/test/util:status_matchers",
        "//asylo/test/util:test_main",
        "//asylo/util:status",
        "@com_google_absl//absl/strings",
        "@com_google_googletest//:gtest",
    ],
)

# Defines a C++ interface for hash functions.
cc_library(
    name = "hash_interface",
    hdrs = ["hash_interface.h"],
    copts = ASYLO_DEFAULT_COPTS,
    visibility = ["//asylo:implementation"],
    deps = [
        ":algorithms_cc_proto",
        "//asylo/crypto/util:byte_container_view",
        "//asylo/util:status",
    ],
)

# Defines a C++ interface for nonce generators.
cc_library(
    name = "nonce_generator_interface",
    hdrs = ["nonce_generator_interface.h"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        "//asylo/util:status",
        "@com_google_absl//absl/types:span",
    ],
)

# Implementation of NonceGeneratorInterface with random nonce generation.
cc_library(
    name = "random_nonce_generator",
    srcs = ["random_nonce_generator.cc"],
    hdrs = ["random_nonce_generator.h"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":nonce_generator_interface",
        "//asylo/crypto/util:bssl_util",
        "//asylo/util:status",
        "@boringssl//:crypto",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/types:span",
    ],
)

# Tests for RandomNonceGenerator.
cc_test(
    name = "random_nonce_generator_test",
    srcs = ["random_nonce_generator_test.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":random_nonce_generator",
        "//asylo/test/util:status_matchers",
        "//asylo/test/util:test_main",
        "@com_google_absl//absl/container:flat_hash_set",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/types:span",
        "@com_google_googletest//:gtest",
    ],
)

# Implementation of HashInterface for SHA256.
cc_library(
    name = "sha256_hash",
    srcs = ["sha256_hash.cc"],
    hdrs = ["sha256_hash.h"],
    copts = ASYLO_DEFAULT_COPTS,
    visibility = ["//asylo:implementation"],
    deps = [
        ":hash_interface",
        "//asylo/crypto/util:bssl_util",
        "//asylo/crypto/util:byte_container_view",
        "//asylo/util:status",
        "@boringssl//:crypto",
    ],
)

# Tests for the Sha256Hash wrapper class.
cc_test(
    name = "sha256_hash_test",
    srcs = ["sha256_hash_test.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":algorithms_cc_proto",
        ":sha256_hash",
        "//asylo/crypto/util:byte_container_util",
        "//asylo/test/util:status_matchers",
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
    copts = ASYLO_DEFAULT_COPTS,
    visibility = ["//visibility:public"],
    deps = [
        "//asylo/crypto/util:bssl_util",
        "//asylo/crypto/util:bytes",
        "//asylo/util:cleansing_types",
        "//asylo/util:logging",
        "//asylo/util:status",
        "@boringssl//:crypto",
        "@com_google_absl//absl/strings",
    ],
)

cc_test(
    name = "aes_gcm_siv_test",
    srcs = ["aes_gcm_siv_test.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":aes_gcm_siv",
        "//asylo/crypto/util:byte_container_view",
        "//asylo/crypto/util:bytes",
        "//asylo/crypto/util:trivial_object_util",
        "//asylo/test/util:status_matchers",
        "//asylo/test/util:test_main",
        "//asylo/util:status",
        "@com_google_absl//absl/strings",
        "@com_google_googletest//:gtest",
    ],
)

cc_library(
    name = "signing_key",
    hdrs = ["signing_key.h"],
    copts = ASYLO_DEFAULT_COPTS,
    visibility = ["//asylo:implementation"],
    deps = [
        ":algorithms_cc_proto",
        ":keys_cc_proto",
        "//asylo/crypto/util:byte_container_view",
        "//asylo/util:cleansing_types",
        "//asylo/util:status",
    ],
)

cc_library(
    name = "ecdsa_p256_sha256_signing_key",
    srcs = ["ecdsa_p256_sha256_signing_key.cc"],
    hdrs = ["ecdsa_p256_sha256_signing_key.h"],
    copts = ASYLO_DEFAULT_COPTS,
    visibility = ["//asylo:implementation"],
    deps = [
        ":bignum_util",
        ":keys_cc_proto",
        ":sha256_hash",
        ":signing_key",
        "//asylo/crypto/util:bssl_util",
        "//asylo/crypto/util:byte_container_view",
        "//asylo/util:status",
        "@boringssl//:crypto",
        "@com_google_absl//absl/memory",
        "@com_google_absl//absl/strings:str_format",
    ],
)

cc_test(
    name = "ecdsa_p256_sha256_signing_key_test",
    srcs = ["ecdsa_p256_sha256_signing_key_test.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":ecdsa_p256_sha256_signing_key",
        ":fake_signing_key",
        ":signing_key",
        "//asylo/crypto/util:byte_container_util",
        "//asylo/crypto/util:byte_container_view",
        "//asylo/test/util:status_matchers",
        "//asylo/test/util:test_main",
        "//asylo/util:cleansing_types",
        "//asylo/util:logging",
        "@boringssl//:crypto",
        "@com_google_absl//absl/flags:flag",
        "@com_google_absl//absl/strings",
        "@com_google_googletest//:gtest",
    ],
)

cc_library(
    name = "fake_signing_key",
    testonly = 1,
    srcs = ["fake_signing_key.cc"],
    hdrs = ["fake_signing_key.h"],
    copts = ASYLO_DEFAULT_COPTS,
    visibility = ["//asylo:implementation"],
    deps = [
        ":algorithms_cc_proto",
        ":keys_cc_proto",
        ":signing_key",
        "//asylo/crypto/util:byte_container_view",
        "//asylo/util:cleansing_types",
        "//asylo/util:status",
        "@com_google_absl//absl/memory",
    ],
)

cc_test(
    name = "fake_signing_key_test",
    srcs = ["fake_signing_key_test.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":fake_signing_key",
        ":signing_key",
        "//asylo/crypto/util:byte_container_view",
        "//asylo/test/util:status_matchers",
        "//asylo/test/util:test_main",
        "//asylo/util:cleansing_types",
        "//asylo/util:status",
        "@com_google_googletest//:gtest",
    ],
)

cc_library(
    name = "asymmetric_encryption_key",
    hdrs = ["asymmetric_encryption_key.h"],
    copts = ASYLO_DEFAULT_COPTS,
    visibility = ["//asylo:implementation"],
    deps = [
        ":algorithms_cc_proto",
        "//asylo/crypto/util:byte_container_view",
        "//asylo/util:cleansing_types",
        "//asylo/util:status",
    ],
)

cc_library(
    name = "rsa_oaep_encryption_key",
    srcs = ["rsa_oaep_encryption_key.cc"],
    hdrs = ["rsa_oaep_encryption_key.h"],
    copts = ASYLO_DEFAULT_COPTS,
    visibility = ["//asylo:implementation"],
    deps = [
        ":algorithms_cc_proto",
        ":asymmetric_encryption_key",
        "//asylo/crypto/util:bssl_util",
        "//asylo/crypto/util:byte_container_util",
        "//asylo/crypto/util:byte_container_view",
        "//asylo/util:status",
        "@boringssl//:crypto",
        "@com_google_absl//absl/strings",
    ],
)

cc_test(
    name = "rsa_oaep_encryption_key_test",
    srcs = ["rsa_oaep_encryption_key_test.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":algorithms_cc_proto",
        ":asymmetric_encryption_key",
        ":rsa_oaep_encryption_key",
        "//asylo/crypto/util:bssl_util",
        "//asylo/crypto/util:byte_container_util",
        "//asylo/test/util:status_matchers",
        "//asylo/test/util:test_main",
        "//asylo/util:cleansing_types",
        "@boringssl//:crypto",
        "@com_google_absl//absl/strings",
        "@com_google_googletest//:gtest",
    ],
)

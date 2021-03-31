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

load("@rules_cc//cc:defs.bzl", "cc_library", "cc_proto_library")
load("@rules_proto//proto:defs.bzl", "proto_library")
load(
    "//asylo/bazel:asylo.bzl",
    cc_test = "cc_test_and_cc_enclave_test",
)
load("//asylo/bazel:copts.bzl", "ASYLO_DEFAULT_COPTS")

licenses(["notice"])  # Apache v2.0

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

proto_library(
    name = "fake_certificate_proto",
    srcs = ["fake_certificate.proto"],
)

cc_proto_library(
    name = "fake_certificate_cc_proto",
    deps = [":fake_certificate_proto"],
)

proto_library(
    name = "sha256_hash_proto",
    srcs = ["sha256_hash.proto"],
    visibility = ["//visibility:public"],
)

cc_proto_library(
    name = "sha256_hash_cc_proto",
    visibility = ["//visibility:public"],
    deps = ["sha256_hash_proto"],
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
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/strings",
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
        "@com_google_absl//absl/status",
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
        "//asylo/util:error_codes",
        "//asylo/util:logging",
        "//asylo/util:status",
        "@boringssl//:crypto",
        "@com_google_absl//absl/base:core_headers",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/strings",
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
        "//asylo/test/util:integral_type_test_data",
        "//asylo/test/util:status_matchers",
        "//asylo/test/util:test_main",
        "//asylo/util:status",
        "@boringssl//:crypto",
        "@com_google_absl//absl/base:core_headers",
        "@com_google_absl//absl/hash:hash_testing",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/strings:str_format",
        "@com_google_absl//absl/types:optional",
        "@com_google_absl//absl/types:span",
        "@com_google_googletest//:gtest",
    ],
)

# Library for specifying ASN.1 structures.
cc_library(
    name = "asn1_schema",
    srcs = ["asn1_schema.cc"],
    hdrs = ["asn1_schema.h"],
    copts = ASYLO_DEFAULT_COPTS,
    visibility = ["//asylo:implementation"],
    deps = [
        ":asn1",
        "//asylo/util:status",
        "//asylo/util:status_helpers",
        "@com_google_absl//absl/memory",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/strings:str_format",
    ],
)

# Tests for the ASN.1 specification library.
cc_test(
    name = "asn1_schema_test",
    srcs = ["asn1_schema_test.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":asn1",
        ":asn1_schema",
        "//asylo/test/util:status_matchers",
        "//asylo/test/util:test_main",
        "//asylo/util:status",
        "@boringssl//:crypto",
        "@com_google_absl//absl/memory",
        "@com_google_absl//absl/status",
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
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/strings:str_format",
    ],
)

# Tests for BIGNUM utilities library.
cc_test(
    name = "bignum_util_test",
    srcs = ["bignum_util_test.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":bignum_util",
        "//asylo/test/util:integral_type_test_data",
        "//asylo/test/util:status_matchers",
        "//asylo/test/util:test_main",
        "//asylo/util:status",
        "@boringssl//:crypto",
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
        ":x509_certificate",
        "//asylo/identity/attestation/sgx/internal:attestation_key_certificate_impl",
        "//asylo/util:proto_enum_util",
        "//asylo/util:status",
        "//asylo/util:status_helpers",
        "@com_google_absl//absl/container:flat_hash_map",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/strings",
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
        ":fake_certificate",
        ":fake_certificate_cc_proto",
        "//asylo/test/util:proto_matchers",
        "//asylo/test/util:status_matchers",
        "//asylo/test/util:test_main",
        "//asylo/util:proto_parse_util",
        "@com_google_absl//absl/memory",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/types:optional",
        "@com_google_absl//absl/types:span",
        "@com_google_googletest//:gtest",
        "@com_google_protobuf//:protobuf",
    ],
)

# Interface for performing operations on certificates.
cc_library(
    name = "certificate_interface",
    hdrs = ["certificate_interface.h"],
    copts = ASYLO_DEFAULT_COPTS,
    visibility = ["//asylo:implementation"],
    deps = [
        ":certificate_cc_proto",
        "//asylo/util:status",
        "@com_google_absl//absl/time",
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
        ":asn1",
        ":certificate_cc_proto",
        ":certificate_interface",
        ":x509_signer",
        "//asylo/crypto/util:bssl_util",
        "//asylo/crypto/util:byte_container_view",
        "//asylo/util:logging",
        "//asylo/util:proto_enum_util",
        "//asylo/util:status",
        "//asylo/util:status_helpers",
        "@boringssl//:crypto",
        "@com_google_absl//absl/base",
        "@com_google_absl//absl/memory",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/strings:str_format",
        "@com_google_absl//absl/time",
        "@com_google_absl//absl/types:optional",
        "@com_google_absl//absl/types:span",
    ],
)

# Tests for X.509 certificate wrapper.
cc_test(
    name = "x509_certificate_test",
    srcs = ["x509_certificate_test.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":asn1",
        ":bignum_util",
        ":certificate_cc_proto",
        ":certificate_interface",
        ":ecdsa_p256_sha256_signing_key",
        ":fake_certificate",
        ":x509_certificate",
        "//asylo/crypto/util:byte_container_util",
        "//asylo/test/util:status_matchers",
        "//asylo/test/util:string_matchers",
        "//asylo/test/util:test_main",
        "//asylo/util:status",
        "@boringssl//:crypto",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/strings:str_format",
        "@com_google_absl//absl/time",
        "@com_google_absl//absl/types:optional",
        "@com_google_absl//absl/types:span",
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
        "@com_google_absl//absl/memory",
        "@com_google_absl//absl/status",
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
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/types:span",
        "@com_google_googletest//:gtest",
    ],
)

# Implementation of HashInterface for SHA algorithms
cc_library(
    name = "sha_hash",
    hdrs = ["sha_hash.h"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":hash_interface",
        ":sha256_hash_cc_proto",
        "//asylo/crypto/util:bssl_util",
        "//asylo/crypto/util:byte_container_view",
        "//asylo/util:status",
        "@boringssl//:crypto",
        "@com_google_absl//absl/status",
    ],
)

cc_library(
    name = "sha_hash_test",
    testonly = True,
    hdrs = ["sha_hash_test.h"],
    deps = [
        ":algorithms_cc_proto",
        ":sha256_hash_util",
        ":sha_hash",
        "//asylo/crypto/util:byte_container_util",
        "//asylo/test/util:status_matchers",
        "@boringssl//:crypto",
        "@com_google_absl//absl/strings",
        "@com_google_googletest//:gtest",
    ],
)

# Implementation of ShaHash for SHA256.
cc_library(
    name = "sha256_hash",
    hdrs = ["sha256_hash.h"],
    copts = ASYLO_DEFAULT_COPTS,
    visibility = ["//asylo:implementation"],
    deps = [
        ":algorithms_cc_proto",
        ":sha_hash",
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
        ":sha_hash_test",
        "//asylo/test/util:test_main",
        "@com_google_googletest//:gtest",
    ],
)

# Implementation of ShaHash for SHA256.
cc_library(
    name = "sha384_hash",
    hdrs = ["sha384_hash.h"],
    copts = ASYLO_DEFAULT_COPTS,
    visibility = ["//asylo:implementation"],
    deps = [
        ":algorithms_cc_proto",
        ":sha_hash",
        "@boringssl//:crypto",
    ],
)

# Tests for the Sha384Hash wrapper class.
cc_test(
    name = "sha384_hash_test",
    srcs = ["sha384_hash_test.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":algorithms_cc_proto",
        ":sha384_hash",
        ":sha_hash_test",
        "//asylo/test/util:test_main",
        "@boringssl//:crypto",
        "@com_google_googletest//:gtest",
    ],
)

cc_library(
    name = "signing_key",
    srcs = ["signing_key.cc"],
    hdrs = ["signing_key.h"],
    copts = ASYLO_DEFAULT_COPTS,
    visibility = ["//asylo:implementation"],
    deps = [
        ":algorithms_cc_proto",
        ":keys_cc_proto",
        ":x509_signer",
        "//asylo/crypto/util:byte_container_util",
        "//asylo/crypto/util:byte_container_view",
        "//asylo/util:cleansing_types",
        "//asylo/util:proto_enum_util",
        "//asylo/util:status",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/strings:str_format",
    ],
)

cc_library(
    name = "ecdsa_signing_key",
    srcs = ["ecdsa_signing_key.cc"],
    hdrs = ["ecdsa_signing_key.h"],
    deps = [
        ":algorithms_cc_proto",
        ":bignum_util",
        ":keys_cc_proto",
        ":sha256_hash",
        ":signing_key",
        "//asylo/crypto/util:bssl_util",
        "//asylo/crypto/util:byte_container_view",
        "//asylo/crypto/util:bytes",
        "//asylo/util:proto_enum_util",
        "//asylo/util:status",
        "@boringssl//:crypto",
        "@com_google_absl//absl/memory",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/strings:str_format",
    ],
)

cc_library(
    name = "ecdsa_signing_key_test",
    testonly = True,
    hdrs = ["ecdsa_signing_key_test.h"],
    deps = [
        ":algorithms_cc_proto",
        ":ecdsa_signing_key",
        ":fake_signing_key",
        ":keys_cc_proto",
        ":signing_key",
        "//asylo/crypto/util:byte_container_util",
        "//asylo/crypto/util:byte_container_view",
        "//asylo/test/util:proto_matchers",
        "//asylo/test/util:status_matchers",
        "//asylo/test/util:string_matchers",
        "//asylo/util:cleansing_types",
        "//asylo/util:logging",
        "@boringssl//:crypto",
        "@com_google_absl//absl/flags:flag",
        "@com_google_absl//absl/functional:bind_front",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/strings",
        "@com_google_googletest//:gtest",
        "@com_google_protobuf//:protobuf",
    ],
)

cc_library(
    name = "ecdsa_p256_sha256_signing_key",
    hdrs = ["ecdsa_p256_sha256_signing_key.h"],
    copts = ASYLO_DEFAULT_COPTS,
    visibility = ["//asylo:implementation"],
    deps = [
        ":algorithms_cc_proto",
        ":ecdsa_signing_key",
        ":sha256_hash",
        "@boringssl//:crypto",
    ],
)

cc_test(
    name = "ecdsa_p256_sha256_signing_key_test",
    srcs = ["ecdsa_p256_sha256_signing_key_test.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":algorithms_cc_proto",
        ":ecdsa_p256_sha256_signing_key",
        ":ecdsa_signing_key_test",
        "//asylo/crypto/util:byte_container_view",
        "//asylo/test/util:test_main",
        "@com_google_absl//absl/strings",
        "@com_google_googletest//:gtest",
    ],
)

cc_library(
    name = "ecdsa_p384_sha384_signing_key",
    hdrs = ["ecdsa_p384_sha384_signing_key.h"],
    copts = ASYLO_DEFAULT_COPTS,
    visibility = ["//asylo:implementation"],
    deps = [
        ":algorithms_cc_proto",
        ":ecdsa_signing_key",
        ":sha384_hash",
        "@boringssl//:crypto",
    ],
)

cc_test(
    name = "ecdsa_p384_sha384_signing_key_test",
    srcs = ["ecdsa_p384_sha384_signing_key_test.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":ecdsa_p384_sha384_signing_key",
        ":ecdsa_signing_key_test",
        "//asylo/test/util:test_main",
        "@com_google_googletest//:gtest",
    ],
)

cc_library(
    name = "fake_certificate",
    testonly = 1,
    srcs = ["fake_certificate.cc"],
    hdrs = ["fake_certificate.h"],
    copts = ASYLO_DEFAULT_COPTS,
    visibility = ["//asylo:implementation"],
    deps = [
        ":certificate_cc_proto",
        ":certificate_interface",
        ":fake_certificate_cc_proto",
        "//asylo/util:status",
        "@com_google_absl//absl/memory",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/strings:str_format",
        "@com_google_absl//absl/time",
        "@com_google_absl//absl/types:optional",
    ],
)

cc_test(
    name = "fake_certificate_test",
    srcs = ["fake_certificate_test.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":certificate_cc_proto",
        ":certificate_interface",
        ":fake_certificate",
        ":fake_certificate_cc_proto",
        "//asylo/test/util:status_matchers",
        "//asylo/test/util:test_main",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/types:optional",
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
        "//asylo/crypto/util:byte_container_util",
        "//asylo/crypto/util:byte_container_view",
        "//asylo/util:cleansing_types",
        "//asylo/util:status",
        "@boringssl//:crypto",
        "@com_google_absl//absl/memory",
        "@com_google_absl//absl/status",
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
        "@com_google_absl//absl/status",
        "@com_google_googletest//:gtest",
    ],
)

cc_library(
    name = "asymmetric_encryption_key",
    srcs = ["asymmetric_encryption_key.cc"],
    hdrs = ["asymmetric_encryption_key.h"],
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

cc_test(
    name = "asymmetric_encryption_key_test",
    srcs = ["asymmetric_encryption_key_test.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":algorithms_cc_proto",
        ":asymmetric_encryption_key",
        ":keys_cc_proto",
        "//asylo/test/util:status_matchers",
        "//asylo/test/util:test_main",
        "//asylo/util:cleansing_types",
        "//asylo/util:error_codes",
        "//asylo/util:status",
        "@com_google_absl//absl/memory",
        "@com_google_absl//absl/status",
        "@com_google_googletest//:gtest",
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
        "//asylo/util:proto_enum_util",
        "//asylo/util:status",
        "@boringssl//:crypto",
        "@com_google_absl//absl/memory",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/strings",
    ],
)

cc_test(
    name = "rsa_oaep_encryption_key_test",
    size = "small",
    srcs = ["rsa_oaep_encryption_key_test.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    transitive_features = ["lvi_no_auto_mitigation"],  # disable LVI mitigation to shorten test time
    deps = [
        ":algorithms_cc_proto",
        ":asymmetric_encryption_key",
        ":keys_cc_proto",
        ":rsa_oaep_encryption_key",
        "//asylo/crypto/util:bssl_util",
        "//asylo/crypto/util:byte_container_util",
        "//asylo/test/util:status_matchers",
        "//asylo/test/util:test_main",
        "//asylo/util:cleansing_types",
        "//asylo/util:proto_parse_util",
        "//asylo/util:status",
        "//asylo/util:status_macros",
        "@boringssl//:crypto",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/strings",
        "@com_google_googletest//:gtest",
    ],
)

cc_library(
    name = "sha256_hash_util",
    srcs = ["sha256_hash_util.cc"],
    hdrs = ["sha256_hash_util.h"],
    copts = ASYLO_DEFAULT_COPTS,
    visibility = ["//visibility:public"],
    deps = [
        ":sha256_hash_cc_proto",
        "//asylo/crypto/util:bytes",
        "//asylo/crypto/util:trivial_object_util",
        "//asylo/util:status",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/strings:str_format",
    ],
)

cc_library(
    name = "x509_signer",
    hdrs = ["x509_signer.h"],
    deps = [
        "//asylo/util:cleansing_types",
        "//asylo/util:status",
        "@boringssl//:crypto",
    ],
)

cc_test(
    name = "sha256_hash_util_test",
    srcs = ["sha256_hash_util_test.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":sha256_hash_cc_proto",
        ":sha256_hash_util",
        "//asylo/test/util:status_matchers",
        "//asylo/test/util:test_main",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/strings",
        "@com_google_googletest//:gtest",
    ],
)

cc_library(
    name = "rsa_x509_signer",
    srcs = ["rsa_x509_signer.cc"],
    hdrs = ["rsa_x509_signer.h"],
    deps = [
        ":algorithms_cc_proto",
        ":x509_signer",
        "//asylo/crypto/util:bssl_util",
        "//asylo/crypto/util:byte_container_view",
        "//asylo/util:cleansing_types",
        "//asylo/util:status",
        "@boringssl//:crypto",
        "@com_google_absl//absl/memory",
        "@com_google_absl//absl/status",
    ],
)

cc_test(
    name = "rsa_x509_signer_test",
    srcs = ["rsa_x509_signer_test.cc"],
    deps = [
        ":algorithms_cc_proto",
        ":certificate_cc_proto",
        ":certificate_interface",
        ":keys_cc_proto",
        ":rsa_x509_signer",
        ":x509_certificate",
        "//asylo/crypto/util:byte_container_util",
        "//asylo/test/util:status_matchers",
        "//asylo/test/util:string_matchers",
        "//asylo/test/util:test_main",
        "//asylo/util:error_codes",
        "@boringssl//:crypto",
        "@com_google_absl//absl/strings",
    ],
)

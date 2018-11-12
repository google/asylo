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
    "//asylo/bazel:proto.bzl",
    "asylo_grpc_proto_library",
)

# Service definition for the attestation-domain service.
asylo_grpc_proto_library(
    name = "attestation_domain_grpc_proto",
    srcs = ["attestation_domain.proto"],
    generate_mocks = True,
)

# Implementation of GetAttestationDomain() that returns a string representing
# current local attestation domain.
cc_library(
    name = "attestation_domain",
    srcs = ["attestation_domain.cc"],
    hdrs = ["attestation_domain.h"],
    deps = [
        "//asylo/crypto/util:bssl_util",
        "//asylo/util:logging",
        "//asylo/util:status",
        "@boringssl//:crypto",
        "@com_google_absl//absl/strings",
    ],
)

# Implementation of AttestationDomainService.
cc_library(
    name = "attestation_domain_service_impl",
    srcs = ["attestation_domain_service_impl.cc"],
    hdrs = ["attestation_domain_service_impl.h"],
    visibility = ["//asylo:implementation"],
    deps = [
        ":attestation_domain",
        ":attestation_domain_grpc_proto",
        "@com_github_grpc_grpc//:grpc++",
    ],
)

# Implementation of the AttestationDomainService client.
cc_library(
    name = "attestation_domain_client",
    srcs = ["attestation_domain_client.cc"],
    hdrs = ["attestation_domain_client.h"],
    visibility = ["//asylo:implementation"],
    deps = [
        ":attestation_domain_grpc_proto",
        "//asylo/util:status",
        "@com_github_grpc_grpc//:grpc++",
    ],
)

# Tests for the attestation_domain library.
cc_test(
    name = "attestation_domain_test",
    srcs = ["attestation_domain_test.cc"],
    deps = [
        ":attestation_domain",
        "//asylo/test/util:status_matchers",
        "//asylo/test/util:test_flags",
        "//asylo/test/util:test_main",
        "@com_google_absl//absl/strings",
        "@com_google_googletest//:gtest",
    ],
)

# Tests for the attestation_domain_client library.
cc_test(
    name = "attestation_domain_client_test",
    srcs = ["attestation_domain_client_test.cc"],
    deps = [
        ":attestation_domain_client",
        ":attestation_domain_grpc_proto",
        "//asylo/test/util:status_matchers",
        "//asylo/test/util:test_main",
        "//asylo/util:status",
        "@com_github_grpc_grpc//:grpc++",
        "@com_google_absl//absl/memory",
        "@com_google_absl//absl/synchronization",
        "@com_google_googletest//:gtest",
    ],
)

# Tests for the attestation_domain_service_impl library.
cc_test(
    name = "attestation_domain_service_impl_test",
    srcs = ["attestation_domain_service_impl_test.cc"],
    deps = [
        ":attestation_domain",
        ":attestation_domain_service_impl",
        "//asylo/test/util:status_matchers",
        "//asylo/test/util:test_flags",
        "//asylo/test/util:test_main",
        "@com_github_grpc_grpc//:grpc++",
        "@com_google_absl//absl/strings",
        "@com_google_googletest//:gtest",
    ],
)

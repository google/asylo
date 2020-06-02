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

load("@io_bazel_rules_go//go:def.bzl", "go_test")

licenses(["notice"])

# Description: This package provides tools for generating test data for the
# gRPC security stack implementation.

# Generates test vectors for EKEP secret derivation.
# Note that the test just makes sure this file builds and runs, but doesn't
# actually check anything. However, one can manually run this target in order to
# derive the test vectors used in other tests.
go_test(
    name = "generate_test_vectors_test",
    size = "small",
    srcs = ["generate_test_vectors_test.go"],
    deps = [
        "@com_github_golang_crypto//:curve25519",
        "@com_github_golang_crypto//:hkdf",
    ],
)

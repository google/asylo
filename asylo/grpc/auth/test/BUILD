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

# Description:
#  End-to-end tests for the enclave gRPC stack.

package(
    default_visibility = ["//asylo/grpc/auth/test:__subpackages__"],
)

load(":generate_end2end_tests.bzl", "grpc_end2end_tests")

# A utility library for end2end tests that bridges constants in the C++ layer
# to the C layer.
cc_library(
    name = "end2end_test_util",
    testonly = 1,
    srcs = ["end2end_test_util.cc"],
    hdrs = ["end2end_test_util.h"],
    deps = [
        "//asylo/grpc/auth/core:assertion_description",
        "//asylo/identity:identity_proto_cc",
        "//asylo/identity/null_identity:null_identity_constants",
    ],
)

# A binary that packages a test fixture for the enclave gRPC stack with the
# gRPC end2end tests library.
cc_binary(
    name = "h2_enclave_security_test",
    testonly = 1,
    srcs = ["h2_enclave_security_test.cc"],
    deps = [
        ":end2end_test_util",
        "//asylo/grpc/auth/core:assertion_description",
        "//asylo/grpc/auth/core:enclave_credentials_options",
        "//asylo/grpc/auth/core:grpc_security_enclave",
        "//asylo/identity:enclave_assertion_authority_config_proto_cc",
        "//asylo/identity:init",
        "@com_github_grpc_grpc//:gpr_base",
        "@com_github_grpc_grpc//:grpc_secure",
        "@com_github_grpc_grpc//test/core/end2end:end2end_tests",
        "@com_github_grpc_grpc//test/core/util:gpr_test_util",
        "@com_github_grpc_grpc//test/core/util:grpc_test_util_base",
    ],
)

# Generates rules for gRPC end2end tests.
#
# An end2end test target looks like this:
#   h2_enclave_security_test@<TEST_NAME>
#
# See END2END_TESTS in generate_end2end_tests.bzl for the test names that are
# supported.
grpc_end2end_tests()

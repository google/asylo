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
#  This package contains C and C++ utilities used by the enclave gRPC stack.

package(
    default_visibility = ["//asylo/grpc/auth:__subpackages__"],
)

load("//asylo/bazel:copts.bzl", "ASYLO_DEFAULT_COPTS")
load("//asylo/bazel:asylo.bzl", "cc_test")

# A safe_string C utility.
cc_library(
    name = "safe_string",
    srcs = ["safe_string.cc"],
    hdrs = ["safe_string.h"],
    deps = ["@com_github_grpc_grpc//:gpr_base"],
)

# Tests for the safe_string C utility.
cc_test(
    name = "safe_string_test",
    srcs = ["safe_string_test.cc"],
    tags = ["regression"],
    deps = [
        "//asylo/grpc/auth/util:safe_string",
        "//asylo/test/util:test_main",
        "@com_google_googletest//:gtest",
    ],
)

# Bridge utilities between the C++ and C layers of gRPC.
cc_library(
    name = "bridge_cpp_to_c",
    srcs = ["bridge_cpp_to_c.cc"],
    hdrs = ["bridge_cpp_to_c.h"],
    deps = [
        "//asylo/grpc/auth:enclave_credentials_options",
        "//asylo/grpc/auth/core:assertion_description",
        "//asylo/grpc/auth/core:enclave_credentials_options",
        "//asylo/identity:assertion_description_util",
        "//asylo/identity:identity_proto_cc",
    ],
)

# Tests for functions in the C++ to C bridge library.
cc_test(
    name = "bridge_cpp_to_c_test",
    srcs = ["bridge_cpp_to_c_test.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    enclave_test_name = "bridge_cpp_to_c_enclave_test",
    tags = ["regression"],
    deps = [
        ":bridge_cpp_to_c",
        "//asylo/grpc/auth:enclave_credentials_options",
        "//asylo/grpc/auth:null_credentials_options",
        "//asylo/identity:assertion_description_util",
        "//asylo/identity:identity_proto_cc",
        "//asylo/test/util:test_main",
        "@com_google_googletest//:gtest",
    ],
)

# Implementation of ZeroCopyInputStream that manages an internal list of
# buffers.
cc_library(
    name = "multi_buffer_input_stream",
    srcs = ["multi_buffer_input_stream.cc"],
    hdrs = ["multi_buffer_input_stream.h"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        "//asylo/util:logging",
        "@com_google_protobuf//:protobuf_lite",
    ],
)

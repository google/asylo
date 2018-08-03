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

# BUILD file needed to make bzl files available to load.

exports_files([
    "asylo.bzl",
    "proto.bzl",
    "enclave_unittest.sh",
    "asylo_deps.bzl",
    "install_path.bzl",
    "patch_repository.bzl",
    "sgx_deps.bzl",
])

load("//asylo/bazel:asylo.bzl", "cc_enclave_test")
load("//asylo/bazel:proto.bzl", "asylo_proto_library")

# This tests that gtest can work inside an enclave.
cc_enclave_test(
    name = "gtest_test",
    srcs = ["gtest_test.cc"],
    tags = ["regression"],
    deps = [
        "@com_google_googletest//:gtest",
    ],
)

# Used to pass configuration from test_shim_loader to test_shim_enclave.
asylo_proto_library(
    name = "test_shim_enclave_proto",
    srcs = ["test_shim_enclave.proto"],
    deps = ["//asylo:enclave_proto"],
)

# Used by the cc_enclave_test rule to create enclaves that run gtest test
# suites. Should not typically be used directly.
cc_library(
    name = "test_shim_enclave",
    testonly = 1,
    srcs = ["test_shim_enclave.cc"],
    visibility = ["//visibility:public"],
    deps = [
        ":test_shim_enclave_proto_cc",
        "//asylo/test/util:enclave_test_application",
        "//asylo/test/util:test_flags",
        "@com_google_googletest//:gtest",
    ],
)

# Used by the cc_enclave_test rule to execute gtest test suites inside enclaves.
# Should not typically be used directly.
cc_test(
    name = "test_shim_loader",
    srcs = ["test_shim_loader.cc"],
    linkstatic = True,
    visibility = ["//visibility:public"],
    deps = [
        ":test_shim_enclave_proto_cc",
        "//asylo:enclave_client",
        "//asylo/test/util:test_flags",
        "//asylo/util:logging",
        "@com_github_gflags_gflags//:gflags_nothreads",
    ],
)

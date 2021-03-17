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

# BUILD file needed to make bzl files available to load.

load("@bazel_skylib//:bzl_library.bzl", "bzl_library")
load("@rules_cc//cc:defs.bzl", "cc_binary", "cc_library", "cc_proto_library")
load("@rules_proto//proto:defs.bzl", "proto_library")
load(
    "//asylo/bazel:asylo.bzl",
    "ASYLO_ALL_BACKENDS",
    "ASYLO_ALL_BACKEND_TAGS",
    "cc_enclave_test",
    "embed_enclaves",
)
load("//asylo/bazel:copts.bzl", "ASYLO_DEFAULT_COPTS")

licenses(["notice"])

exports_files([
    "asylo.bzl",
    "asylo_deps.bzl",
    "copts.bzl",
    "dlopen_enclave.bzl",
    "installation_path.bzl",
    "passing_test.sh",
    "remote_deps.bzl",
    "sgx_deps.bzl",
    "sgx_rules.bzl",
])

exports_files(
    [
        "asylo_copy_from_host.bzl",
        "asylo_internal.bzl",
        "asylo_transitions.bzl",
    ],
    visibility = ["//asylo/docs:__pkg__"],
)

# This tests that gtest can work inside an enclave.
cc_enclave_test(
    name = "gtest_test",
    srcs = ["gtest_test.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        "@com_google_googletest//:gtest",
    ],
)

# Used to pass configuration from test_shim_loader to test_shim_enclave.
proto_library(
    name = "test_shim_enclave_proto",
    srcs = ["test_shim_enclave.proto"],
    deps = ["//asylo:enclave_proto"],
)

cc_proto_library(
    name = "test_shim_enclave_cc_proto",
    deps = [":test_shim_enclave_proto"],
)

# Used by the cc_enclave_test rule to create enclaves that run gtest test
# suites. Should not typically be used directly.
cc_library(
    name = "test_shim_enclave",
    testonly = 1,
    srcs = ["test_shim_enclave.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    tags = ASYLO_ALL_BACKEND_TAGS,
    visibility = ["//visibility:public"],
    deps = [
        ":test_shim_enclave_cc_proto",
        "//asylo/test/util:enclave_test_application",
        "//asylo/test/util:test_flags",
        "@com_github_google_benchmark//:benchmark",
        "@com_google_absl//absl/flags:flag",
        "@com_google_absl//absl/status",
        "@com_google_googletest//:gtest",
    ],
    alwayslink = 1,
)

# Used by the cc_enclave_test rule to execute gtest test suites inside enclaves.
# Should not typically be used directly.
cc_binary(
    name = "test_shim_loader",
    testonly = 1,
    srcs = ["test_shim_loader.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    linkstatic = True,
    visibility = ["//visibility:public"],
    deps = [
        ":test_shim_enclave_cc_proto",
        "//asylo:enclave_cc_proto",
        "//asylo:enclave_client",
        "//asylo/platform/primitives/sgx:loader_cc_proto",
        "//asylo/test/util:test_flags",
        "//asylo/util:logging",
        "@com_google_absl//absl/flags:flag",
        "@com_google_absl//absl/flags:parse",
        "@com_google_googletest//:gtest",
    ],
)

EMBED_ENCLAVES_TEST_SECTION = "foo_section"

# A rule to embed an "enclave" (really a text file) in
# embed_enclaves_test_binary_plain.
embed_enclaves(
    name = "embed_enclaves_test_binary",
    elf_file = "//asylo/test/util:test_binary",
    enclaves = {EMBED_ENCLAVES_TEST_SECTION: "//asylo/test/util:sample_text"},
    executable = 1,
)

# A test of embed_enclaves.
sh_test(
    name = "embed_enclaves_test",
    srcs = ["embed_enclaves_test.sh"],
    args = [
        "$(OBJCOPY)",
        "$(location :embed_enclaves_test_binary)",
        EMBED_ENCLAVES_TEST_SECTION,
        "$(location //asylo/test/util:sample_text)",
    ],
    data = [
        ":embed_enclaves_test_binary",
        "//asylo/test/util:sample_text",
    ],
    toolchains = ["@bazel_tools//tools/cpp:current_cc_toolchain"],
    deps = ["//asylo/test/util:shell_testing"],
)

bzl_library(
    name = "dlopen_enclave_bzl",
    srcs = ["dlopen_enclave.bzl"],
    visibility = ["//asylo:implementation"],
)

bzl_library(
    name = "asylo_bzl",
    srcs = ["asylo.bzl"],
    visibility = ["//asylo:implementation"],
)

bzl_library(
    name = "installation_path_bzl",
    srcs = ["installation_path.bzl"],
    visibility = ["//asylo:implementation"],
)

bzl_library(
    name = "asylo_copy_from_host_bzl",
    srcs = ["asylo_copy_from_host.bzl"],
    visibility = ["//asylo:implementation"],
)

bzl_library(
    name = "asylo_transitions_bzl",
    srcs = ["asylo_transitions.bzl"],
    visibility = ["//asylo:implementation"],
)

bzl_library(
    name = "asylo_internal_bzl",
    srcs = ["asylo_internal.bzl"],
    visibility = ["//asylo:implementation"],
)

bzl_library(
    name = "asylo_deps_bzl",
    srcs = ["asylo_deps.bzl"],
    visibility = ["//asylo:implementation"],
)

bzl_library(
    name = "remote_deps_bzl",
    srcs = ["remote_deps.bzl"],
    visibility = ["//asylo:implementation"],
)

bzl_library(
    name = "sgx_rules_bzl",
    srcs = ["sgx_rules.bzl"],
    visibility = ["//asylo:implementation"],
)

bzl_library(
    name = "java_deps_bzl",
    srcs = ["java_deps.bzl"],
    visibility = ["//asylo:implementation"],
)

bzl_library(
    name = "copts_bzl",
    srcs = ["copts.bzl"],
    visibility = ["//asylo:implementation"],
)

bzl_library(
    name = "sgx_deps_bzl",
    srcs = ["sgx_deps.bzl"],
    visibility = ["//asylo:implementation"],
)

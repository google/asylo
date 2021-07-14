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
load("//asylo/bazel:asylo.bzl", "cc_enclave_test", "cc_test", "embed_enclaves")
load("//asylo/bazel:copts.bzl", "ASYLO_DEFAULT_COPTS")
load("//asylo/bazel:dlopen_enclave.bzl", "dlopen_enclave_test")

licenses(["notice"])  # Apache v2.0

# Common utilities for trusted and untrusted targets.

# Defines ASYLO macros.
cc_library(
    name = "asylo_macros",
    hdrs = ["asylo_macros.h"],
    copts = ASYLO_DEFAULT_COPTS,
    visibility = ["//asylo:implementation"],
)

# Implementation of binary search over size_t.
cc_library(
    name = "binary_search",
    hdrs = ["binary_search.h"],
    copts = ASYLO_DEFAULT_COPTS,
    visibility = ["//asylo:implementation"],
    deps = [
        ":function_traits",
    ],
)

cc_test(
    name = "binary_search_test",
    srcs = ["binary_search_test.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    enclave_test_name = "binary_search_enclave_test",
    deps = [
        ":binary_search",
        "//asylo/test/util:test_main",
        "@com_google_googletest//:gtest",
    ],
)

# A library for cleanup objects.
cc_library(
    name = "cleanup",
    hdrs = ["cleanup.h"],
    copts = ASYLO_DEFAULT_COPTS,
    visibility = ["//visibility:public"],
)

cc_test(
    name = "cleanup_test",
    srcs = ["cleanup_test.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    enclave_test_name = "cleanup_enclave_test",
    deps = [
        ":cleanup",
        "//asylo/test/util:test_main",
        "@com_google_googletest//:gtest",
    ],
)

# Utility for reading ELF files.
cc_library(
    name = "elf_reader",
    srcs = ["elf_reader.cc"],
    hdrs = ["elf_reader.h"],
    copts = ASYLO_DEFAULT_COPTS,
    visibility = ["//asylo:implementation"],
    deps = [
        ":status",
        "@com_google_absl//absl/container:flat_hash_map",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/types:optional",
        "@com_google_absl//absl/types:span",
    ],
)

# Embedded section to view in ElfReader unit test.
ELF_READER_TEST_SECTION = "foo_section"

embed_enclaves(
    name = "elf_reader_test_binary",
    elf_file = "//asylo/test/util:test_binary",
    enclaves = {ELF_READER_TEST_SECTION: "//asylo/test/util:sample_text"},
    executable = 1,
)

cc_test(
    name = "elf_reader_test",
    srcs = ["elf_reader_test.cc"],
    args = [
        "--elf_file",
        "$(location :elf_reader_test_binary)",
        "--section_name",
        "%s" % ELF_READER_TEST_SECTION,
        "--expected_contents",
        "$(location //asylo/test/util:sample_text)",
    ],
    copts = ASYLO_DEFAULT_COPTS,
    data = [
        ":elf_reader_test_binary",
        "//asylo/test/util:sample_text",
    ],
    deps = [
        ":elf_reader",
        ":file_mapping",
        "//asylo/test/util:status_matchers",
        "//asylo/test/util:test_main",
        "//asylo/util:logging",
        "@com_google_absl//absl/flags:flag",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/types:span",
        "@com_google_googletest//:gtest",
    ],
)

# A library of utilities for working with POSIX file descriptors.
cc_library(
    name = "fd_utils",
    srcs = ["fd_utils.cc"],
    hdrs = ["fd_utils.h"],
    copts = ASYLO_DEFAULT_COPTS,
    visibility = ["//asylo:implementation"],
    deps = [
        ":posix_errors",
        ":status",
        "//asylo/util:logging",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/time",
    ],
)

cc_test(
    name = "fd_utils_test",
    srcs = ["fd_utils_test.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    enclave_test_name = "fd_utils_enclave_test",
    deps = [
        ":fd_utils",
        "//asylo/test/util:status_matchers",
        "//asylo/test/util:test_main",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/synchronization",
        "@com_google_absl//absl/time",
        "@com_google_googletest//:gtest",
    ],
)

# A library for memory-mapping files.
cc_library(
    name = "file_mapping",
    srcs = ["file_mapping.cc"],
    hdrs = ["file_mapping.h"],
    copts = ASYLO_DEFAULT_COPTS,
    visibility = ["//asylo:implementation"],
    deps = [
        ":cleanup",
        ":posix_errors",
        ":status",
        "//asylo/util:logging",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/types:span",
    ],
)

cc_test(
    name = "file_mapping_test",
    srcs = ["file_mapping_test.cc"],
    args = [
        "--test_file",
        "$(location //asylo/test/util:sample_text)",
    ],
    copts = ASYLO_DEFAULT_COPTS,
    data = ["//asylo/test/util:sample_text"],
    deps = [
        ":file_mapping",
        ":status",
        "//asylo/test/util:status_matchers",
        "//asylo/test/util:test_main",
        "@com_google_absl//absl/flags:flag",
        "@com_google_absl//absl/strings",
        "@com_google_googletest//:gtest",
    ],
)

# A deleter struct that wraps a C function.
cc_library(
    name = "function_deleter",
    hdrs = ["function_deleter.h"],
    copts = ASYLO_DEFAULT_COPTS,
    visibility = ["//asylo:implementation"],
)

cc_test(
    name = "function_deleter_test",
    srcs = ["function_deleter_test.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    enclave_test_name = "function_deleter_enclave_test",
    deps = [
        ":function_deleter",
        "//asylo/test/util:test_main",
        "@com_google_absl//absl/base:core_headers",
        "@com_google_googletest//:gtest",
    ],
)

# Type checking for anonymous functions.
cc_library(
    name = "function_traits",
    hdrs = ["function_traits.h"],
    copts = ASYLO_DEFAULT_COPTS,
)

cc_test(
    name = "function_traits_test",
    srcs = ["function_traits_test.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":function_traits",
        "//asylo/test/util:test_main",
        "@com_google_googletest//:gtest",
    ],
)

# Minimal logging library implementation.
cc_library(
    name = "logging",
    srcs = ["logging.cc"],
    hdrs = ["logging.h"],
    copts = ASYLO_DEFAULT_COPTS,
    visibility = ["//visibility:public"],
    deps = ["@com_google_absl//absl/base:core_headers"],
)

cc_library(
    name = "mutex_guarded",
    hdrs = ["mutex_guarded.h"],
    copts = ASYLO_DEFAULT_COPTS,
    visibility = ["//visibility:public"],
    deps = [
        "@com_google_absl//absl/base:core_headers",
        "@com_google_absl//absl/synchronization",
        "@com_google_absl//absl/time",
        "@com_google_absl//absl/types:optional",
    ],
)

cc_test(
    name = "mutex_guarded_test",
    srcs = ["mutex_guarded_test.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":mutex_guarded",
        "//asylo/test/util:test_main",
        "@com_google_absl//absl/memory",
        "@com_google_absl//absl/synchronization",
        "@com_google_absl//absl/time",
        "@com_google_googletest//:gtest",
    ],
)

cc_library(
    name = "error_codes",
    hdrs = ["error_codes.h"],
    copts = ASYLO_DEFAULT_COPTS,
    visibility = ["//asylo:implementation"],
)

cc_library(
    name = "status_macros",
    hdrs = ["status_macros.h"],
    copts = ASYLO_DEFAULT_COPTS,
    visibility = ["//visibility:public"],
    deps = [
        "@com_google_absl//absl/base:core_headers",
        "@com_google_absl//absl/status",
    ],
)

cc_library(
    name = "status",
    srcs = [
        "error_codes.h",
        "error_space.cc",
        "error_space.h",
        "posix_error_space.cc",
        "status.cc",
        "status_error_space.cc",
        "status_error_space.h",
        "status_internal.h",
        "statusor.cc",
    ],
    hdrs = [
        "posix_error_space.h",
        "status.h",
        "status_macros.h",
        "statusor.h",
    ],
    copts = ASYLO_DEFAULT_COPTS,
    visibility = ["//visibility:public"],
    deps = [
        ":cleanup",
        ":status_cc_proto",
        "//asylo/platform/common:static_map",
        "//asylo/util:logging",
        "@com_google_absl//absl/base:config",
        "@com_google_absl//absl/base:core_headers",
        "@com_google_absl//absl/container:flat_hash_map",
        "@com_google_absl//absl/meta:type_traits",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/status:statusor",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/strings:cord",
        "@com_google_absl//absl/strings:str_format",
        "@com_google_absl//absl/types:optional",
    ],
)

# Tests for the Status utility.
cc_test(
    name = "status_test",
    srcs = ["status_test.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    enclave_test_name = "status_enclave_test",
    deps = [
        ":error_codes",
        ":status",
        "//asylo/test/util:status_matchers",
        "//asylo/test/util:test_main",
        "@com_github_grpc_grpc//:grpc++",
        "@com_github_grpc_grpc//:grpc++_codegen_base",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/status:statusor",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/strings:cord",
        "@com_google_absl//absl/types:optional",
        "@com_google_googletest//:gtest",
        "@com_google_protobuf//:protobuf_lite",
    ],
)

# Tests for the StatusOr template class.
cc_test(
    name = "statusor_test",
    srcs = [
        "error_codes.h",
        "error_space.h",
        "status_error_space.h",
        "statusor_test.cc",
    ],
    copts = ASYLO_DEFAULT_COPTS,
    enclave_test_name = "statusor_enclave_test",
    deps = [
        ":status",
        "//asylo/platform/common:static_map",
        "//asylo/test/util:status_matchers",
        "//asylo/test/util:test_main",
        "@com_google_absl//absl/base:config",
        "@com_google_absl//absl/base:core_headers",
        "@com_google_absl//absl/container:flat_hash_map",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/status:statusor",
        "@com_google_absl//absl/strings:str_format",
        "@com_google_googletest//:gtest",
    ],
)

# Tests for the Status macros.
cc_test(
    name = "status_macros_test",
    srcs = ["status_macros_test.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":status",
        "//asylo/test/util:status_matchers",
        "//asylo/test/util:test_main",
        "@com_google_absl//absl/memory",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/strings",
        "@com_google_googletest//:gtest",
    ],
)

cc_library(
    name = "status_helpers",
    srcs = [
        "status_helpers.cc",
        "status_helpers_internal.h",
    ],
    hdrs = ["status_helpers.h"],
    copts = ASYLO_DEFAULT_COPTS,
    visibility = ["//visibility:public"],
    deps = [
        ":status",
        ":status_cc_proto",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/strings:cord",
        "@com_google_absl//absl/types:optional",
        "@com_google_protobuf//:protobuf",
    ],
)

cc_test(
    name = "status_helpers_test",
    srcs = ["status_helpers_test.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    enclave_test_name = "status_helpers_enclave_test",
    deps = [
        ":error_codes",
        ":status",
        ":status_helpers",
        "//asylo:enclave_cc_proto",
        "//asylo/platform/primitives/sgx:sgx_errors",
        "//asylo/test/util:proto_matchers",
        "//asylo/test/util:status_matchers",
        "//asylo/test/util:test_main",
        "@com_github_grpc_grpc//:grpc++",
        "@com_github_grpc_grpc//:grpc++_codegen_base",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/strings:cord",
        "@com_google_absl//absl/types:optional",
        "@com_google_googletest//:gtest",
        "@com_google_protobuf//:protobuf",
        "@com_google_protobuf//:protobuf_lite",
        "@linux_sgx//:public",
    ],
)

# Container types that zero-out memory before freeing resources.
cc_library(
    name = "cleansing_types",
    hdrs = [
        "cleansing_allocator.h",
        "cleansing_types.h",
    ],
    copts = ASYLO_DEFAULT_COPTS,
    visibility = ["//visibility:public"],
    deps = ["@boringssl//:crypto"],
)

cc_test(
    name = "cleansing_allocator_test",
    srcs = [
        "cleansing_allocator.h",
        "cleansing_allocator_test.cc",
    ],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        "//asylo/crypto/util:bytes",
        "//asylo/crypto/util:trivial_object_util",
        "//asylo/test/util:test_main",
        "@boringssl//:crypto",
        "@com_google_googletest//:gtest",
    ],
)

# Tests for Google canonical error space.
cc_test(
    name = "error_space_test",
    srcs = [
        "error_codes.h",
        "error_space.h",
        "error_space_test.cc",
    ],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":status",
        "//asylo/platform/common:static_map",
        "//asylo/test/util:test_main",
        "@com_google_absl//absl/container:flat_hash_map",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/strings:str_format",
        "@com_google_googletest//:gtest",
    ],
)

# Tests for Posix error space.
cc_test(
    name = "posix_error_space_test",
    srcs = ["posix_error_space_test.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":status",
        "//asylo/test/util:test_main",
        "@com_google_absl//absl/strings:str_format",
        "@com_google_googletest//:gtest",
    ],
)

cc_library(
    name = "posix_error_matchers",
    testonly = 1,
    srcs = ["posix_error_matchers.cc"],
    hdrs = ["posix_error_matchers.h"],
    copts = ASYLO_DEFAULT_COPTS,
    visibility = ["//visibility:public"],
    deps = [
        ":posix_errors",
        ":status",
        "//asylo/test/util:status_matchers",
        "@com_google_googletest//:gtest",
    ],
)

cc_library(
    name = "posix_errors",
    srcs = ["posix_errors.cc"],
    hdrs = ["posix_errors.h"],
    copts = ASYLO_DEFAULT_COPTS,
    visibility = ["//visibility:public"],
    deps = [
        ":status",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/strings:str_format",
    ],
)

cc_test(
    name = "posix_errors_test",
    srcs = ["posix_errors_test.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    enclave_test_name = "posix_errors_enclave_test",
    deps = [
        ":posix_error_matchers",
        ":posix_errors",
        ":status",
        "//asylo/test/util:status_matchers",
        "//asylo/test/util:test_main",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/strings",
        "@com_google_googletest//:gtest",
    ],
)

cc_library(
    name = "proto_enum_util",
    hdrs = ["proto_enum_util.h"],
    copts = ASYLO_DEFAULT_COPTS,
    visibility = ["//asylo:implementation"],
    deps = [
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/strings:str_format",
        "@com_google_protobuf//:protobuf",
    ],
)

proto_library(
    name = "proto_enum_util_test_proto",
    testonly = 1,
    srcs = ["proto_enum_util_test.proto"],
)

cc_proto_library(
    name = "proto_enum_util_test_cc_proto",
    testonly = 1,
    deps = ["proto_enum_util_test_proto"],
)

cc_test(
    name = "proto_enum_util_test",
    srcs = ["proto_enum_util_test.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    enclave_test_name = "proto_enum_util_enclave_test",
    deps = [
        ":proto_enum_util",
        ":proto_enum_util_test_cc_proto",
        "//asylo/test/util:test_main",
        "@com_google_googletest//:gtest",
    ],
)

cc_library(
    name = "proto_flag",
    hdrs = ["proto_flag.h"],
    copts = ASYLO_DEFAULT_COPTS,
    visibility = ["//visibility:public"],
    deps = [
        "//asylo/util:logging",
        "@com_google_absl//absl/strings",
        "@com_google_protobuf//:protobuf",
    ],
)

cc_test(
    name = "proto_flag_test",
    srcs = ["proto_flag_test.cc"],
    args = ["--my_test_flag=\"name: 'foo' value: 'bar'\""],
    deps = [
        ":proto_flag",
        ":proto_parse_util",
        "//asylo:enclave_cc_proto",
        "//asylo/test/util:proto_matchers",
        "//asylo/test/util:test_main",
        "@com_google_absl//absl/flags:flag",
        "@com_google_absl//absl/flags:parse",
        "@com_google_googletest//:gtest",
    ],
)

cc_library(
    name = "proto_parse_util",
    hdrs = ["proto_parse_util.h"],
    copts = ASYLO_DEFAULT_COPTS,
    visibility = ["//asylo:implementation"],
    deps = [
        ":status",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/strings",
        "@com_google_protobuf//:protobuf",
    ],
)

proto_library(
    name = "proto_parse_util_test_proto",
    testonly = 1,
    srcs = ["proto_parse_util_test.proto"],
)

cc_proto_library(
    name = "proto_parse_util_test_cc_proto",
    testonly = 1,
    deps = ["proto_parse_util_test_proto"],
)

cc_test(
    name = "proto_parse_util_test",
    srcs = ["proto_parse_util_test.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    enclave_test_name = "proto_parse_util_enclave_test",
    deps = [
        ":proto_parse_util",
        ":proto_parse_util_test_cc_proto",
        ":status",
        "//asylo/test/util:proto_matchers",
        "//asylo/test/util:status_matchers",
        "//asylo/test/util:test_main",
        "@com_google_absl//absl/status",
        "@com_google_googletest//:gtest",
    ],
)

# A library to help with the google.protobuf.Value representation of JSON.
cc_library(
    name = "proto_struct_util",
    srcs = ["proto_struct_util.cc"],
    hdrs = ["proto_struct_util.h"],
    copts = ASYLO_DEFAULT_COPTS,
    visibility = ["//asylo:implementation"],
    deps = [
        ":status",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/strings",
        "@com_google_protobuf//:protobuf",
    ],
)

# Tests for proto struct utilities.
cc_test(
    name = "proto_struct_util_test",
    srcs = ["proto_struct_util_test.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    enclave_test_name = "proto_struct_util_enclave_test",
    deps = [
        ":proto_struct_util",
        ":status",
        "//asylo/test/util:proto_matchers",
        "//asylo/test/util:status_matchers",
        "//asylo/test/util:test_main",
        "@com_google_absl//absl/status",
        "@com_google_googletest//:gtest",
        "@com_google_protobuf//:protobuf",
    ],
)

# Protobuf representation for asylo::Status.
proto_library(
    name = "status_proto",
    srcs = ["status.proto"],
    visibility = ["//visibility:public"],
)

cc_proto_library(
    name = "status_cc_proto",
    visibility = ["//visibility:public"],
    deps = [":status_proto"],
)

# Library for manipulating file paths.
cc_library(
    name = "path",
    srcs = ["path.cc"],
    hdrs = ["path.h"],
    copts = ASYLO_DEFAULT_COPTS,
    visibility = ["//visibility:public"],
    deps = ["@com_google_absl//absl/strings"],
)

# Test for the path library.
cc_test(
    name = "path_test",
    srcs = ["path_test.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    enclave_test_name = "path_enclave_test",
    deps = [
        ":path",
        "//asylo/test/util:test_main",
        "@com_google_googletest//:gtest",
    ],
)

# A library that implements asylo::Thread
cc_library(
    name = "thread",
    srcs = ["std_thread.h"],
    hdrs = ["thread.h"],
    copts = ASYLO_DEFAULT_COPTS,
    visibility = ["//visibility:public"],
    deps =
        [
            "//asylo/util:logging",
        ],
)

cc_test(
    name = "thread_test",
    srcs = ["thread_test.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":mutex_guarded",
        ":thread",
        "//asylo/test/util:test_main",
        "@com_google_absl//absl/container:flat_hash_set",
        "@com_google_absl//absl/synchronization",
        "@com_google_absl//absl/time",
        "@com_google_googletest//:gtest",
    ],
)

dlopen_enclave_test(
    name = "primitives_thread_test",
    srcs = ["thread_test.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":mutex_guarded",
        ":thread",
        "//asylo/test/util:test_main",
        "@com_google_absl//absl/container:flat_hash_set",
        "@com_google_absl//absl/synchronization",
        "@com_google_absl//absl/time",
        "@com_google_googletest//:gtest",
    ],
)

cc_library(
    name = "hex_util",
    srcs = ["hex_util.cc"],
    hdrs = ["hex_util.h"],
    copts = ASYLO_DEFAULT_COPTS,
    visibility = ["//asylo:implementation"],
    deps = ["@com_google_absl//absl/strings"],
)

cc_test(
    name = "hex_util_test",
    srcs = ["hex_util_test.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    enclave_test_name = "hex_util_enclave_test",
    deps = [
        ":hex_util",
        "//asylo/test/util:test_main",
        "@com_google_googletest//:gtest",
    ],
)

cc_library(
    name = "http_fetcher",
    hdrs = ["http_fetcher.h"],
    copts = ASYLO_DEFAULT_COPTS,
    visibility = ["//asylo:implementation"],
    deps = [
        ":status",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/types:optional",
    ],
)

cc_library(
    name = "http_fetcher_impl",
    srcs = ["http_fetcher_impl.cc"],
    hdrs = ["http_fetcher_impl.h"],
    copts = ASYLO_DEFAULT_COPTS,
    visibility = ["//asylo:implementation"],
    deps = [
        ":cleanup",
        ":function_deleter",
        ":http_fetcher",
        ":status",
        "@com_github_curl_curl//:curl",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/strings:str_format",
        "@com_googlesource_code_re2//:re2",
    ],
)

cc_test(
    name = "http_fetcher_impl_test",
    srcs = ["http_fetcher_impl_test.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":http_fetcher_impl",
        ":status",
        "//asylo/test/util:status_matchers",
        "//asylo/test/util:test_main",
        "@com_github_curl_curl//:curl",
        "@com_google_absl//absl/container:flat_hash_set",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/types:optional",
        "@com_google_googletest//:gtest",
    ],
)

cc_library(
    name = "time_conversions",
    srcs = [
        "time_conversions_internal.cc",
        "time_conversions_internal.h",
    ],
    hdrs = ["time_conversions.h"],
    copts = ASYLO_DEFAULT_COPTS,
    visibility = ["//asylo:implementation"],
    deps = [
        ":status",
        "@com_github_grpc_grpc//:gpr",
        "@com_github_grpc_grpc//:gpr_codegen",
        "@com_github_grpc_grpc//:grpc",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/strings:str_format",
        "@com_google_absl//absl/time",
        "@com_google_absl//absl/types:optional",
        "@com_google_protobuf//:protobuf",
    ],
)

cc_test(
    name = "time_conversions_test",
    srcs = [
        "time_conversions_internal.h",
        "time_conversions_test.cc",
    ],
    copts = ASYLO_DEFAULT_COPTS,
    enclave_test_name = "time_conversions_enclave_test",
    deps = [
        ":binary_search",
        ":status",
        ":time_conversions",
        "//asylo/test/util:proto_matchers",
        "//asylo/test/util:status_matchers",
        "//asylo/test/util:test_main",
        "//asylo/util:logging",
        "@com_github_grpc_grpc//:gpr",
        "@com_github_grpc_grpc//:gpr_codegen",
        "@com_github_grpc_grpc//:grpc",
        "@com_google_absl//absl/container:flat_hash_map",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/strings:str_format",
        "@com_google_absl//absl/time",
        "@com_google_googletest//:gtest",
        "@com_google_protobuf//:protobuf",
    ],
)

cc_library(
    name = "url_util",
    srcs = ["url_util.cc"],
    hdrs = ["url_util.h"],
    copts = ASYLO_DEFAULT_COPTS,
    visibility = ["//asylo:implementation"],
    deps = [
        ":error_codes",
        ":function_deleter",
        ":status",
        "@com_google_absl//absl/strings",
    ] + select({
        # Prevent accidentally inserting libcurl into enclave depedencies.
        "@com_google_asylo//asylo": [],
        "//conditions:default": ["@com_github_curl_curl//:curl"],
    }),
)

cc_test(
    name = "url_util_test",
    srcs = ["url_util_test.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":url_util",
        "//asylo/test/util:status_matchers",
        "//asylo/test/util:test_main",
        "@com_google_googletest//:gtest",
    ],
)

cc_library(
    name = "aligned_object_ptr",
    hdrs = ["aligned_object_ptr.h"],
    copts = ASYLO_DEFAULT_COPTS,
    visibility = ["//asylo:implementation"],
)

cc_test(
    name = "aligned_object_ptr_test",
    srcs = ["aligned_object_ptr_test.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":aligned_object_ptr",
        "//asylo/test/util:test_main",
        "@com_google_absl//absl/base:core_headers",
        "@com_google_absl//absl/container:flat_hash_map",
        "@com_google_googletest//:gtest",
    ],
)

cc_library(
    name = "lock_guard",
    hdrs = ["lock_guard.h"],
    copts = ASYLO_DEFAULT_COPTS,
    visibility = ["//asylo:implementation"],
    deps = [
        ":function_traits",
        "@com_google_absl//absl/base:core_headers",
    ],
)

cc_enclave_test(
    name = "lock_guard_test",
    srcs = ["lock_guard_test.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":lock_guard",
        ":thread",
        "//asylo/platform/core:trusted_mutex",
        "//asylo/platform/core:trusted_spin_lock",
        "@com_google_absl//absl/base:core_headers",
        "@com_google_absl//absl/synchronization",
        "@com_google_googletest//:gtest",
    ],
)

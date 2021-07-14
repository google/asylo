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

load("@com_github_grpc_grpc//bazel:cc_grpc_library.bzl", "cc_grpc_library")
load("@rules_cc//cc:defs.bzl", "cc_library", "cc_proto_library", "cc_test")
load("@rules_proto//proto:defs.bzl", "proto_library")
load("//asylo/bazel:copts.bzl", "ASYLO_DEFAULT_COPTS")
load("//asylo/bazel:dlopen_enclave.bzl", "dlopen_enclave_test")

licenses(["notice"])

package(
    default_visibility = ["//asylo:implementation"],
)

# Enclave loader for remotely loaded enclaves.
cc_library(
    name = "enclave_loader",
    srcs = ["enclave_loader.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        "//asylo:enclave_cc_proto",
        "//asylo/platform/primitives:enclave_loader_hdr",
        "//asylo/platform/primitives:untrusted_primitives",
        "//asylo/platform/primitives/remote:proxy_client",
        "//asylo/platform/primitives/util:dispatch_table",
        "//asylo/platform/primitives/util:exit_log",
        "//asylo/util:status",
        "//asylo/util:status_macros",
        "//asylo/util/remote:remote_loader_cc_proto",
        "//asylo/util/remote:remote_proxy_config",
        "@com_google_absl//absl/memory",
    ],
)

# A full-duplex gRPC Communicator for an Asylo backend proxy, connecting
# a remote client to an enclave proxy server running elsewhere.
proto_library(
    name = "grpc_service_proto",
    srcs = ["grpc_service.proto"],
    deps = [
        "//asylo/util:status_proto",
    ],
)

cc_proto_library(
    name = "grpc_service_cc_proto",
    deps = [":grpc_service_proto"],
)

cc_grpc_library(
    name = "grpc_service",
    srcs = [":grpc_service_proto"],
    grpc_only = True,
    deps = [":grpc_service_cc_proto"],
)

cc_library(
    name = "communicator",
    srcs = [
        "communicator.cc",
        "grpc_client_impl.cc",
        "grpc_server_impl.cc",
    ],
    hdrs = [
        "communicator.h",
        "grpc_client_impl.h",
        "grpc_server_impl.h",
    ],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":grpc_service",
        ":grpc_service_cc_proto",
        "//asylo/platform/primitives",
        "//asylo/platform/primitives:untrusted_primitives",
        "//asylo/platform/primitives/remote/metrics:proc_system_service",
        "//asylo/platform/primitives/remote/metrics/clients:opencensus_client",
        "//asylo/platform/primitives/util:message_reader_writer",
        "//asylo/util:asylo_macros",
        "//asylo/util:cleanup",
        "//asylo/util:logging",
        "//asylo/util:mutex_guarded",
        "//asylo/util:status",
        "//asylo/util:status_helpers",
        "//asylo/util:thread",
        "//asylo/util/remote:remote_loader_cc_proto",
        "//asylo/util/remote:remote_proxy_config",
        "@com_github_grpc_grpc//:grpc++",
        "@com_github_grpc_grpc//:grpc++_codegen_base",
        "@com_google_absl//absl/base:core_headers",
        "@com_google_absl//absl/container:flat_hash_map",
        "@com_google_absl//absl/container:flat_hash_set",
        "@com_google_absl//absl/flags:flag",
        "@com_google_absl//absl/memory",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/synchronization",
        "@com_google_absl//absl/time",
        "@com_google_absl//absl/types:optional",
        "@com_google_absl//absl/types:span",
    ],
)

cc_test(
    name = "communicator_test",
    size = "small",
    srcs = [
        "communicator_test.cc",
    ],
    copts = ASYLO_DEFAULT_COPTS,
    tags = [
        "exclusive",  # test uses gMock on std::threads.
        "notsan",
    ],
    deps = [
        ":communicator",
        "//asylo/platform/primitives",
        "//asylo/test/util:status_matchers",
        "//asylo/util:cleanup",
        "//asylo/util:logging",
        "//asylo/util:mutex_guarded",
        "//asylo/util:status",
        "//asylo/util:thread",
        "//asylo/util/remote:local_provision",
        "//asylo/util/remote:provision",
        "@com_github_grpc_grpc//:grpc++",
        "@com_google_absl//absl/base:core_headers",
        "@com_google_absl//absl/container:flat_hash_set",
        "@com_google_absl//absl/flags:parse",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/synchronization",
        "@com_google_absl//absl/time",
        "@com_google_googletest//:gtest",
        "@io_opencensus_cpp//opencensus/stats",
        "@io_opencensus_cpp//opencensus/tags",
    ],
)

dlopen_enclave_test(
    name = "primitives_communicator_test",
    size = "medium",
    srcs = [
        "communicator_test.cc",
    ],
    copts = ASYLO_DEFAULT_COPTS,
    tags = [
        "asylo-remote",
        "exclusive",  # test uses gMock on std::threads.
        "notsan",
    ],
    deps = [
        ":communicator",
        "//asylo/platform/primitives",
        "//asylo/test/util:status_matchers",
        "//asylo/util:cleanup",
        "//asylo/util:logging",
        "//asylo/util:mutex_guarded",
        "//asylo/util:status",
        "//asylo/util:thread",
        "//asylo/util/remote:local_provision",
        "//asylo/util/remote:provision",
        "@com_github_grpc_grpc//:grpc++",
        "@com_google_absl//absl/base:core_headers",
        "@com_google_absl//absl/container:flat_hash_set",
        "@com_google_absl//absl/flags:parse",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/synchronization",
        "@com_google_absl//absl/time",
        "@com_google_googletest//:gtest",
        "@io_opencensus_cpp//opencensus/stats",
        "@io_opencensus_cpp//opencensus/tags",
    ],
)

# Enclave proxy backend primitives (proxy client and server) that provide
# access to a remotely-loaded enclave.
cc_library(
    name = "proxy_server",
    srcs = [
        "local_exit_calls.cc",
        "local_exit_calls.h",
        "proxy_selectors.h",
        "proxy_server.cc",
    ],
    hdrs = ["proxy_server.h"],
    copts = ASYLO_DEFAULT_COPTS,
    features = ["fully_static_link"],
    linkstatic = True,
    deps = [
        ":communicator",
        "//asylo:enclave_cc_proto",
        "//asylo/platform/host_call:exit_handler_constants",
        "//asylo/platform/host_call:host_call_handlers_util",
        "//asylo/platform/primitives",
        "//asylo/platform/primitives:untrusted_primitives",
        "//asylo/platform/primitives/util:dispatch_table",
        "//asylo/platform/primitives/util:exit_log",
        "//asylo/platform/primitives/util:message_reader_writer",
        "//asylo/platform/system_call/type_conversions:types_definitions",
        "//asylo/util:logging",
        "//asylo/util:status",
        "//asylo/util:thread",
        "//asylo/util/remote:remote_proxy_config",
        "@com_github_grpc_grpc//:grpc++",
        "@com_google_absl//absl/container:flat_hash_map",
        "@com_google_absl//absl/memory",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/types:optional",
    ],
)

cc_library(
    name = "proxy_client",
    srcs = [
        "proxy_client.cc",
        "proxy_selectors.h",
    ],
    hdrs = ["proxy_client.h"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":communicator",
        "//asylo:enclave_cc_proto",
        "//asylo/platform/primitives",
        "//asylo/platform/primitives:untrusted_primitives",
        "//asylo/platform/primitives/dlopen:loader_cc_proto",
        "//asylo/platform/primitives/remote/metrics/clients:opencensus_client",
        "//asylo/platform/primitives/sgx:exit_handlers",
        "//asylo/platform/primitives/sgx:loader_cc_proto",
        "//asylo/platform/primitives/util:message_reader_writer",
        "//asylo/util:logging",
        "//asylo/util:status",
        "//asylo/util/remote:remote_loader_cc_proto",
        "//asylo/util/remote:remote_proxy_config",
        "@com_google_absl//absl/container:flat_hash_map",
        "@com_google_absl//absl/memory",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/strings",
    ],
)

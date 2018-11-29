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

# Socket implementation, tests, and perf measurement tools.

load("@linux_sgx//:sgx_sdk.bzl", "sgx_enclave")
load("//asylo/bazel:asylo.bzl", "enclave_test")
load("//asylo/bazel:copts.bzl", "ASYLO_DEFAULT_COPTS")
load("//asylo/bazel:proto.bzl", "asylo_proto_library")
load(
    "//asylo/bazel:asylo.bzl",
    "cc_test",
)

package(
    default_visibility = ["//asylo:implementation"],
)

# Contains arch-dependent implementations of sockets.
cc_library(
    name = "sockets",
    srcs = [
        "in.cc",
        "inet.cc",
        "netdb.cc",
        "socket.cc",
    ],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        "//asylo/platform/arch:trusted_arch",
        "//asylo/platform/common:memory",
        "//asylo/platform/posix/io:io_manager",
    ],
)

# Contains socket communication class for data transmission.
cc_library(
    name = "socket_transmit",
    srcs = ["socket_transmit.cc"],
    hdrs = ["socket_transmit.h"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        "//asylo/util:logging",
        "//asylo/platform/arch:trusted_arch",
        "//asylo/util:status",
    ] + select({
        "@com_google_asylo//asylo": [
            ":sockets",
        ],
        "//conditions:default": [],
    }),
)

# Contains server class for automated socket tests.
cc_library(
    name = "socket_server",
    srcs = ["socket_server.cc"],
    hdrs = ["socket_server.h"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":socket_transmit",
        "//asylo/util:logging",
        "//asylo/platform/arch:trusted_arch",
        "//asylo/platform/storage/utils:fd_closer",
        "//asylo/util:status",
    ] + select({
        "@com_google_asylo//asylo": [
            ":sockets",
        ],
        "//conditions:default": [],
    }),
)

# Contains client class for automated socket tests.
cc_library(
    name = "socket_client",
    srcs = ["socket_client.cc"],
    hdrs = ["socket_client.h"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":socket_transmit",
        "//asylo/util:logging",
        "//asylo/platform/arch:trusted_arch",
        "//asylo/platform/storage/utils:fd_closer",
        "//asylo/util:status",
    ] + select({
        "@com_google_asylo//asylo": [
            ":sockets",
        ],
        "//conditions:default": [],
    }),
)

# Contains constants and client/server transmit functions for socket tests.
cc_library(
    name = "socket_test_transmit",
    srcs = ["socket_test_transmit.cc"],
    hdrs = ["socket_test_transmit.h"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":socket_client",
        ":socket_server",
        "//asylo/util:status",
    ],
)

# Extension of EnclaveInput proto for socket tests.
asylo_proto_library(
    name = "socket_test_proto",
    srcs = ["socket_test.proto"],
    deps = ["//asylo:enclave_proto"],
)

# Enclave for UNIX domain-socket test.
sgx_enclave(
    name = "domain_socket_test_enclave.so",
    srcs = ["domain_socket_test_enclave.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":socket_client",
        ":socket_server",
        ":socket_test_proto_cc",
        ":socket_test_transmit",
        "//asylo/test/util:enclave_test_application",
        "//asylo/util:logging",
    ],
)

# Driver for UNIX domain-socket test.
enclave_test(
    name = "domain_socket_test",
    srcs = ["domain_socket_test_driver.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    enclaves = {"enclave": ":domain_socket_test_enclave.so"},
    test_args = ["--enclave_path='{enclave}'"],
    deps = [
        ":socket_client",
        ":socket_server",
        ":socket_test_proto_cc",
        ":socket_test_transmit",
        "//asylo:enclave_client",
        "//asylo/platform/arch:trusted_arch",
        "//asylo/test/util:enclave_test",
        "//asylo/test/util:status_matchers",
        "//asylo/test/util:test_flags",
        "//asylo/test/util:test_main",
        "//asylo/util:logging",
        "@com_github_gflags_gflags//:gflags_nothreads",
        "@com_google_googletest//:gtest",
    ],
)

# Enclave for INET6 socket test.
sgx_enclave(
    name = "inet6_socket_test_enclave.so",
    srcs = ["inet6_socket_test_enclave.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":socket_client",
        ":socket_server",
        ":socket_test_proto_cc",
        ":socket_test_transmit",
        "//asylo/test/util:enclave_test_application",
        "//asylo/util:logging",
    ],
)

# Driver for INET6 socket test.
enclave_test(
    name = "inet6_socket_test",
    srcs = ["inet6_socket_test_driver.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    enclaves = {"enclave": ":inet6_socket_test_enclave.so"},
    test_args = ["--enclave_path='{enclave}'"],
    deps = [
        ":socket_client",
        ":socket_server",
        ":socket_test_proto_cc",
        ":socket_test_transmit",
        "//asylo:enclave_client",
        "//asylo/platform/arch:trusted_arch",
        "//asylo/test/util:enclave_test",
        "//asylo/test/util:status_matchers",
        "//asylo/test/util:test_main",
        "@com_google_googletest//:gtest",
    ],
)

# Enclave for getaddrinfo and freeaddrinfo tests.
sgx_enclave(
    name = "addrinfo_test_enclave.so",
    srcs = ["addrinfo_test_enclave.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":socket_test_proto_cc",
        "//asylo/test/util:enclave_test_application",
    ],
)

# Driver for getaddrinfo and freeaddrinfo tests.
enclave_test(
    name = "addrinfo_test",
    srcs = ["addrinfo_test_driver.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    enclaves = {"enclave": ":addrinfo_test_enclave.so"},
    test_args = ["--enclave_path='{enclave}'"],
    deps = [
        ":socket_test_proto_cc",
        "//asylo/test/util:enclave_test",
        "//asylo/test/util:status_matchers",
        "//asylo/test/util:test_main",
        "@com_google_googletest//:gtest",
    ],
)

cc_test(
    name = "inet_pton_test",
    srcs = ["inet_pton_test.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    enclave_test_name = "inet_pton_enclave_test",
    deps = [
        "//asylo/test/util:test_main",
        "@com_google_googletest//:gtest",
    ],
)

cc_test(
    name = "inet_aton_test",
    srcs = ["inet_aton_test.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    enclave_test_name = "inet_aton_enclave_test",
    deps = [
        "//asylo/test/util:test_main",
        "@com_google_googletest//:gtest",
    ],
)

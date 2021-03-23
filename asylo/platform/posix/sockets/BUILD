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

# Socket implementation, tests, and perf measurement tools.

load("@rules_cc//cc:defs.bzl", "cc_library", "cc_proto_library")
load("@rules_proto//proto:defs.bzl", "proto_library")
load(
    "//asylo/bazel:asylo.bzl",
    "ASYLO_ALL_BACKEND_TAGS",
    "cc_test",
    "cc_unsigned_enclave",
    "debug_sign_enclave",
    "enclave_test",
)
load("//asylo/bazel:copts.bzl", "ASYLO_DEFAULT_COPTS")

licenses(["notice"])

package(
    default_visibility = ["//asylo:implementation"],
)

# Contains arch-dependent implementations of sockets.
cc_library(
    name = "sockets",
    srcs = [
        "in.cc",
        "socket.cc",
    ],
    copts = ASYLO_DEFAULT_COPTS,
    tags = ASYLO_ALL_BACKEND_TAGS,
    deps = [
        ":backend_independent_sockets",
        "//asylo/platform/common:memory",
        "//asylo/platform/posix/io:io_manager",
    ],
    alwayslink = 1,
)

# Contains backend independent implementations of sockets. This is required to
# distinguish backend dependent (unmigrated) and backend independent (migrated)
# cc files in sockets library. This library can be used for providing backend
# independent posix implementations for backends requiring one, or by higher level
# libraries like backend_independent_posix. This is expected to be removed if/when
# sockets cc_library does not rely on backend dependent trusted_arch anymore.
cc_library(
    name = "backend_independent_sockets",
    srcs = [
        "inet.cc",
        "netdb.cc",
    ],
    copts = ASYLO_DEFAULT_COPTS,
    tags = ASYLO_ALL_BACKEND_TAGS,
    deps = [
        "//asylo/platform/host_call",
    ],
    alwayslink = 1,
)

# Contains socket communication class for data transmission.
cc_library(
    name = "socket_transmit",
    srcs = ["socket_transmit.cc"],
    hdrs = ["socket_transmit.h"],
    copts = ASYLO_DEFAULT_COPTS,
    tags = ASYLO_ALL_BACKEND_TAGS,
    deps = [
        "@com_google_absl//absl/status",
        "//asylo/util:posix_errors",
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
    tags = ASYLO_ALL_BACKEND_TAGS,
    deps = [
        ":socket_transmit",
        "@com_google_absl//absl/status",
        "//asylo/util:logging",
        "//asylo/platform/storage/utils:fd_closer",
        "//asylo/util:posix_errors",
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
    tags = ASYLO_ALL_BACKEND_TAGS,
    deps = [
        ":socket_transmit",
        "@com_google_absl//absl/status",
        "//asylo/util:logging",
        "//asylo/platform/storage/utils:fd_closer",
        "//asylo/util:posix_errors",
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
        "@com_google_absl//absl/base:core_headers",
        "@com_google_absl//absl/status",
    ],
)

# Extension of EnclaveInput proto for socket tests.
proto_library(
    name = "socket_test_proto",
    srcs = ["socket_test.proto"],
    deps = ["//asylo:enclave_proto"],
)

cc_proto_library(
    name = "socket_test_cc_proto",
    deps = ["socket_test_proto"],
)

# Enclave for UNIX domain-socket test.
cc_unsigned_enclave(
    name = "domain_socket_test_enclave_unsigned.so",
    srcs = ["domain_socket_test_enclave.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":socket_client",
        ":socket_server",
        ":socket_test_cc_proto",
        ":socket_test_transmit",
        "//asylo/test/util:enclave_test_application",
        "//asylo/util:logging",
    ],
)

debug_sign_enclave(
    name = "domain_socket_test_enclave.so",
    unsigned = "domain_socket_test_enclave_unsigned.so",
)

# Driver for UNIX domain-socket test.
enclave_test(
    name = "domain_socket_test",
    size = "small",
    srcs = ["domain_socket_test_driver.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    enclaves = {"enclave": ":domain_socket_test_enclave.so"},
    test_args = ["--enclave_path='{enclave}'"],
    deps = [
        ":socket_client",
        ":socket_server",
        ":socket_test_cc_proto",
        ":socket_test_transmit",
        "//asylo:enclave_client",
        "//asylo/test/util:enclave_test",
        "//asylo/test/util:status_matchers",
        "//asylo/test/util:test_flags",
        "//asylo/test/util:test_main",
        "//asylo/util:logging",
        "@com_google_absl//absl/flags:flag",
        "@com_google_absl//absl/strings",
        "@com_google_googletest//:gtest",
    ],
)

# Enclave for INET6 socket test.
cc_unsigned_enclave(
    name = "inet6_socket_test_enclave_unsigned.so",
    srcs = ["inet6_socket_test_enclave.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":socket_client",
        ":socket_server",
        ":socket_test_cc_proto",
        ":socket_test_transmit",
        "//asylo/test/util:enclave_test_application",
        "//asylo/util:logging",
    ],
)

debug_sign_enclave(
    name = "inet6_socket_test_enclave.so",
    unsigned = "inet6_socket_test_enclave_unsigned.so",
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
        ":socket_test_cc_proto",
        ":socket_test_transmit",
        "//asylo:enclave_client",
        "//asylo/test/util:enclave_test",
        "//asylo/test/util:status_matchers",
        "//asylo/test/util:test_main",
        "@com_google_googletest//:gtest",
    ],
)

# Enclave for getaddrinfo and freeaddrinfo tests.
cc_unsigned_enclave(
    name = "addrinfo_test_enclave_unsigned.so",
    srcs = ["addrinfo_test_enclave.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":socket_test_cc_proto",
        "//asylo/test/util:enclave_test_application",
    ],
)

debug_sign_enclave(
    name = "addrinfo_test_enclave.so",
    unsigned = "addrinfo_test_enclave_unsigned.so",
)

# Driver for getaddrinfo and freeaddrinfo tests.
enclave_test(
    name = "addrinfo_test",
    srcs = ["addrinfo_test_driver.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    enclaves = {"enclave": ":addrinfo_test_enclave.so"},
    test_args = ["--enclave_path='{enclave}'"],
    deps = [
        ":socket_test_cc_proto",
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
        "//asylo/util:logging",
        "@com_google_absl//absl/strings:str_format",
        "@com_google_googletest//:gtest",
    ],
)

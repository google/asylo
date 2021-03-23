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

# Various tests and test data

load("@linux_sgx//:sgx_sdk.bzl", "sgx")
load("@rules_cc//cc:defs.bzl", "cc_binary", "cc_library", "cc_proto_library", "cc_test")
load("@rules_proto//proto:defs.bzl", "proto_library")
load(
    "//asylo/bazel:asylo.bzl",
    "cc_unsigned_enclave",
    "debug_sign_enclave",
    "enclave_loader",
)
load("//asylo/bazel:copts.bzl", "ASYLO_DEFAULT_COPTS")

licenses(["notice"])  # Apache v2.0

# Example for using the remote Asylo framework.

cc_library(
    name = "web_server_lib",
    srcs = ["web_server.cc"],
    hdrs = ["web_server.h"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        "//asylo/util:cleanup",
        "//asylo/util:logging",
        "//asylo/util:mutex_guarded",
        "//asylo/util:posix_errors",
        "//asylo/util:status",
        "@com_google_absl//absl/container:flat_hash_map",
        "@com_google_absl//absl/container:flat_hash_set",
        "@com_google_absl//absl/memory",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/strings",
    ],
)

cc_test(
    name = "web_server_test",
    size = "small",
    srcs = ["web_server_test.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":web_server_lib",
        "//asylo/test/util:test_main",
        "//asylo/util:logging",
        "@com_google_absl//absl/container:flat_hash_map",
        "@com_google_absl//absl/strings",
        "@com_google_googletest//:gtest",
    ],
)

proto_library(
    name = "circles_proto",
    srcs = ["circles.proto"],
    deps = ["//asylo:enclave_proto"],
)

cc_proto_library(
    name = "circles_cc_proto",
    deps = [":circles_proto"],
)

cc_unsigned_enclave(
    name = "circle_enclave_0_unsigned.so",
    srcs = ["circle_enclave.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    defines = [
        "CENTER_X=100",
        "CENTER_Y=200",
        "SPEED_X=5",
        "SPEED_Y=3",
        "CIRCLE_RADIUS=5",
        "CIRCLE_COLOR=\"rgb(66,133,244)\"",
    ],
    deps = [
        ":circles_cc_proto",
        "//asylo:enclave_runtime",
        "//asylo/util:logging",
        "//asylo/util:status",
        "@com_google_absl//absl/memory",
        "@com_google_absl//absl/strings",
    ],
)

debug_sign_enclave(
    name = "circle_enclave_0_debug.so",
    unsigned = ":circle_enclave_0_unsigned.so",
)

cc_unsigned_enclave(
    name = "circle_enclave_1_unsigned.so",
    srcs = ["circle_enclave.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    defines = [
        "CENTER_X=-200",
        "CENTER_Y=-100",
        "SPEED_X=5",
        "SPEED_Y=5",
        "CIRCLE_RADIUS=10",
        "CIRCLE_COLOR=\"rgb(234,67,53)\"",
    ],
    deps = [
        ":circles_cc_proto",
        "//asylo:enclave_runtime",
        "//asylo/util:logging",
        "//asylo/util:status",
        "@com_google_absl//absl/memory",
        "@com_google_absl//absl/strings",
    ],
)

debug_sign_enclave(
    name = "circle_enclave_1_debug.so",
    unsigned = ":circle_enclave_1_unsigned.so",
)

cc_unsigned_enclave(
    name = "circle_enclave_2_unsigned.so",
    srcs = ["circle_enclave.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    defines = [
        "CENTER_X=-100",
        "CENTER_Y=200",
        "SPEED_X=3",
        "SPEED_Y=5",
        "CIRCLE_RADIUS=20",
        "CIRCLE_COLOR=\"rgb(250,187,5)\"",
    ],
    deps = [
        ":circles_cc_proto",
        "//asylo:enclave_runtime",
        "//asylo/util:logging",
        "//asylo/util:status",
        "@com_google_absl//absl/memory",
        "@com_google_absl//absl/strings",
    ],
)

debug_sign_enclave(
    name = "circle_enclave_2_debug.so",
    unsigned = ":circle_enclave_2_unsigned.so",
)

cc_unsigned_enclave(
    name = "circle_enclave_3_unsigned.so",
    srcs = ["circle_enclave.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    defines = [
        "CENTER_X=200",
        "CENTER_Y=-100",
        "SPEED_X=3",
        "SPEED_Y=3",
        "CIRCLE_RADIUS=15",
        "CIRCLE_COLOR=\"rgb(52,168,82)\"",
    ],
    deps = [
        ":circles_cc_proto",
        "//asylo:enclave_runtime",
        "//asylo/util:logging",
        "//asylo/util:status",
        "@com_google_absl//absl/memory",
        "@com_google_absl//absl/strings",
    ],
)

debug_sign_enclave(
    name = "circle_enclave_3_debug.so",
    unsigned = ":circle_enclave_3_unsigned.so",
)

cc_library(
    name = "circle_client",
    testonly = True,
    srcs = ["circle_client.cc"],
    hdrs = ["circle_client.h"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":circles_cc_proto",
        "//asylo:enclave_cc_proto",
        "//asylo:enclave_client",
        "//asylo/platform/primitives/sgx:loader_cc_proto",
        "//asylo/util:logging",
        "//asylo/util:path",
        "//asylo/util:status_macros",
        "//asylo/util/remote:provision",
        "//asylo/util/remote:remote_loader_cc_proto",
        "//asylo/util/remote:remote_proxy_config",
        "@com_google_absl//absl/flags:flag",
        "@com_google_absl//absl/flags:parse",
        "@com_google_absl//absl/memory",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/strings",
        "@com_google_googletest//:gtest",
    ],
)

# Bouncing circles application running with local provisioning.
#
# To run this application, do
#
# bazel run --config=sgx  \
#     //remote/bouncing_circles:web_application -- --port=NNNN
#
# then open a browser window at
# http://<host machine>:NNNN/
# and follow the link
#
enclave_loader(
    name = "web_application",
    testonly = True,
    srcs = ["web_application.cc"],
    backends = sgx.backend_labels,
    copts = ASYLO_DEFAULT_COPTS,
    enclaves = {
        "circle_enclave_0": ":circle_enclave_0_debug.so",
        "circle_enclave_1": ":circle_enclave_1_debug.so",
        "circle_enclave_2": ":circle_enclave_2_debug.so",
        "circle_enclave_3": ":circle_enclave_3_debug.so",
    },
    linkstatic = True,
    loader_args = [
        "--enclave_binary_paths='{circle_enclave_0},{circle_enclave_1},{circle_enclave_2},{circle_enclave_3}'",
    ],
    remote_proxy = "//asylo/util/remote:sgx_remote_proxy",
    deps = [
        ":circle_client",
        ":circles_cc_proto",
        ":web_server_lib",
        "//asylo:enclave_client",
        "//asylo/test/util:status_matchers",
        "//asylo/util:logging",
        "//asylo/util:status",
        "//asylo/util:thread",
        "//asylo/util/remote:local_provision",
        "//asylo/util/remote:process_main_wrapper",
        "@com_google_absl//absl/flags:flag",
        "@com_google_absl//absl/flags:parse",
        "@com_google_absl//absl/memory",
        "@com_google_absl//absl/strings",
    ],
)

# Bouncing circles application running with remote provisioning,
# using two docker containers.
#
# To run this application follow the instructions in the accompanying build.sh
# file.
cc_binary(
    name = "web_application_remote",
    testonly = True,
    srcs = ["web_application.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    data = [
        "//asylo/examples/remote/provision_server:certs",
    ],
    linkstatic = True,
    deps = [
        ":circle_client",
        ":web_server_lib",
        "//asylo:enclave_client",
        "//asylo/test/util:status_matchers",
        "//asylo/util:logging",
        "//asylo/util:status",
        "//asylo/util:thread",
        "//asylo/util/remote:process_main_wrapper",
        "//asylo/util/remote:remote_provision_client",
        "@com_google_absl//absl/flags:flag",
        "@com_google_absl//absl/flags:parse",
        "@com_google_absl//absl/memory",
        "@com_google_absl//absl/strings",
    ],
)

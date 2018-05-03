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

# Hello World project for Asylo.

load(
    "@com_google_asylo//asylo/bazel:asylo.bzl",
    "debug_enclave_driver",
    "sim_enclave",
)
load("@com_google_asylo//asylo/bazel:proto.bzl", "asylo_proto_library")

package(
    default_visibility = ["//visibility:public"],
)

# Example for using the Asylo framework.

asylo_proto_library(
    name = "hello_proto",
    srcs = ["hello.proto"],
    deps = ["@com_google_asylo//asylo:enclave_proto"],
)

sim_enclave(
    name = "hello_enclave.so",
    srcs = ["hello_enclave.cc"],
    deps = [
        ":hello_proto_cc",
        "@com_google_absl//absl/strings",
        "@com_google_asylo//asylo:enclave_runtime",
        "@com_google_asylo//asylo/util:status",
    ],
)

debug_enclave_driver(
    name = "hello_world",
    srcs = ["hello_driver.cc"],
    enclaves = [":hello_enclave.so"],
    deps = [
        ":hello_proto_cc",
        "@com_github_gflags_gflags//:gflags_nothreads",
        "@com_google_absl//absl/strings",
        "@com_google_asylo//asylo:enclave_client",
        "@com_google_asylo//asylo/util:logging",
    ],
)

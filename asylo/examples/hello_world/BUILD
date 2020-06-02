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

# Hello World project for Asylo.

load("@linux_sgx//:sgx_sdk.bzl", "sgx")
load("@rules_cc//cc:defs.bzl", "cc_proto_library")
load("@rules_proto//proto:defs.bzl", "proto_library")
load("//asylo/bazel:asylo.bzl", "cc_unsigned_enclave", "debug_sign_enclave", "enclave_loader")
load("//asylo/bazel:copts.bzl", "ASYLO_DEFAULT_COPTS")

licenses(["notice"])

package(
    default_visibility = ["//visibility:public"],
)

# Example for using the Asylo framework.

proto_library(
    name = "hello_proto",
    srcs = ["hello.proto"],
    deps = ["//asylo:enclave_proto"],
)

cc_proto_library(
    name = "hello_cc_proto",
    deps = [":hello_proto"],
)

cc_unsigned_enclave(
    name = "hello_enclave_unsigned.so",
    srcs = ["hello_enclave.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":hello_cc_proto",
        "//asylo:enclave_runtime",
        "//asylo/util:logging",
        "//asylo/util:status",
        "@com_google_absl//absl/strings",
    ],
)

debug_sign_enclave(
    name = "hello_enclave.so",
    unsigned = "hello_enclave_unsigned.so",
)

enclave_loader(
    name = "hello_world",
    srcs = ["hello_driver.cc"],
    backends = sgx.backend_labels,  # Has SGX loader dependencies
    copts = ASYLO_DEFAULT_COPTS,
    enclaves = {"enclave": ":hello_enclave.so"},
    loader_args = ["--enclave_path='{enclave}'"],
    deps = [
        ":hello_cc_proto",
        "//asylo:enclave_cc_proto",
        "//asylo:enclave_client",
        "//asylo/platform/primitives/sgx:loader_cc_proto",
        "//asylo/util:logging",
        "@com_google_absl//absl/flags:flag",
        "@com_google_absl//absl/flags:parse",
        "@com_google_absl//absl/strings",
    ],
)

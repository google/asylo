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

load("@linux_sgx//:sgx_sdk.bzl", "sgx")
load(
    "//asylo/bazel:asylo.bzl",
    "enclave_loader",
)
load("//asylo/bazel:copts.bzl", "ASYLO_DEFAULT_COPTS")

licenses(["notice"])

# Example demonstrating gRPC in Asylo for remote SGX backend.

package(
    default_visibility = ["//visibility:public"],
)

# The driver for the gRPC server enclave.
enclave_loader(
    name = "grpc_server",
    srcs = ["grpc_server_driver.cc"],
    backends = sgx.backend_labels,  # Has SGX loader dependencies
    copts = ASYLO_DEFAULT_COPTS,
    enclaves = {"enclave": "//asylo/examples/grpc_server:grpc_server_enclave.so"},
    loader_args = ["--enclave_path='{enclave}'"],
    remote_proxy = "//asylo/util/remote:sgx_remote_proxy",
    deps = [
        "//asylo:enclave_client",
        "//asylo/examples/grpc_server:grpc_server_config_cc_proto",
        "//asylo/platform/primitives/sgx:loader_cc_proto",
        "//asylo/util:logging",
        "//asylo/util:status",
        "//asylo/util/remote:local_provision",
        "//asylo/util/remote:provision",
        "//asylo/util/remote:remote_loader_cc_proto",
        "//asylo/util/remote:remote_proxy_config",
        "@com_google_absl//absl/flags:flag",
        "@com_google_absl//absl/flags:parse",
    ],
)

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

load("//asylo/bazel:asylo.bzl", "enclave_loader")

package(
    default_visibility = ["//visibility:public"],
)

proto_library(
    name = "hello_proto",
    srcs = ["hello.proto"],
    deps = ["//asylo:enclave_proto"],
)

cc_proto_library(
    name = "hello_cc_proto",
    deps = [":hello_proto"],
)

enclave_loader(
    name = "edp_hello_world",
    srcs = ["hello_driver.cc"],
    enclaves = {"enclave": "//asylo/examples/edp_hello_world/rust_enclave:hello_world.sgxs"},
    loader_args = ["--enclave_path='{enclave}'"],
    deps = [
        ":hello_cc_proto",
        "@com_google_absl//absl/flags:flag",
        "@com_google_absl//absl/flags:parse",
        "@com_google_absl//absl/strings",
        "//asylo:enclave_client",
        "//asylo/util:logging",
    ],
)

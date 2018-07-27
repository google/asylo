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

package(
    default_visibility = ["//visibility:public"],
)

load(
    "//asylo/bazel:asylo.bzl",
    "enclave_loader",
    "sim_enclave",
)
load("//asylo/bazel:proto.bzl", "asylo_proto_library")

# Example and exercise for using Asylo toolkits.
asylo_proto_library(
    name = "demo_proto",
    srcs = ["demo.proto"],
    deps = ["//asylo:enclave_proto"],
)

sim_enclave(
    name = "demo_enclave",
    srcs = ["demo_enclave.cc"],
    deps = [
        ":demo_proto_cc",
        "//asylo:enclave_runtime",
        "//asylo/crypto:aes_gcm_siv",
        "//asylo/util:cleansing_types",
        "//asylo/util:status",
        "@com_google_absl//absl/strings",
    ],
)

enclave_loader(
    name = "quickstart",
    srcs = ["demo_driver.cc"],
    enclaves = {"enclave": ":demo_enclave"},
    loader_args = ["--enclave_path='{enclave}'"],
    deps = [
        ":demo_proto_cc",
        "//asylo:enclave_client",
        "//asylo/util:logging",
        "@com_github_gflags_gflags//:gflags_nothreads",
    ],
)

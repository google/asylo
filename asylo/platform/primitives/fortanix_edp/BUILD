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
    default_visibility = ["//asylo:implementation"],
)

exports_files([
    "enclave_loader.cc",
])

load("//asylo/bazel:copts.bzl", "ASYLO_DEFAULT_COPTS")

cc_library(
    name = "untrusted_edp",
    srcs = ["untrusted_edp.cc"],
    hdrs = ["untrusted_edp.h"],
    copts = ASYLO_DEFAULT_COPTS + select({
        "//asylo/platform/primitives:edp": [
            "-D _CFG_EDP_",
        ],
        "//conditions:default": [],
    }),
    deps = [
        "//asylo:enclave_cc_proto",
        "//asylo/platform/primitives:untrusted_primitives",
        "//asylo/platform/primitives/util:message_reader_writer",
        "//asylo/util:cleanup",
        "//asylo/util:file_mapping",
        "//asylo/util:status",
        "@com_google_absl//absl/container:flat_hash_map",
        "@com_google_absl//absl/strings",
    ] + select({
        "//asylo/platform/primitives:edp": [
            "//asylo/platform/primitives/fortanix_edp/edp_runner",
        ],
        "//conditions:default": [],
    }),
)

# Message definitions for Fortanix EDP enclave loader.
proto_library(
    name = "loader_proto",
    srcs = ["loader.proto"],
    visibility = ["//visibility:public"],
    deps = [
        "//asylo:enclave_proto",
    ],
)

cc_proto_library(
    name = "loader_cc_proto",
    visibility = ["//visibility:public"],
    deps = [":loader_proto"],
)


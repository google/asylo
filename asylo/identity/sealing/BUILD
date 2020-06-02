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

load("@rules_cc//cc:defs.bzl", "cc_library", "cc_proto_library")
load("@rules_proto//proto:defs.bzl", "proto_library")
load("//asylo/bazel:copts.bzl", "ASYLO_DEFAULT_COPTS")

licenses(["notice"])  # Apache v2.0

package(default_visibility = ["//visibility:public"])

proto_library(
    name = "sealed_secret_proto",
    srcs = ["sealed_secret.proto"],
    deps = [
        "//asylo/crypto:algorithms_proto",
        "//asylo/identity:identity_acl_proto",
        "//asylo/identity:identity_proto",
    ],
)

cc_proto_library(
    name = "sealed_secret_cc_proto",
    deps = [":sealed_secret_proto"],
)

cc_library(
    name = "secret_sealer",
    srcs = ["secret_sealer.cc"],
    hdrs = ["secret_sealer.h"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":sealed_secret_cc_proto",
        "//asylo/crypto/util:byte_container_util",
        "//asylo/crypto/util:byte_container_view",
        "//asylo/identity:identity_cc_proto",
        "//asylo/platform/common:static_map",
        "//asylo/util:cleansing_types",
        "//asylo/util:status",
    ],
)

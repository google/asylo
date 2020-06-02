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

load("@rules_cc//cc:defs.bzl", "cc_library")
load("//asylo/bazel:copts.bzl", "ASYLO_DEFAULT_COPTS")

licenses(["notice"])  # Apache v2.0

package(default_visibility = ["//visibility:public"])

cc_library(
    name = "enclave_assertion_generator",
    hdrs = ["enclave_assertion_generator.h"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        "//asylo/identity:enclave_assertion_authority",
        "//asylo/identity:identity_cc_proto",
        "//asylo/platform/common:static_map",
        "//asylo/util:status",
    ],
)

cc_library(
    name = "enclave_assertion_verifier",
    hdrs = ["enclave_assertion_verifier.h"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        "//asylo/identity:enclave_assertion_authority",
        "//asylo/identity:identity_cc_proto",
        "//asylo/platform/common:static_map",
        "//asylo/util:status",
    ],
)

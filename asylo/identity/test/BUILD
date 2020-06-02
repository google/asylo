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

# Test utils for identity.

load("@rules_cc//cc:defs.bzl", "cc_library")
load("//asylo/bazel:copts.bzl", "ASYLO_DEFAULT_COPTS")

licenses(["notice"])

package(
    default_testonly = 1,
    default_visibility = ["//asylo:implementation"],
)

cc_library(
    name = "mock_identity_expectation_matcher",
    hdrs = ["mock_identity_expectation_matcher.h"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        "//asylo/identity:identity_cc_proto",
        "//asylo/identity:identity_expectation_matcher",
        "//asylo/util:status",
        "@com_google_googletest//:gtest",
    ],
)

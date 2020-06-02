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

load("@rules_cc//cc:defs.bzl", "cc_library")
load("//asylo/bazel:copts.bzl", "ASYLO_DEFAULT_COPTS")

licenses(["notice"])  # Apache v2.0

package(
    default_visibility = [
        "//asylo:implementation",
    ],
)

cc_library(
    name = "signal_manager",
    srcs = ["signal_manager.cc"],
    hdrs = ["signal_manager.h"],
    copts = ASYLO_DEFAULT_COPTS + ["-faligned-new"],
    deps = [
        "//asylo/platform/core:trusted_spin_lock",
        "//asylo/util:lock_guard",
        "//asylo/util:status",
        "@com_google_absl//absl/memory",
        "@com_google_absl//absl/strings",
    ],
)

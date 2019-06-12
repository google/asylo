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

load("//asylo/bazel:copts.bzl", "ASYLO_DEFAULT_COPTS")

package(
    default_visibility = ["//asylo:implementation"],
)

# Trusted simulator components.
cc_library(
    name = "trusted_sim",
    srcs = [
        "malloc_lock.cc",
        "runtime_stubs.c",
        "runtime_syscalls.c",
        "shared_sim.h",
        "trusted_runtime.cc",
        "trusted_sim.cc",
    ],
    copts = ASYLO_DEFAULT_COPTS,
    tags = ["asylo-sim"],
    deps = select(
        {
            "//asylo/platform/primitives:asylo_sim": [
                "//asylo/platform/primitives",
                "//asylo/platform/primitives/util:primitive_locks",
                "//asylo/platform/primitives/x86:spin_lock",
                "//asylo/platform/primitives/util:trusted_runtime_helper",
                "//asylo/platform/primitives:trusted_primitives",
                "//asylo/platform/primitives:trusted_runtime",
                "//asylo/util:status_macros",
            ],
        },
        "Trusted simulation components must be built with --define=ASYLO_SIM=1",
    ),
)

cc_library(
    name = "untrusted_sim",
    srcs = [
        "shared_sim.h",
        "untrusted_sim.cc",
    ],
    hdrs = ["untrusted_sim.h"],
    copts = ASYLO_DEFAULT_COPTS,
    linkopts = ["-ldl"],
    deps = [
        "//asylo/platform/primitives",
        "//asylo/platform/primitives:untrusted_primitives",
        "//asylo/platform/primitives/util:status_conversions",
        "//asylo/util:status",
        "@com_google_absl//absl/base",
        "@com_google_absl//absl/container:flat_hash_map",
        "@com_google_absl//absl/debugging:leak_check",
        "@com_google_absl//absl/memory",
        "@com_google_absl//absl/strings",
    ],
)

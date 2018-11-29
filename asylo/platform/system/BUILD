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

# asylo system library supplements.

package(
    default_visibility = ["//asylo:implementation"],
)

load("//asylo/bazel:copts.bzl", "ASYLO_DEFAULT_COPTS")

filegroup(
    name = "system_headers",
    srcs = glob(["include/**/*.h"]) + [
        "include/string",
    ],
    visibility = ["//visibility:public"],
)

cc_library(
    name = "system",
    hdrs = [":system_headers"],
    copts = ASYLO_DEFAULT_COPTS,
    linkstatic = 1,
)

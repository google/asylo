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

load(
    "//asylo/distrib/test:use_enclave_info.bzl",
    "check_enclave_info_rule",
)

exports_files([
    "use_enclave_info.bzl",
])

check_enclave_info_rule(
    name = "enclave_runner_is_not_an_enclave",
    testonly = 1,
    executable = "//asylo/bazel:enclave_runner",
)

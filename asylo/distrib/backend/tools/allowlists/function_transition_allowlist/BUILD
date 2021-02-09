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

licenses(["notice"])

# This group must exist at this label in order to enable Bazel transitions.
# This might have problems if used from a client workspace.
package_group(
    name = "function_transition_allowlist",
    includes = [
        "@com_google_asylo_backend_provider//:implementation",
        "@linux_sgx//:implementation",
    ],
    packages = ["//..."],
)

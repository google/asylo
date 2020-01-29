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

load("@rules_java//java:defs.bzl", "java_library", "java_proto_library")

licenses(["notice"])

# This build file provides rules for loading Asylo enclaves from a Java client.

package(
    default_visibility = [
        "//asylo:__pkg__",
        "//asylo/binding/java/src/test/java/com/asylo/client:__pkg__",
    ],
)

java_library(
    name = "enclave_client",
    srcs = [
        "AutoCloseablePointer.java",
        "EnclaveClient.java",
        "EnclaveException.java",
        "EnclaveManager.java",
    ],
    exports = [
        ":enclave_client_java_proto",
        ":loader_java_proto",
    ],
    deps = [
        ":enclave_client_java_proto",
        "//asylo/binding/java/src/main/native:libenclave_client_java.so",
        "@com_google_protobuf//:protobuf_java",
    ],
)

java_proto_library(
    name = "enclave_client_java_proto",
    deps = [
        "//asylo:enclave_proto",
    ],
)

java_proto_library(
    name = "loader_java_proto",
    deps = [
        "//asylo/platform/primitives/sgx:loader_proto",
    ],
)

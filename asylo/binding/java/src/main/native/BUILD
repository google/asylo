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

licenses(["notice"])

# Build rules for JNI peers of Asylo Java client

package(
    default_visibility = [
        "//asylo/binding/java/src/main/java/com/asylo/client:__pkg__",
        "//asylo/binding/java/src/test/native:__pkg__",
    ],
)

cc_library(
    name = "enclave_client_jni",
    srcs = [
        "enclave_client.cc",
        "enclave_manager.cc",
        "jni_utils.cc",
    ],
    hdrs = [
        "enclave_client.h",
        "enclave_manager.h",
        "jni_utils.h",
        "@bazel_tools//tools/jdk:jni_header",
        "@bazel_tools//tools/jdk:jni_md_header-linux",
    ],
    copts = [
        "-isystem",
        "$(BINDIR)/external/bazel_tools/tools/jdk/include",
        "-isystem",
        "$(BINDIR)/external/bazel_tools/tools/jdk/include/linux",
    ],
    deps = [
        "//asylo:enclave_cc_proto",
        "//asylo:enclave_client",
        "//asylo/platform/primitives/sgx:loader_cc_proto",
        "//asylo/util:status",
        "@com_google_absl//absl/memory",
        "@com_google_protobuf//:protobuf",
    ],
    alwayslink = 1,
)

cc_binary(
    name = "libenclave_client_java.so",
    linkshared = True,
    deps = [
        ":enclave_client_jni",
    ],
)

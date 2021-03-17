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

# Build rules for testing JNI utils

package(
    default_testonly = 1,
    default_visibility = [
        "//asylo/binding/java/src/test/java/com/asylo/client:__pkg__",
    ],
)

cc_library(
    name = "enclave_jni_unit_test_helper",
    srcs = [
        "enclave_native_jni_utils_tests.cc",
    ],
    hdrs = [
        "enclave_native_jni_utils_tests.h",
        "@bazel_tools//tools/jdk:jni_header",
        "@bazel_tools//tools/jdk:jni_md_header-linux",
    ],
    copts = [
        "-isystem $(BINDIR)/external/bazel_tools/tools/jdk/include",
        "-isystem $(BINDIR)/external/bazel_tools/tools/jdk/include/linux",
    ],
    deps = [
        "//asylo:enclave_cc_proto",
        "//asylo/binding/java/src/main/native:enclave_client_jni",
        "//asylo/binding/java/src/test/java/com/asylo/client:jni_utils_test_cc_proto",
        "@com_google_absl//absl/status",
    ],
    alwayslink = 1,
)

cc_binary(
    name = "libenclave_jni_unit_test_helper_java.so",
    linkshared = True,
    deps = [
        ":enclave_jni_unit_test_helper",
    ],
)

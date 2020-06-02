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

load("@rules_cc//cc:defs.bzl", "cc_proto_library")
load(
    "@rules_java//java:defs.bzl",
    "java_library",
    "java_proto_library",
    "java_test",
)
load("@rules_proto//proto:defs.bzl", "proto_library")

licenses(["notice"])

# This build file provides rules for using asylo Java client.

package(
    default_testonly = 1,
    default_visibility = ["//visibility:public"],
)

java_library(
    name = "tests_lib",
    srcs = [
        "AllTests.java",
        "EnclaveClientTest.java",
        "EnclaveManagerTest.java",
        "EnclaveNativeJniUtilsTest.java",
    ],
    deps = [
        ":jni_utils_test_java_proto",
        "//asylo/binding/java/src/main/java/com/asylo/client:enclave_client",
        "//asylo/binding/java/src/test/native:libenclave_jni_unit_test_helper_java.so",
        "@com_google_protobuf//:protobuf_java",
        "@maven//:com_google_truth_truth",
        "@maven//:junit_junit",
    ],
)

java_test(
    name = "AllTests",
    size = "small",
    test_class = "com.asylo.client.AllTests",
    runtime_deps = [
        ":tests_lib",
    ],
)

proto_library(
    name = "jni_utils_test_proto",
    srcs = ["jni_utils_test.proto"],
    deps = ["//asylo:enclave_proto"],
)

cc_proto_library(
    name = "jni_utils_test_cc_proto",
    deps = [":jni_utils_test_proto"],
)

java_proto_library(
    name = "jni_utils_test_java_proto",
    deps = [":jni_utils_test_proto"],
)

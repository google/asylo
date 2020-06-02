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

# Asylo framework.

load("@rules_cc//cc:defs.bzl", "cc_library", "cc_proto_library")
load("@rules_proto//proto:defs.bzl", "proto_library")
load("//asylo/bazel:asylo.bzl", "ASYLO_ALL_BACKEND_TAGS")
load("//asylo/bazel:copts.bzl", "ASYLO_DEFAULT_COPTS")

licenses(["notice"])

exports_files(["LICENSE"])

package_group(
    name = "implementation",
    packages = [
        "-//asylo/examples/...",
        "//asylo/...",
    ],
)

config_setting(
    name = "asylo",
    values = {
        "cpu": "k8",
        "crosstool_top": "@com_google_asylo_toolchain//toolchain:crosstool",
    },
    visibility = ["//visibility:public"],
)

config_setting(
    name = "no_backend",
    flag_values = {
        "@com_google_asylo_backend_provider//:backend": "@com_google_asylo_backend_provider//:none",
    },
    visibility = ["//visibility:public"],
)

# Client library for applications consuming Asylo enclaves.
cc_library(
    name = "enclave_client",
    hdrs = [
        "client.h",
        "enclave_manager.h",
    ],
    copts = ASYLO_DEFAULT_COPTS,
    visibility = ["//visibility:public"],
    deps = [
        "//asylo/platform/arch:untrusted_arch",
        "//asylo/platform/core:untrusted_core",
    ],
)

# Defines the ioctl interface to secure I/O.
cc_library(
    name = "secure_storage",
    hdrs = ["secure_storage.h"],
    visibility = ["//visibility:public"],
)

# Java client library for applications consuming Asylo enclaves.
java_library(
    name = "enclave_client_java",
    visibility = [
        "//visibility:public",
    ],
    exports = [
        "//asylo/binding/java/src/main/java/com/asylo/client:enclave_client",
    ],
)

# Runtime library for Asylo enclaves.
cc_library(
    name = "enclave_runtime",
    hdrs = ["trusted_application.h"],
    copts = ASYLO_DEFAULT_COPTS,
    linkstatic = 1,
    tags = ASYLO_ALL_BACKEND_TAGS,
    visibility = ["//visibility:public"],
    deps = select(
        {
            "@com_google_asylo//asylo": [
                "//asylo/platform/core:trusted_application",
                "//asylo/platform/posix:trusted_posix",
                "//asylo/platform/system",
            ],
        },
        no_match_error = "Must build in the Asylo toolchain.",
    ),
    alwayslink = 1,
)

# Message definitions for enclave entry and exit points.
proto_library(
    name = "enclave_proto",
    srcs = ["enclave.proto"],
    visibility = ["//visibility:public"],
    deps = [
        "//asylo/identity:enclave_assertion_authority_config_proto",
        "//asylo/util:status_proto",
    ],
)

cc_proto_library(
    name = "enclave_cc_proto",
    visibility = ["//visibility:public"],
    deps = [":enclave_proto"],
)

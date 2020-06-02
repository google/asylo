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

load("@linux_sgx//:sgx_sdk.bzl", "sgx")
load("@rules_cc//cc:defs.bzl", "cc_binary", "cc_proto_library")
load("@rules_proto//proto:defs.bzl", "proto_library")
load(
    "//asylo/bazel:asylo.bzl",
    "cc_unsigned_enclave",
    "debug_sign_enclave",
    "enclave_loader",
    "enclave_test",
)
load("//asylo/bazel:copts.bzl", "ASYLO_DEFAULT_COPTS")

licenses(["notice"])  # Apache v2.0

# Example and exercise for using Asylo toolkits.
proto_library(
    name = "demo_proto",
    srcs = ["demo.proto"],
    deps = ["//asylo:enclave_proto"],
)

cc_proto_library(
    name = "demo_cc_proto",
    deps = [":demo_proto"],
)

cc_unsigned_enclave(
    name = "demo_enclave_unsigned.so",
    srcs = ["demo_enclave.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":demo_cc_proto",
        "//asylo:enclave_runtime",
        "//asylo/crypto:aead_cryptor",
        "//asylo/util:cleansing_types",
        "//asylo/util:status",
        "@com_google_absl//absl/base:core_headers",
        "@com_google_absl//absl/strings",
    ],
)

debug_sign_enclave(
    name = "demo_enclave_debug.so",
    unsigned = ":demo_enclave_unsigned.so",
)

enclave_loader(
    name = "quickstart",
    srcs = ["demo_driver.cc"],
    backends = sgx.backend_labels,
    copts = ASYLO_DEFAULT_COPTS,
    enclaves = {"enclave": ":demo_enclave_debug.so"},
    loader_args = [
        "--enclave_path='{enclave}'",
        "--message='FooBar'",
    ],
    remote_proxy = "//asylo/util/remote:sgx_remote_proxy",
    deps = [
        ":demo_cc_proto",
        "//asylo:enclave_client",
        "//asylo/platform/primitives/sgx:loader_cc_proto",
        "//asylo/util:logging",
        "//asylo/util:status",
        "//asylo/util/remote:local_provision",
        "//asylo/util/remote:provision",
        "//asylo/util/remote:remote_loader_cc_proto",
        "//asylo/util/remote:remote_proxy_config",
        "@com_google_absl//absl/flags:flag",
        "@com_google_absl//absl/flags:parse",
    ],
)

cc_binary(
    name = "quickstart_remote",
    testonly = True,
    srcs = ["demo_driver.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    data = [
        "//asylo/examples/remote/provision_server:certs",
    ],
    deps = [
        ":demo_cc_proto",
        "//asylo:enclave_client",
        "//asylo/platform/primitives/sgx:loader_cc_proto",
        "//asylo/util:logging",
        "//asylo/util:status",
        "//asylo/util/remote:provision",
        "//asylo/util/remote:remote_loader_cc_proto",
        "//asylo/util/remote:remote_provision_client",
        "//asylo/util/remote:remote_proxy_config",
        "@com_google_absl//absl/flags:flag",
        "@com_google_absl//absl/flags:parse",
    ],
)

enclave_test(
    name = "demo_enclave_remote_test",
    size = "small",
    srcs = ["demo_enclave_remote_test.cc"],
    backends = sgx.backend_labels,
    copts = ASYLO_DEFAULT_COPTS,
    enclaves = {"enclave": ":demo_enclave_debug.so"},
    remote_proxy = "//asylo/util/remote:sgx_remote_proxy",
    tags = [
        "asylo-remote",
        "noregression",
    ],
    test_args = [
        "--enclave_path='{enclave}'",
    ],
    deps = [
        ":demo_cc_proto",
        "//asylo:enclave_client",
        "//asylo/platform/primitives/sgx:loader_cc_proto",
        "//asylo/test/util:status_matchers",
        "//asylo/test/util:test_main",
        "//asylo/util:status",
        "//asylo/util/remote:local_provision",
        "//asylo/util/remote:provision",
        "//asylo/util/remote:remote_loader_cc_proto",
        "//asylo/util/remote:remote_proxy_config",
        "@com_google_absl//absl/flags:flag",
        "@com_google_absl//absl/flags:parse",
        "@com_google_absl//absl/memory",
        "@com_google_googletest//:gtest",
    ],
)

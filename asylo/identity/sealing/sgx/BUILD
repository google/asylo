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

load("@rules_cc//cc:defs.bzl", "cc_library", "cc_test")
load("//asylo/bazel:copts.bzl", "ASYLO_DEFAULT_COPTS")

licenses(["notice"])

package(default_visibility = ["//visibility:public"])

cc_library(
    name = "sgx_local_secret_sealer",
    srcs = ["sgx_local_secret_sealer.cc"],
    hdrs = ["sgx_local_secret_sealer.h"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        "//asylo/crypto:aead_cryptor",
        "//asylo/crypto:algorithms_cc_proto",
        "//asylo/crypto/util:byte_container_util",
        "//asylo/crypto/util:byte_container_view",
        "//asylo/crypto/util:bytes",
        "//asylo/identity:identity_acl_cc_proto",
        "//asylo/identity:identity_cc_proto",
        "//asylo/identity/platform/sgx:code_identity_cc_proto",
        "//asylo/identity/platform/sgx:sgx_identity_cc_proto",
        "//asylo/identity/platform/sgx:sgx_identity_util",
        "//asylo/identity/platform/sgx/internal:hardware_types",
        "//asylo/identity/sealing:sealed_secret_cc_proto",
        "//asylo/identity/sealing:secret_sealer",
        "//asylo/identity/sealing/sgx/internal:local_secret_sealer_helpers",
        "//asylo/util:cleansing_types",
        "//asylo/util:status",
        "@com_google_absl//absl/memory",
        "@com_google_absl//absl/status",
    ],
)

# This test uses FakeEnclave to simulate different enclaves. Since FakeEnclave
# should not be used inside a real enclave, this test is not a
# "cc_test_and_cc_enclave_test" target.
cc_test(
    name = "sgx_local_secret_sealer_test",
    srcs = ["sgx_local_secret_sealer_test.cc"],
    args = ["--test_data_path=$(rootpath :testdata/local_secret_sealer_test_data)"],
    copts = ASYLO_DEFAULT_COPTS,
    data = [":testdata/local_secret_sealer_test_data"],
    deps = [
        ":sgx_local_secret_sealer",
        "//asylo/crypto:algorithms_cc_proto",
        "//asylo/crypto:sha256_hash",
        "//asylo/crypto/util:byte_container_view",
        "//asylo/crypto/util:bytes",
        "//asylo/crypto/util:trivial_object_util",
        "//asylo/identity:identity_acl_cc_proto",
        "//asylo/identity:identity_cc_proto",
        "//asylo/identity/platform/sgx:architecture_bits",
        "//asylo/identity/platform/sgx:code_identity_cc_proto",
        "//asylo/identity/platform/sgx:machine_configuration_cc_proto",
        "//asylo/identity/platform/sgx/internal:fake_enclave",
        "//asylo/identity/platform/sgx/internal:hardware_types",
        "//asylo/identity/platform/sgx/internal:proto_format",
        "//asylo/identity/platform/sgx/internal:sgx_identity_util_internal",
        "//asylo/identity/sealing:sealed_secret_cc_proto",
        "//asylo/identity/sealing/sgx/internal:local_secret_sealer_helpers",
        "//asylo/identity/sealing/sgx/internal:local_secret_sealer_test_data_cc_proto",
        "//asylo/platform/common:singleton",
        "//asylo/test/util:proto_matchers",
        "//asylo/test/util:status_matchers",
        "//asylo/test/util:test_main",
        "//asylo/util:path",
        "//asylo/util:status",
        "@com_google_absl//absl/flags:flag",
        "@com_google_absl//absl/memory",
        "@com_google_absl//absl/status",
        "@com_google_googletest//:gtest",
        "@com_google_protobuf//:protobuf",
    ],
)

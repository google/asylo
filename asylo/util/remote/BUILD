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

load("@com_github_grpc_grpc//bazel:cc_grpc_library.bzl", "cc_grpc_library")
load("@rules_cc//cc:defs.bzl", "cc_binary", "cc_library", "cc_proto_library", "cc_test")
load("@rules_proto//proto:defs.bzl", "proto_library")
load("//asylo/bazel:asylo.bzl", "enclave_loader")
load("//asylo/bazel:copts.bzl", "ASYLO_DEFAULT_COPTS")

licenses(["notice"])  # Apache v2.0

proto_library(
    name = "remote_loader_proto",
    srcs = ["remote_loader.proto"],
    visibility = ["//visibility:public"],
    deps = [
        "//asylo:enclave_proto",
        "//asylo/platform/primitives/dlopen:loader_proto",
        "//asylo/platform/primitives/sgx:loader_proto",
    ],
)

cc_proto_library(
    name = "remote_loader_cc_proto",
    visibility = ["//visibility:public"],
    deps = [":remote_loader_proto"],
)

cc_library(
    name = "grpc_channel_builder",
    srcs = ["grpc_channel_builder.cc"],
    hdrs = ["grpc_channel_builder.h"],
    copts = ASYLO_DEFAULT_COPTS,
    visibility = ["//visibility:public"],
    deps = [
        "//asylo/platform/primitives/remote/util:grpc_credential_builder",
        "//asylo/util:status",
        "@com_github_grpc_grpc//:grpc++",
        "@com_google_absl//absl/flags:flag",
        "@com_google_absl//absl/strings",
    ],
)

cc_library(
    name = "remote_proxy_config",
    srcs = ["remote_proxy_config.cc"],
    hdrs = ["remote_proxy_config.h"],
    copts = ASYLO_DEFAULT_COPTS,
    visibility = ["//visibility:public"],
    deps = [
        ":grpc_channel_builder",
        ":provision",
        "//asylo/platform/primitives/remote/metrics/clients:opencensus_client_config",
        "//asylo/platform/primitives/remote/util:grpc_credential_builder",
        "//asylo/util:status",
        "@com_github_grpc_grpc//:grpc++",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/time",
        "@com_google_absl//absl/types:optional",
    ],
)

cc_test(
    name = "remote_proxy_config_test",
    size = "small",
    srcs = ["remote_proxy_config_test.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":provision",
        ":remote_proxy_config",
        "//asylo/platform/primitives/remote/util:grpc_credential_builder",
        "//asylo/test/util:status_matchers",
        "//asylo/test/util:test_main",
        "@com_google_absl//absl/memory",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/time",
        "@com_google_googletest//:gtest",
    ],
)

cc_library(
    name = "process_main_wrapper",
    hdrs = ["process_main_wrapper.h"],
    copts = ASYLO_DEFAULT_COPTS,
    visibility = ["//visibility:public"],
    deps = [
        "//asylo/util:logging",
        "//asylo/util:status",
        "//asylo/util:thread",
        "@com_google_absl//absl/status",
    ],
)

cc_library(
    name = "grpc_server_main_wrapper",
    hdrs = ["grpc_server_main_wrapper.h"],
    copts = ASYLO_DEFAULT_COPTS,
    visibility = ["//visibility:public"],
    deps = [
        ":process_main_wrapper",
        "//asylo/platform/primitives/remote/util:grpc_credential_builder",
        "//asylo/util:logging",
        "//asylo/util:status",
        "@com_github_grpc_grpc//:grpc++",
        "@com_google_absl//absl/memory",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/strings",
    ],
)

cc_binary(
    name = "dlopen_remote_proxy",
    copts = ASYLO_DEFAULT_COPTS,
    visibility = ["//visibility:public"],
    deps = [
        "//asylo/platform/primitives/dlopen:dlopen_remote_proxy_lib",
        "//asylo/platform/primitives/remote/util:remote_proxy_lib",
    ],
)

cc_binary(
    name = "sgx_remote_proxy",
    copts = ASYLO_DEFAULT_COPTS,
    visibility = ["//visibility:public"],
    deps = [
        "//asylo/platform/primitives/remote/util:remote_proxy_lib",
        "//asylo/platform/primitives/sgx:sgx_remote_proxy_lib",
    ],
)

cc_library(
    name = "provision",
    hdrs = ["provision.h"],
    visibility = ["//visibility:public"],
    deps = [
        "//asylo/util:status",
        "@com_google_absl//absl/strings",
    ],
)

# Implementation of ":provision" interface to start remote proxy locally,
# on the same machine. Linked into the application mostly for testing purposes.
cc_library(
    name = "local_provision",
    srcs = ["local_provision.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    visibility = ["//visibility:public"],
    deps = [
        ":provision",
        "//asylo/platform/primitives/remote/util:proxy_launcher_lib",
        "//asylo/util:status",
        "@com_google_absl//absl/flags:flag",
        "@com_google_absl//absl/memory",
        "@com_google_absl//absl/strings",
    ],
)

# Implementation of ":provision" interface to start remote proxy on another
# machine. One option is that the user application runs on non-SGX machine while
# remote proxy runs and loads the enclaves on SGX-enabled machine.
# ":remote_provision_client" needs to be linked into the application.
# ":remote_provision_server" runs on the enclaves machine as a stand-alone
# gRPC server. To establish connection, flags --security_type=ssl --ssl_cert=...
# --ssl_key=... may need to be added to the server and the application.
proto_library(
    name = "remote_provision_proto",
    srcs = ["remote_provision.proto"],
)

cc_proto_library(
    name = "remote_provision_cc_proto",
    deps = [":remote_provision_proto"],
)

cc_grpc_library(
    name = "remote_provision_grpc_service",
    srcs = [":remote_provision_proto"],
    grpc_only = True,
    deps = [":remote_provision_cc_proto"],
)

cc_library(
    name = "remote_provision_server_lib",
    srcs = ["remote_provision_server_lib.cc"],
    hdrs = ["remote_provision_server_lib.h"],
    copts = ASYLO_DEFAULT_COPTS,
    visibility = ["//visibility:public"],
    deps = [
        ":grpc_server_main_wrapper",
        ":process_main_wrapper",
        ":remote_provision_cc_proto",
        ":remote_provision_grpc_service",
        "//asylo/crypto:sha256_hash",
        "//asylo/platform/primitives/remote/util:proxy_launcher_lib",
        "//asylo/util:cleanup",
        "//asylo/util:mutex_guarded",
        "//asylo/util:path",
        "//asylo/util:posix_errors",
        "//asylo/util:status",
        "//asylo/util:status_helpers",
        "//asylo/util:thread",
        "@com_github_grpc_grpc//:gpr_codegen",
        "@com_github_grpc_grpc//:grpc++",
        "@com_github_grpc_grpc//:grpc++_codegen_base",
        "@com_google_absl//absl/container:flat_hash_set",
        "@com_google_absl//absl/flags:flag",
        "@com_google_absl//absl/flags:parse",
        "@com_google_absl//absl/memory",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/strings",
    ],
)

enclave_loader(
    name = "remote_provision_host_server",
    srcs = ["remote_provision_host_server.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    linkstatic = True,
    remote_proxy = "//asylo/util/remote:sgx_remote_proxy",
    visibility = ["//visibility:public"],
    deps = [
        ":grpc_server_main_wrapper",
        ":process_main_wrapper",
        ":remote_provision_server_lib",
        "@com_google_absl//absl/base:core_headers",
        "@com_google_absl//absl/flags:flag",
        "@com_google_absl//absl/flags:parse",
    ],
)

cc_library(
    name = "remote_provision_client",
    srcs = ["remote_provision_client.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    visibility = ["//visibility:public"],
    deps = [
        ":grpc_channel_builder",
        ":provision",
        ":remote_provision_cc_proto",
        ":remote_provision_grpc_service",
        "//asylo/crypto:sha256_hash",
        "//asylo/platform/primitives/remote/util:grpc_credential_builder",
        "//asylo/util:cleanup",
        "//asylo/util:posix_errors",
        "//asylo/util:status",
        "//asylo/util:status_helpers",
        "@com_github_grpc_grpc//:gpr_codegen",
        "@com_github_grpc_grpc//:grpc++",
        "@com_github_grpc_grpc//:grpc++_codegen_base",
        "@com_google_absl//absl/flags:flag",
        "@com_google_absl//absl/memory",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/strings",
    ],
)

# Generation of sample SSL certificates, which are stored in this library, so that
# both host and target can use the same pair.
# There is no need to regenerate them, unless something changes in the environment.

genrule(
    name = "gen_certs",
    testonly = True,
    srcs = [],
    outs = [
        "new.server.crt",
        "new.server.key",
    ],
    cmd = """
        export OPENSSL_CONF=/tmp/openssl.conf;

        echo "[req]
        distinguished_name = req_distinguished_name
        req_extensions = v3_req

        [req_distinguished_name]
        countryName = Country Name (2 letter code)
        countryName_default = US
        stateOrProvinceName = State or Province Name (full name)
        stateOrProvinceName_default = CA
        localityName = Locality Name (eg, city)
        localityName_default = SF
        organizationalUnitName = Organizational Unit Name (eg, section)
        organizationalUnitName_default = Google
        commonName = Common Name (CN)
        commonName_default = common_ssl_name
        commonName_max = 64

        [ v3_req ]
        basicConstraints = CA:FALSE
        keyUsage = nonRepudiation, digitalSignature, keyEncipherment" > /tmp/openssl.conf;

        openssl req -newkey rsa:2048 -nodes -keyout $(location new.server.key)\
            -x509 -days 365 -out $(location new.server.crt)\
            -subj "/C=SP/ST=Test/L=Test/O=Test/OU=Test/CN=common_ssl_name"
            """,
)

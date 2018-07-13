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

"""Repository rule implementations for WORKSPACE to use."""

load(
    "@com_google_asylo//asylo/bazel:patch_repository.bzl",
    "patch_repository",
)

def _asylo_backend_deps_impl(repository_ctx):
    repository_ctx.template(
        "BUILD",
        Label("@com_google_asylo//asylo/distrib/backend:BUILD.tpl"),
    )
    repository_ctx.template(
        "enclave_info.bzl",
        Label("@com_google_asylo//asylo/distrib/backend:enclave_info.bzl.tpl"),
    )
    repository_ctx.template(
        "WORKSPACE",
        Label("@com_google_asylo//asylo/distrib/backend:WORKSPACE.tpl"),
    )

# Rule to include Asylo's backend support dependencies in a WORKSPACE.
_asylo_backend_deps = repository_rule(
    implementation = _asylo_backend_deps_impl,
)

def asylo_backend_deps():
    """Macro to include Asylo's tools for defining a backend."""

    # enclave_info.bzl
    if "com_google_asylo_backend_provider" not in native.existing_rules():
        _asylo_backend_deps(name = "com_google_asylo_backend_provider")

def asylo_testonly_deps():
    """Macro to include Asylo's testing-only dependencies in a WORKSPACE."""

    # GoogleTest/GoogleMock framework. Used by most unit-tests.
    if "com_google_googletest" not in native.existing_rules():
        native.new_http_archive(
            name = "com_google_googletest",
            build_file_content = """
cc_library(
    name = "gtest",
    srcs = [
          "googletest/src/gtest-all.cc",
          "googlemock/src/gmock-all.cc",
    ],
    hdrs = glob([
        "**/*.h",
        "googletest/src/*.cc",
        "googlemock/src/*.cc",
    ]),
    includes = [
        "googlemock",
        "googletest",
        "googletest/include",
        "googlemock/include",
    ],
    linkopts = select({
        "@com_google_asylo//asylo": [],
        "//conditions:default": ["-pthread"],
    }),
    visibility = ["//visibility:public"],
)

cc_library(
    name = "gtest_main",
    srcs = ["googlemock/src/gmock_main.cc"],
    linkopts = select({
        "@com_google_asylo//asylo": [],
        "//conditions:default": ["-pthread"],
    }),
    visibility = ["//visibility:public"],
    deps = [":gtest"],
)
""",
            urls = [
                "https://github.com/google/googletest/archive/release-1.8.0.tar.gz",
            ],
            sha256 = "58a6f4277ca2bc8565222b3bbd58a177609e9c488e8a72649359ba51450db7d8",
            strip_prefix = "googletest-release-1.8.0",
        )

    # gflags
    if "com_github_gflags_gflags" not in native.existing_rules():
        native.http_archive(
            name = "com_github_gflags_gflags",
            # Release v2.2.1
            urls = ["https://github.com/gflags/gflags/archive/v2.2.1.tar.gz"],
            sha256 = "ae27cdbcd6a2f935baa78e4f21f675649271634c092b1be01469440495609d0e",
            strip_prefix = "gflags-2.2.1",
        )

def asylo_deps():
    """Macro to include Asylo's critical dependencies in a WORKSPACE."""

    # Asylo macros depend on the backend provider.
    asylo_backend_deps()

    # Boringssl
    if "boringssl" not in native.existing_rules():
        patch_repository(
            name = "boringssl",
            # Non-release commit to master-with-bazel branch from March 8, 2018
            urls = [
                "https://github.com/google/boringssl/archive/241dc59bb90f8c45ebc8473fc7599b861a93bfa6.tar.gz",
            ],
            patch = "@com_google_asylo//asylo/distrib:boringssl.patch",
            sha256 = "379e5f0f29e1429b00b44b87b66776d123dd18410b457e0a18e4f0eeff4b94c9",
            strip_prefix = "boringssl-241dc59bb90f8c45ebc8473fc7599b861a93bfa6",
        )

    # CCTZ (Time-zone framework).
    if "com_googlesource_code_cctz" not in native.existing_rules():
        native.http_archive(
            name = "com_googlesource_code_cctz",
            urls = ["https://github.com/google/cctz/archive/v2.2.tar.gz"],
            sha256 = "ab315d5beb18a65ace57f6ea91f9ea298ec163fee89f84a44e81732af4d07348",
            strip_prefix = "cctz-2.2",
        )

    # RE2 regular-expression framework. Used by some unit-tests.
    if "com_googlesource_code_re2" not in native.existing_rules():
        native.http_archive(
            name = "com_googlesource_code_re2",
            urls = ["https://github.com/google/re2/archive/2018-03-01.tar.gz"],
            sha256 = "51dc7ee9d1a68ee0209672ac4bdff56766c56606dfcdd57aed022015c4784178",
            strip_prefix = "re2-2018-03-01",
        )

    # Absl for C++
    if "com_google_absl" not in native.existing_rules():
        patch_repository(
            name = "com_google_absl",
            # Non-release commit from April 20, 2018
            urls = [
                "https://github.com/abseil/abseil-cpp/archive/94ce52d46c171683b1ee22d14277a6d3bdfd7c4c.tar.gz",
            ],
            patch = "@com_google_asylo//asylo/distrib:absl_mutex.patch",
            sha256 = "eadb5ae992b94102288647399a75ea36e4b112642c86b346b5b5720d8c345b30",
            strip_prefix = "abseil-cpp-94ce52d46c171683b1ee22d14277a6d3bdfd7c4c",
        )

    # Absl for python
    if "io_abseil_py" not in native.existing_rules():
        native.http_archive(
            name = "io_abseil_py",
            # Pre-release commit dated 01/30/2018
            urls = ["https://github.com/abseil/abseil-py/archive/5e343642d987268df199b4c851b7dd3d687ac316.tar.gz"],
            strip_prefix = "abseil-py-5e343642d987268df199b4c851b7dd3d687ac316",
        )

    # Protobuf
    if "com_google_protobuf" not in native.existing_rules():
        patch_repository(
            name = "com_google_protobuf",
            strip_prefix = "protobuf-3.5.1",
            urls = ["https://github.com/google/protobuf/archive/v3.5.1.tar.gz"],
            sha256 = "826425182ee43990731217b917c5c3ea7190cfda141af4869e6d4ad9085a740f",
            patch = "@com_google_asylo//asylo/distrib:protobuf.patch",
        )

    # gRPC
    if "com_github_grpc_grpc" not in native.existing_rules():
        patch_repository(
            name = "com_github_grpc_grpc",
            urls = ["https://github.com/grpc/grpc/archive/v1.13.0.tar.gz"],
            sha256 = "50db9cf2221354485eb7c3bd55a4c27190caef7048a2a1a15fbe60a498f98b44",
            patch = "@com_google_asylo//asylo/distrib:grpc_1_13_0.patch",
            strip_prefix = "grpc-1.13.0",
        )

    # Google certificate transparency has a merkletree implementation.
    if "com_google_certificate_transparency" not in native.existing_rules():
        native.new_http_archive(
            name = "com_google_certificate_transparency",
            # Non-release commit 335536d introduced Merkle trees. They have not been
            # modified since.
            urls = ["https://github.com/google/certificate-transparency/archive/335536d7276e375bdcfd740056506bf503221f03.tar.gz"],
            build_file_content = """
cc_library(
    name = "merkletree",
    hdrs = ["cpp/merkletree/merkle_tree.h"],
    strip_include_prefix = "cpp",
    deps = ["merkletree_impl"],
    visibility = ["//visibility:public"],
)

cc_library(
    name = "merkletree_impl",
    srcs = [
        "cpp/merkletree/merkle_tree.cc",
        "cpp/merkletree/merkle_tree_math.cc",
        "cpp/merkletree/serial_hasher.cc",
        "cpp/merkletree/tree_hasher.cc",
    ],
    strip_include_prefix = "cpp",
    hdrs = [
       "cpp/merkletree/merkle_tree.h",
       "cpp/merkletree/merkle_tree_interface.h",
       "cpp/merkletree/merkle_tree_math.h",
       "cpp/merkletree/serial_hasher.h",
       "cpp/merkletree/tree_hasher.h",
   ],
    deps = ["@boringssl//:crypto"],
    alwayslink = 1,
)
""",
            sha256 = "3a787ff86b55069dad1e394b6f5d225a29a8f70557133064dc69d47a64b614fc",
            strip_prefix = "certificate-transparency-335536d7276e375bdcfd740056506bf503221f03",
        )

    # required by protobuf_python
    if "six_archive" not in native.existing_rules():
        native.new_http_archive(
            name = "six_archive",
            build_file = "@com_google_protobuf//:six.BUILD",
            # Release 1.10.0
            url = "https://pypi.python.org/packages/source/s/six/six-1.10.0.tar.gz",
        )

    native.bind(
        name = "six",
        actual = "@six_archive//:six",
    )

    # Jinja for code_generator.py
    if "jinja" not in native.existing_rules():
        native.new_http_archive(
            name = "jinja",
            # Jinja release 2.10
            url = "https://github.com/pallets/jinja/archive/2.10.tar.gz",
            build_file_content = """py_library(
    name = "jinja2",
    visibility = ["//visibility:public"],
    srcs = glob(["jinja2/*.py"]),
)""",
        )

def asylo_go_deps():
    """Macro to include Asylo's Go dependencies in a WORKSPACE."""

    # go rules for EKEP's go_binary usage.
    if "io_bazel_rules_go" not in native.existing_rules():
        native.http_archive(
            name = "io_bazel_rules_go",
            url = "https://github.com/bazelbuild/rules_go/releases/download/0.10.1/rules_go-0.10.1.tar.gz",
            sha256 = "4b14d8dd31c6dbaf3ff871adcd03f28c3274e42abc855cb8fb4d01233c0154dc",
        )

    # go crypto for EKEP's go_binary usage.
    if "com_github_golang_crypto" not in native.existing_rules():
        native.new_http_archive(
            name = "com_github_golang_crypto",
            build_file_content = """
load("@io_bazel_rules_go//go:def.bzl", "go_library", "go_prefix")
go_prefix("github.com/golang/crypto")

go_library(
    name = "curve25519",
    srcs = [
        "curve25519/const_amd64.h",
        "curve25519/const_amd64.s",
        "curve25519/cswap_amd64.s",
        "curve25519/curve25519.go",
        "curve25519/doc.go",
        "curve25519/freeze_amd64.s",
        "curve25519/ladderstep_amd64.s",
        "curve25519/mont25519_amd64.go",
        "curve25519/mul_amd64.s",
        "curve25519/square_amd64.s",
    ],
    visibility = ["//visibility:public"],
)
go_library(
    name = "hkdf",
    srcs = ["hkdf/hkdf.go"],
    visibility = ["//visibility:public"],
)
""",
            # Non-release commit from March 8, 2018
            urls = ["https://github.com/golang/crypto/archive/c7dcf104e3a7a1417abc0230cb0d5240d764159d.tar.gz"],
            sha256 = "e7b88be3ea254c20e126dfa6caf5169b65ce9e19d91ebe445cedbf8308258e49",
            strip_prefix = "crypto-c7dcf104e3a7a1417abc0230cb0d5240d764159d",
        )

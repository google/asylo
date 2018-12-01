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
load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")

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
        patch_repository(
            name = "com_google_googletest",
            urls = [
                "https://github.com/google/googletest/archive/release-1.8.1.tar.gz",
            ],
            sha256 = "9bf1fe5182a604b4135edc1a425ae356c9ad15e9b23f9f12a02e80184c3a249c",
            strip_prefix = "googletest-release-1.8.1",
            patches = ["@com_google_asylo//asylo/distrib:googletest.patch"],
        )

    # gflags
    if "com_github_gflags_gflags" not in native.existing_rules():
        http_archive(
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
            patches = ["@com_google_asylo//asylo/distrib:boringssl.patch"],
            sha256 = "379e5f0f29e1429b00b44b87b66776d123dd18410b457e0a18e4f0eeff4b94c9",
            strip_prefix = "boringssl-241dc59bb90f8c45ebc8473fc7599b861a93bfa6",
        )

    # RE2 regular-expression framework. Used by some unit-tests.
    if "com_googlesource_code_re2" not in native.existing_rules():
        http_archive(
            name = "com_googlesource_code_re2",
            urls = ["https://github.com/google/re2/archive/2018-03-01.tar.gz"],
            sha256 = "51dc7ee9d1a68ee0209672ac4bdff56766c56606dfcdd57aed022015c4784178",
            strip_prefix = "re2-2018-03-01",
        )

    # Absl for C++
    if "com_google_absl" not in native.existing_rules():
        http_archive(
            name = "com_google_absl",
            # Head commit on Nov 20, 2018.
            urls = [
                "https://github.com/abseil/abseil-cpp/archive/3088e76c597e068479e82508b1770a7ad0c806b6.tar.gz",
            ],
            sha256 = "d10f684f170eb36f3ce752d2819a0be8cc703b429247d7d662ba5b4b48dd7f65",
            strip_prefix = "abseil-cpp-3088e76c597e068479e82508b1770a7ad0c806b6",
        )

    # Absl for python
    if "io_abseil_py" not in native.existing_rules():
        http_archive(
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
            patches = ["@com_google_asylo//asylo/distrib:protobuf.patch"],
        )

    # gRPC
    if "com_github_grpc_grpc" not in native.existing_rules():
        patch_repository(
            name = "com_github_grpc_grpc",
            urls = ["https://github.com/grpc/grpc/archive/v1.13.0.tar.gz"],
            sha256 = "50db9cf2221354485eb7c3bd55a4c27190caef7048a2a1a15fbe60a498f98b44",
            patches = ["@com_google_asylo//asylo/distrib:grpc_1_13_0.patch"],
            strip_prefix = "grpc-1.13.0",
        )

    # Google certificate transparency has a merkletree implementation.
    if "com_google_certificate_transparency" not in native.existing_rules():
        http_archive(
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
        http_archive(
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
        http_archive(
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
        http_archive(
            name = "io_bazel_rules_go",
            url = "https://github.com/bazelbuild/rules_go/releases/download/0.10.1/rules_go-0.10.1.tar.gz",
            sha256 = "4b14d8dd31c6dbaf3ff871adcd03f28c3274e42abc855cb8fb4d01233c0154dc",
        )

    # go crypto for EKEP's go_binary usage.
    if "com_github_golang_crypto" not in native.existing_rules():
        http_archive(
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

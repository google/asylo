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

load("//asylo/bazel:installation_path.bzl", "installation_path")
load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")

# website-docs-metadata
# ---
#
# title:  //asylo/bazel:asylo_deps.bzl
#
# overview: Repository rules for importing dependencies needed for Asylo
#
# location: /_docs/reference/api/bazel/asylo_deps_bzl.md
#
# layout: docs
#
# type: markdown
#
# toc: true
#
# ---
# {% include home.html %}

def _asylo_backend_deps_impl(repository_ctx):
    """Provides all repository files for com_google_asylo_backend_provider.

    While a local_repository would be easier for a single project, this
    dependency has be be usable from external projects as well. A local
    path is inadequate when "local" changes based on the calling project.

    All the files are copied to the workspace's path with empty substitutions
    on file "templates".

    Args:
        repository_ctx: A ctx object all repository rule implementation
            functions are given.
    """
    repository_ctx.template(
        "BUILD",
        Label("@com_google_asylo//asylo/distrib/backend:BUILD.tpl"),
    )
    repository_ctx.template(
        "enclave_info.bzl",
        Label("@com_google_asylo//asylo/distrib/backend:enclave_info.bzl.tpl"),
    )
    repository_ctx.template(
        "transitions.bzl",
        Label("@com_google_asylo//asylo/distrib/backend:transitions.bzl.tpl"),
    )
    repository_ctx.template(
        "WORKSPACE",
        Label("@com_google_asylo//asylo/distrib/backend:WORKSPACE.tpl"),
    )
    repository_ctx.template(
        "empty.txt",
        Label("@com_google_asylo//asylo/distrib/backend:empty.txt"),
    )
    repository_ctx.template(
        "true.c",
        Label("@com_google_asylo//asylo/distrib/backend:true.c"),
    )
    repository_ctx.template(
        "tools/whitelists/function_transition_whitelist/BUILD",
        Label("@com_google_asylo//asylo/distrib/backend/tools/whitelists/function_transition_whitelist:BUILD.tpl"),
    )

# Rule to include Asylo's backend support dependencies in a WORKSPACE.
_asylo_backend_deps = repository_rule(
    implementation = _asylo_backend_deps_impl,
)

def asylo_backend_deps():
    """Macro to include Asylo's tools for defining a backend."""

    # enclave_info.bzl
    if not native.existing_rule("com_google_asylo_backend_provider"):
        _asylo_backend_deps(name = "com_google_asylo_backend_provider")

# Makes Bazel version available in BUILD files as bazel_version.
def _bazel_version_repository_impl(repository_ctx):
    s = "bazel_version = \"" + native.bazel_version + "\""
    repository_ctx.file("bazel_version.bzl", s)
    repository_ctx.file("BUILD", "")

def asylo_testonly_deps():
    """Macro to include Asylo's testing-only dependencies in a WORKSPACE."""

    # GoogleTest/GoogleMock framework. Used by most unit-tests.
    if not native.existing_rule("com_google_googletest"):
        http_archive(
            name = "com_google_googletest",
            # Commit from 2019 December 13
            urls = [
                "https://github.com/google/googletest/archive/5b162a79d49d044690f3eb7d87ecc3b98a3f2e25.tar.gz",
            ],
            sha256 = "a09a41b66083f9be6cd56c4bf1bfb1318e691973dfc4a8f54f025a970a3e9703",
            strip_prefix = "googletest-5b162a79d49d044690f3eb7d87ecc3b98a3f2e25",
        )

def _instantiate_crosstool_impl(repository_ctx):
    """Instantiates the Asylo crosstool template with the installation path.

    The installation path can be an attribute or found from 1 of 3 canonical
    locations (resolved in the following order):
      * $HOME/.asylo/default_toolchain_location [first line has the path]
      * /usr/local/share/asylo/default_toolchain_location [first line has the path]
      * [default fallback] /opt/asylo/toolchains/default

    Args:
      repository_ctx: The repository_rule implementation object.

    Returns:
      Void.
    """
    toolchain_location = installation_path(
        repository_ctx,
        "default_toolchain_location",
        repository_ctx.attr.toolchain_path,
        "/opt/asylo/toolchains/default",
        "Asylo toolchain",
    )

    repository_ctx.symlink(toolchain_location, "toolchain")

_instantiate_crosstool = repository_rule(
    implementation = _instantiate_crosstool_impl,
    local = True,
    attrs = {"toolchain_path": attr.string()},
)

def asylo_deps(toolchain_path = None):
    """Macro to include Asylo's critical dependencies in a WORKSPACE.

    Args:
      toolchain_path: The absolute path to the installed Asylo toolchain.
                      This can be omitted if the path is the first line of
                      /usr/local/share/asylo/default_toolchain_location
    """

    # Asylo macros depend on the backend provider.
    asylo_backend_deps()

    _instantiate_crosstool(
        name = "com_google_asylo_toolchain",
        toolchain_path = toolchain_path,
    )

    # Boringssl
    if not native.existing_rule("boringssl"):
        http_archive(
            name = "boringssl",
            # Commit from 2019 December 13
            urls = [
                "https://github.com/google/boringssl/archive/6a47fc1adc71998756d275050351346e4fb4e2d5.tar.gz",
            ],
            sha256 = "37fabee8aa25d4a7f4eb05071b2c1929991c272cc2cb1cb33305163faea3c668",
            strip_prefix = "boringssl-6a47fc1adc71998756d275050351346e4fb4e2d5",
        )

    # RE2 regular-expression framework. Used by some unit-tests.
    if not native.existing_rule("com_googlesource_code_re2"):
        http_archive(
            name = "com_googlesource_code_re2",
            urls = ["https://github.com/google/re2/archive/2019-12-01.tar.gz"],
            sha256 = "7268e1b4254d9ffa5ccf010fee954150dbb788fd9705234442e7d9f0ee5a42d3",
            strip_prefix = "re2-2019-12-01",
        )

    # Required for Absl, Googletest, Protobuf.
    if not native.existing_rule("rules_cc"):
        http_archive(
            name = "rules_cc",
            # Commit from 2019 December 05
            urls = ["https://github.com/bazelbuild/rules_cc/archive/cd7e8a690caf526e0634e3ca55b10308ee23182d.tar.gz"],
            sha256 = "dafda2ff2a913028ce1718253b6b2f353b2d2163470f3069ca810a0d8d55a5a9",
            strip_prefix = "rules_cc-cd7e8a690caf526e0634e3ca55b10308ee23182d",
        )

    # Required for Protobuf
    if not native.existing_rule("rules_java"):
        http_archive(
            name = "rules_java",
            # Commit from 2019 November 14
            urls = ["https://github.com/bazelbuild/rules_java/archive/32ddd6c4f0ad38a54169d049ec05febc393b58fc.tar.gz"],
            sha256 = "1969a89e8da396eb7754fd0247b7df39b6df433c3dcca0095b4ba30a5409cc9d",
            strip_prefix = "rules_java-32ddd6c4f0ad38a54169d049ec05febc393b58fc",
        )

    # Required for Protobuf.
    if not native.existing_rule("rules_proto"):
        http_archive(
            name = "rules_proto",
            # Commit from 2019 December 04
            urls = ["https://github.com/bazelbuild/rules_proto/archive/2c0468366367d7ed97a1f702f9cd7155ab3f73c5.tar.gz"],
            sha256 = "73ebe9d15ba42401c785f9d0aeebccd73bd80bf6b8ac78f74996d31f2c0ad7a6",
            strip_prefix = "rules_proto-2c0468366367d7ed97a1f702f9cd7155ab3f73c5",
        )

    # Required for Protobuf.
    if not native.existing_rule("rules_python"):
        http_archive(
            name = "rules_python",
            # Commit from 2019 October 23
            urls = ["https://github.com/bazelbuild/rules_python/archive/230f6d15b4ab23cd3a46c54023c9e5fb3e1e3542.tar.gz"],
            sha256 = "52197b7445ab0d9fbdec45bf18e90371ead860280de5cd9b2725669d759a3584",
            strip_prefix = "rules_python-230f6d15b4ab23cd3a46c54023c9e5fb3e1e3542",
        )

    # Absl for C++
    if not native.existing_rule("com_google_absl"):
        http_archive(
            name = "com_google_absl",
            # Commit from 2019 October 24
            urls = [
                "https://github.com/abseil/abseil-cpp/archive/078b89b3c046d230ef3ad39494e5852184eb528b.tar.gz",
            ],
            sha256 = "4fb5b2e2300d47ceab00e9c921520eabf6a093236201df613154c8d0725e9edb",
            strip_prefix = "abseil-cpp-078b89b3c046d230ef3ad39494e5852184eb528b",
        )

    # Absl for python
    if not native.existing_rule("io_abseil_py"):
        http_archive(
            name = "io_abseil_py",
            urls = ["https://github.com/abseil/abseil-py/archive/pypi-v0.8.1.tar.gz"],
            sha256 = "0a145cb81101d1add8b87eaae58c5d51521084bf7cc4e4654928b326a864c6c3",
            strip_prefix = "abseil-py-pypi-v0.8.1",
        )

    # Protobuf
    if not native.existing_rule("com_google_protobuf"):
        http_archive(
            name = "com_google_protobuf",
            strip_prefix = "protobuf-3.10.1",
            urls = ["https://github.com/google/protobuf/archive/v3.10.1.tar.gz"],
            sha256 = "6adf73fd7f90409e479d6ac86529ade2d45f50494c5c10f539226693cb8fe4f7",
        )

    # gRPC
    if not native.existing_rule("com_github_grpc_grpc"):
        http_archive(
            name = "com_github_grpc_grpc",
            urls = ["https://github.com/grpc/grpc/archive/v1.25.0.tar.gz"],
            sha256 = "ffbe61269160ea745e487f79b0fd06b6edd3d50c6d9123f053b5634737cf2f69",
            patches = ["@com_google_asylo//asylo/distrib:grpc_1_25_0.patch"],
            strip_prefix = "grpc-1.25.0",
        )

    # Required by gRPC
    if not native.existing_rule("build_bazel_rules_apple"):
        http_archive(
            name = "build_bazel_rules_apple",
            urls = ["https://github.com/bazelbuild/rules_apple/archive/0.19.0.tar.gz"],
            sha256 = "4bd79bb66d48a629f67515ad4822d293368a0e84f3102e2bd660435c83a20a19",
            strip_prefix = "rules_apple-0.19.0",
        )

    # Required by gRPC
    if not native.existing_rule("build_bazel_rules_swift"):
        http_archive(
            name = "build_bazel_rules_swift",
            urls = ["https://github.com/bazelbuild/rules_swift/archive/0.13.0.tar.gz"],
            sha256 = "617e568aa8263c454f63362f5ab837038da710d646510b8f4a6760ff6361f714",
            strip_prefix = "rules_swift-0.13.0",
        )

    # Required by gRPC
    if not native.existing_rule("build_bazel_apple_support"):
        http_archive(
            name = "build_bazel_apple_support",
            urls = ["https://github.com/bazelbuild/apple_support/archive/0.7.2.tar.gz"],
            sha256 = "519a3bc32132f7b5780e82c2fc6ad2a78d4b28b81561e6fd7b7e0b14ea110074",
            strip_prefix = "apple_support-0.7.2",
        )

    # Required by gRPC
    if not native.existing_rule("bazel_version"):
        _bazel_version_repository = repository_rule(
            implementation = _bazel_version_repository_impl,
            local = True,
        )
        _bazel_version_repository(name = "bazel_version")

    # Google certificate transparency has a merkletree implementation.
    if not native.existing_rule("com_google_certificate_transparency"):
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

    # Required by protobuf
    if not native.existing_rule("bazel_skylib"):
        http_archive(
            name = "bazel_skylib",
            urls = ["https://github.com/bazelbuild/bazel-skylib/archive/1.0.2.tar.gz"],
            sha256 = "e5d90f0ec952883d56747b7604e2a15ee36e288bb556c3d0ed33e818a4d971f2",
            strip_prefix = "bazel-skylib-1.0.2",
        )

    # Required by protobuf and gRPC
    http_archive(
        name = "zlib",
        build_file = "@com_google_protobuf//:third_party/zlib.BUILD",
        sha256 = "629380c90a77b964d896ed37163f5c3a34f6e6d897311f1df2a7016355c45eff",
        strip_prefix = "zlib-1.2.11",
        urls = ["https://github.com/madler/zlib/archive/v1.2.11.tar.gz"],
    )

    # Libcurl for Intel PCS client
    if not native.existing_rule("com_github_curl_curl"):
        http_archive(
            name = "com_github_curl_curl",
            urls = [
                "https://github.com/curl/curl/archive/curl-7_66_0.tar.gz",
            ],
            sha256 = "cd6b8c8c8e9f0c66c72842ec921f800b4524c4b67822c6e4d779446005bc6d8d",
            strip_prefix = "curl-curl-7_66_0",
            build_file = str(Label("//asylo/third_party:curl.BUILD")),
        )

def asylo_go_deps():
    """Macro to include Asylo's Go dependencies in a WORKSPACE."""

    # go rules for EKEP's go_binary usage.
    if not native.existing_rule("io_bazel_rules_go"):
        http_archive(
            name = "io_bazel_rules_go",
            urls = ["https://github.com/bazelbuild/rules_go/archive/v0.20.1.tar.gz"],
            sha256 = "58f52fb4d67506f5e58490146fca5ca41583b36b74e4cd8dcd2a1d9c46ca8c62",
            strip_prefix = "rules_go-0.20.1",
        )

    # go crypto for EKEP's go_binary usage.
    if not native.existing_rule("com_github_golang_crypto"):
        http_archive(
            name = "com_github_golang_crypto",
            build_file_content = """
load("@io_bazel_rules_go//go:def.bzl", "go_library")

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
    importpath = "github.com/golang/crypto/curve25519",
    visibility = ["//visibility:public"],
)
go_library(
    name = "hkdf",
    srcs = ["hkdf/hkdf.go"],
    importpath = "github.com/golang/crypto/hkdf",
    visibility = ["//visibility:public"],
)
""",
            # Commit from 2019 October 29
            urls = ["https://github.com/golang/crypto/archive/8986dd9e96cf0a6f74da406c005ba3df38527c04.tar.gz"],
            sha256 = "053ba0305ae2ccb8f3308c9ca12a6938333b0a6f023f161bbfc4879116ddd271",
            strip_prefix = "crypto-8986dd9e96cf0a6f74da406c005ba3df38527c04",
        )

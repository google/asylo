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
            # Commit from 2020 January 21
            urls = [
                "https://github.com/google/googletest/archive/10b1902d893ea8cc43c69541d70868f91af3646b.tar.gz",
            ],
            sha256 = "ea15d0267d8278ef01c319523e37b81cef3d4e06f0a951c2e6217feceec4fe87",
            strip_prefix = "googletest-10b1902d893ea8cc43c69541d70868f91af3646b",
        )

    # Redis example dependency, only needed if running Redis test with Asylo.
    if not native.existing_rule("com_github_antirez_redis"):
        http_archive(
            name = "com_github_antirez_redis",
            build_file = "@com_google_asylo//asylo/distrib:redis.BUILD",
            urls = ["https://github.com/antirez/redis/archive/5.0.7.tar.gz"],
            sha256 = "2761422599f8969559e66797cd7f606c16e907bf82d962345a7d366c5d1278df",
            strip_prefix = "redis-5.0.7",
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
            # Commit from 2020 January 28
            urls = [
                "https://github.com/google/boringssl/archive/aee09c35c59aa0e12700a426f2c6400af24bd475.tar.gz",
            ],
            sha256 = "ccc2c4a990619bacedf2f9ed531bb6f543c10f857299658886f66f5b8c86af80",
            strip_prefix = "boringssl-aee09c35c59aa0e12700a426f2c6400af24bd475",
        )

    # RE2 regular-expression framework. Used by some unit-tests.
    if not native.existing_rule("com_googlesource_code_re2"):
        http_archive(
            name = "com_googlesource_code_re2",
            urls = ["https://github.com/google/re2/archive/2020-01-01.tar.gz"],
            sha256 = "7509a34636b7dd2966f7a34440cee1153983fd61a4bf8f759a4f7781b9ceebaf",
            strip_prefix = "re2-2020-01-01",
        )

    # Required for Absl, Googletest, Protobuf.
    if not native.existing_rule("rules_cc"):
        http_archive(
            name = "rules_cc",
            # Commit from 2020 January 23
            urls = ["https://github.com/bazelbuild/rules_cc/archive/8774a4decd63f45a636f40a75700c06b7ea9d30a.tar.gz"],
            sha256 = "67e8fc3a4903e2bca1a98800ef1a1d5de8f77249c2cd619cce4171b69c96ca77",
            strip_prefix = "rules_cc-8774a4decd63f45a636f40a75700c06b7ea9d30a",
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
            # Commit from 2020 January 09
            urls = ["https://github.com/bazelbuild/rules_proto/archive/d7666ec475c1f8d4a6803cbc0a0b6b4374360868.tar.gz"],
            sha256 = "3cd625058dc989f6fac0bf8cf7c3cac6d654052500bd8ffea15de1b47bd3d20d",
            strip_prefix = "rules_proto-d7666ec475c1f8d4a6803cbc0a0b6b4374360868",
        )

    # Required for Protobuf.
    if not native.existing_rule("rules_python"):
        http_archive(
            name = "rules_python",
            # Commit from 2019 December 05
            urls = ["https://github.com/bazelbuild/rules_python/archive/38f86fb55b698c51e8510c807489c9f4e047480e.tar.gz"],
            sha256 = "c911dc70f62f507f3a361cbc21d6e0d502b91254382255309bc60b7a0f48de28",
            strip_prefix = "rules_python-38f86fb55b698c51e8510c807489c9f4e047480e",
        )

    # Absl for C++
    if not native.existing_rule("com_google_absl"):
        http_archive(
            name = "com_google_absl",
            # Commit from 2020 January 24
            urls = [
                "https://github.com/abseil/abseil-cpp/archive/44427702614d7b86b064ba06a390f5eb2f85dbf6.tar.gz",
            ],
            sha256 = "979e3a5ff3f8ca417bc4350ebeadd7736c8e9f8ed5ac3d2c524074926c99ea44",
            strip_prefix = "abseil-cpp-44427702614d7b86b064ba06a390f5eb2f85dbf6",
        )

    # Protobuf
    if not native.existing_rule("com_google_protobuf"):
        http_archive(
            name = "com_google_protobuf",
            strip_prefix = "protobuf-3.11.2",
            urls = ["https://github.com/google/protobuf/archive/v3.11.2.tar.gz"],
            sha256 = "e8c7601439dbd4489fe5069c33d374804990a56c2f710e00227ee5d8fd650e67",
        )

    # gRPC
    if not native.existing_rule("com_github_grpc_grpc"):
        http_archive(
            name = "com_github_grpc_grpc",
            urls = ["https://github.com/grpc/grpc/archive/v1.26.0.tar.gz"],
            sha256 = "2fcb7f1ab160d6fd3aaade64520be3e5446fc4c6fa7ba6581afdc4e26094bd81",
            patches = ["@com_google_asylo//asylo/distrib:grpc_1_25_0.patch"],
            strip_prefix = "grpc-1.26.0",
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

    # Google benchmark.
    if not native.existing_rule("com_github_google_benchmark"):
        http_archive(
            name = "com_github_google_benchmark",
            urls = ["https://github.com/google/benchmark/archive/16703ff83c1ae6d53e5155df3bb3ab0bc96083be.zip"],
            strip_prefix = "benchmark-16703ff83c1ae6d53e5155df3bb3ab0bc96083be",
            sha256 = "59f918c8ccd4d74b6ac43484467b500f1d64b40cc1010daa055375b322a43ba3",
        )

    # Google certificate transparency has a merkletree implementation.
    if not native.existing_rule("com_google_certificate_transparency"):
        http_archive(
            name = "com_google_certificate_transparency",
            # Non-release commit 335536d introduced Merkle trees. They have not been
            # modified since.
            urls = ["https://github.com/google/certificate-transparency/archive/335536d7276e375bdcfd740056506bf503221f03.tar.gz"],
            build_file_content = """
load("@rules_cc//cc:defs.bzl", "cc_library")

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
                "https://github.com/curl/curl/archive/curl-7_68_0.tar.gz",
            ],
            sha256 = "32c712e4d8c9fa3b56b5be2242e9e2f1bf1bc1d6ac2c0cc5c50130ecdcd25c48",
            strip_prefix = "curl-curl-7_68_0",
            build_file = str(Label("//asylo/third_party:curl.BUILD")),
        )
    if not native.existing_rule("rules_jvm_external"):
        http_archive(
            name = "rules_jvm_external",
            sha256 = "e246373de2353f3d34d35814947aa8b7d0dd1a58c2f7a6c41cfeaff3007c2d14",
            strip_prefix = "rules_jvm_external-3.1",
            url = "https://github.com/bazelbuild/rules_jvm_external/archive/3.1.zip",
        )

def asylo_go_deps():
    """Macro to include Asylo's Go dependencies in a WORKSPACE."""

    # go rules for EKEP's go_binary usage.
    if not native.existing_rule("io_bazel_rules_go"):
        http_archive(
            name = "io_bazel_rules_go",
            urls = ["https://github.com/bazelbuild/rules_go/archive/v0.21.0.tar.gz"],
            sha256 = "7eebf4ed3a3da3c0f41033624ffcaf8727a46f2702257ccf8576efec808a81d7",
            strip_prefix = "rules_go-0.21.0",
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
        "curve25519/curve25519.go",
        "curve25519/curve25519_amd64.go",
        "curve25519/curve25519_amd64.s",
        "curve25519/curve25519_generic.go",
        "curve25519/curve25519_noasm.go",
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
            # Commit from 2020 January 28
            urls = ["https://github.com/golang/crypto/archive/69ecbb4d6d5dab05e49161c6e77ea40a030884e1.tar.gz"],
            sha256 = "00baaaaeb9779ba4710777dd585fb95d61842fa84517f54484376ae0f3e498a2",
            strip_prefix = "crypto-69ecbb4d6d5dab05e49161c6e77ea40a030884e1",
        )

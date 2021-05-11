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

load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")
load("//asylo/bazel:installation_path.bzl", "installation_path")

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
        "tools/allowlists/function_transition_allowlist/BUILD",
        Label("@com_google_asylo//asylo/distrib/backend/tools/allowlists/function_transition_allowlist:BUILD.tpl"),
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

def _asylo_disable_transitions_impl(repository_ctx):
    pass

_asylo_disable_transitions = repository_rule(
    implementation = _asylo_disable_transitions_impl,
)

def asylo_disable_transitions():
    """Serves as a workspace-wide transition-disable flag."""
    if not native.existing_rule("com_google_asylo_disable_transitions"):
        _asylo_disable_transitions(name = "com_google_asylo_disable_transitions")

def asylo_testonly_deps():
    """Macro to include Asylo's testing-only dependencies in a WORKSPACE."""

    # GoogleTest/GoogleMock framework. Used by most unit-tests.
    if not native.existing_rule("com_google_googletest"):
        http_archive(
            name = "com_google_googletest",
            # Commit from 2021 April 29
            urls = [
                "https://github.com/google/googletest/archive/f5e592d8ee5ffb1d9af5be7f715ce3576b8bf9c4.tar.gz",
            ],
            sha256 = "acfd777f1879f189e9351c4358f3f5179b976312826b391d16ece9ddb1049e09",
            strip_prefix = "googletest-f5e592d8ee5ffb1d9af5be7f715ce3576b8bf9c4",
        )

    # Redis example dependency, only needed if running Redis test with Asylo.
    if not native.existing_rule("com_github_antirez_redis"):
        http_archive(
            name = "com_github_antirez_redis",
            build_file = "@com_google_asylo//asylo/distrib:redis.BUILD",
            urls = ["https://github.com/antirez/redis/archive/6.0.9.tar.gz"],
            sha256 = "2819b6d9c56be1f25cd157b9cb6b7c2733edcb46f4f6bcb1b79cefe639a2853b",
            strip_prefix = "redis-6.0.9",
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
            # Commit from 2021 May 04
            urls = [
                "https://github.com/google/boringssl/archive/9c286f671cfb6d8d6288b93a167c2fd6b1a2aaf4.tar.gz",
            ],
            sha256 = "e1c5fbfc5ce0b2a65969bfe1273296e917816ff33f06ae0a288b725e0cfca988",
            strip_prefix = "boringssl-9c286f671cfb6d8d6288b93a167c2fd6b1a2aaf4",
        )

    # RE2 regular-expression framework. Used by some unit-tests.
    if not native.existing_rule("com_googlesource_code_re2"):
        http_archive(
            name = "com_googlesource_code_re2",
            urls = ["https://github.com/google/re2/archive/2021-04-01.tar.gz"],
            sha256 = "358aedf71dbf26506848905f5d4417b7adba5cf44d3bbcf70bf4ef68ccb0871e",
            strip_prefix = "re2-2021-04-01",
        )

    # Required for Absl, Googletest, Protobuf.
    if not native.existing_rule("rules_cc"):
        http_archive(
            name = "rules_cc",
            # Commit from 2021 April 01
            urls = ["https://github.com/bazelbuild/rules_cc/archive/c612c9581b9e740a49ed4c006edb93912c8ab205.tar.gz"],
            sha256 = "05073d6b8562d9f8913c274b1ec2624c5562b7077da69812b2cb4d7c9aa619ff",
            strip_prefix = "rules_cc-c612c9581b9e740a49ed4c006edb93912c8ab205",
        )

    # Required for Protobuf
    if not native.existing_rule("rules_java"):
        http_archive(
            name = "rules_java",
            # Commit from 2021 March 24
            urls = ["https://github.com/bazelbuild/rules_java/archive/ca8f85f30491148dc86865e1e799d96410f31500.tar.gz"],
            sha256 = "578c2af7dc5571cbf1bb2f8c30a8a12505d5d2feeb1f25e109640417a1f28fb3",
            strip_prefix = "rules_java-ca8f85f30491148dc86865e1e799d96410f31500",
        )

    # Required for Protobuf.
    if not native.existing_rule("rules_proto"):
        http_archive(
            name = "rules_proto",
            # Commit from 2021 February 09
            urls = ["https://github.com/bazelbuild/rules_proto/archive/f7a30f6f80006b591fa7c437fe5a951eb10bcbcf.tar.gz"],
            sha256 = "9fc210a34f0f9e7cc31598d109b5d069ef44911a82f507d5a88716db171615a8",
            strip_prefix = "rules_proto-f7a30f6f80006b591fa7c437fe5a951eb10bcbcf",
        )

    # Required for Protobuf.
    if not native.existing_rule("rules_python"):
        http_archive(
            name = "rules_python",
            # Commit from 2021 April 23
            urls = ["https://github.com/bazelbuild/rules_python/archive/1b4f61b15079d447bb7f8d11894824835e792e6c.tar.gz"],
            sha256 = "a8a4d791385ae08e33978bd278f2ac1151db40c0fdce9af21b37016021f9a492",
            strip_prefix = "rules_python-1b4f61b15079d447bb7f8d11894824835e792e6c",
        )

    # Absl for C++
    if not native.existing_rule("com_google_absl"):
        http_archive(
            name = "com_google_absl",
            # Commit from 2021 May 05
            urls = [
                "https://github.com/abseil/abseil-cpp/archive/037ade20d1132781aae3cda4d547a9e6a5f557bf.tar.gz",
            ],
            sha256 = "be19582576eeaeede9026ec00c9fe920214a2d67eeaf8b27e394f68ebe51844f",
            strip_prefix = "abseil-cpp-037ade20d1132781aae3cda4d547a9e6a5f557bf",
        )

    # Protobuf
    if not native.existing_rule("com_google_protobuf"):
        http_archive(
            name = "com_google_protobuf",
            strip_prefix = "protobuf-3.15.8",
            urls = ["https://github.com/google/protobuf/archive/v3.15.8.tar.gz"],
            sha256 = "0cbdc9adda01f6d2facc65a22a2be5cecefbefe5a09e5382ee8879b522c04441",
        )

    # gRPC
    if not native.existing_rule("com_github_grpc_grpc"):
        http_archive(
            name = "com_github_grpc_grpc",
            urls = ["https://github.com/grpc/grpc/archive/v1.37.1.tar.gz"],
            sha256 = "acf247ec3a52edaee5dee28644a4e485c5e5badf46bdb24a80ca1d76cb8f1174",
            patches = ["@com_google_asylo//asylo/distrib:grpc_1_37_1.patch"],
            strip_prefix = "grpc-1.37.1",
        )

    # Apple build rules. Pulled in by grpc_deps(), but need a newer version to avoid error with Bazel-at-HEAD.
    # Can be removed once https://github.com/bazelbuild/rules_apple/commit/a49fe1b808a42d7eb352d289234bbe2f43e8e1b0 is picked up by gRPC.
    if not native.existing_rule("build_bazel_rules_apple"):
        http_archive(
            name = "build_bazel_rules_apple",
            strip_prefix = "rules_apple-0.31.2",
            sha256 = "06191d8c5f87b1f83426cdf6a6d5fc8df545786815801324a1494f46a8a9c3d3",
            urls = ["https://github.com/bazelbuild/rules_apple/archive/0.31.2.tar.gz"],
        )

    # Google benchmark.
    if not native.existing_rule("com_github_google_benchmark"):
        http_archive(
            name = "com_github_google_benchmark",
            # Commit from 2021 May 05
            urls = ["https://github.com/google/benchmark/archive/d0c227ccfd87de776f0a6e097b0d6039315608a2.zip"],
            strip_prefix = "benchmark-d0c227ccfd87de776f0a6e097b0d6039315608a2",
            sha256 = "90cca93346b8cfd253d54b4da37d535976d1ac4bb53cbf2f754c0c8b81b0b8cf",
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
            urls = ["https://github.com/bazelbuild/bazel-skylib/archive/1.0.3.tar.gz"],
            sha256 = "7ac0fa88c0c4ad6f5b9ffb5e09ef81e235492c873659e6bb99efb89d11246bcb",
            strip_prefix = "bazel-skylib-1.0.3",
        )

    # Required by protobuf
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
                "https://github.com/curl/curl/archive/curl-7_76_1.tar.gz",
            ],
            sha256 = "90d31a1ec2abdf78563e9b365f33404ce83ce72c533072c95158a25d177e2aae",
            strip_prefix = "curl-curl-7_76_1",
            build_file = str(Label("//asylo/third_party:curl.BUILD")),
        )
    if not native.existing_rule("rules_jvm_external"):
        http_archive(
            name = "rules_jvm_external",
            sha256 = "82262ff4223c5fda6fb7ff8bd63db8131b51b413d26eb49e3131037e79e324af",
            strip_prefix = "rules_jvm_external-3.2",
            url = "https://github.com/bazelbuild/rules_jvm_external/archive/3.2.zip",
        )

def asylo_go_deps():
    """Macro to include Asylo's Go dependencies in a WORKSPACE."""

    # go rules for EKEP's go_binary usage.
    if not native.existing_rule("io_bazel_rules_go"):
        http_archive(
            name = "io_bazel_rules_go",
            urls = ["https://github.com/bazelbuild/rules_go/archive/v0.24.14.tar.gz"],
            sha256 = "491d123d48eed27ed1dbbc7804cbb0cd3b4726fc0f0255a6e852f7d8ef8cfd23",
            strip_prefix = "rules_go-0.24.14",
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
            # Commit from 2021 May 03
            urls = ["https://github.com/golang/crypto/archive/e9a32991a82ef02a1e74f495dcc0785239782bfe.tar.gz"],
            sha256 = "2d9983e6f6fa283474477185eaf9a672bade71ee071f562f0d5fef22db0dc686",
            strip_prefix = "crypto-e9a32991a82ef02a1e74f495dcc0785239782bfe",
        )

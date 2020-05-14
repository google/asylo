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
            # Commit from 2020 May 14
            urls = [
                "https://github.com/google/googletest/archive/011959aafddcd30611003de96cfd8d7a7685c700.tar.gz",
            ],
            sha256 = "0e34ac9e3aac3af3977a7ca45c27bb941fbf3a803877a7e440f93a6f9dc9235f",
            strip_prefix = "googletest-011959aafddcd30611003de96cfd8d7a7685c700",
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
            # Commit from 2020 May 05
            urls = [
                "https://github.com/google/boringssl/archive/5733f0412601bc16eb3845c0a402073205bf76dd.tar.gz",
            ],
            sha256 = "9228ebe1718963375ce0e67dd2796879127e095dc2552b348a00facf280938c1",
            strip_prefix = "boringssl-5733f0412601bc16eb3845c0a402073205bf76dd",
        )

    # RE2 regular-expression framework. Used by some unit-tests.
    if not native.existing_rule("com_googlesource_code_re2"):
        http_archive(
            name = "com_googlesource_code_re2",
            urls = ["https://github.com/google/re2/archive/2020-04-01.tar.gz"],
            sha256 = "98794bc5416326817498384a9c43cbb5a406bab8da9f84f83c39ecad43ed5cea",
            strip_prefix = "re2-2020-04-01",
        )

    # Required for Absl, Googletest, Protobuf.
    if not native.existing_rule("rules_cc"):
        http_archive(
            name = "rules_cc",
            # Commit from 2020 May 04
            urls = ["https://github.com/bazelbuild/rules_cc/archive/9ddf8aac74201a57ce37f8ef29a01d3e69318aac.tar.gz"],
            sha256 = "3767974dd5714441199217905f4415a70ad11ab08d7baa24a872ac733779a1a7",
            strip_prefix = "rules_cc-9ddf8aac74201a57ce37f8ef29a01d3e69318aac",
        )

    # Required for Protobuf
    if not native.existing_rule("rules_java"):
        http_archive(
            name = "rules_java",
            # Commit from 2020 February 18
            urls = ["https://github.com/bazelbuild/rules_java/archive/9eb38ebffbaf4414fa3d2292b28e604a256dd5a5.tar.gz"],
            sha256 = "a0adff084a3e8ffac3b88582b208897cd615a29620aa5416337df93a3d3bfd15",
            strip_prefix = "rules_java-9eb38ebffbaf4414fa3d2292b28e604a256dd5a5",
        )

    # Required for Protobuf.
    if not native.existing_rule("rules_proto"):
        http_archive(
            name = "rules_proto",
            # Commit from 2020 April 01
            urls = ["https://github.com/bazelbuild/rules_proto/archive/8b81c3ccfdd0e915e46ffa888d3cdb6116db6fa5.tar.gz"],
            sha256 = "6117a0f96af1d264747ea3f3f29b7b176831ed8acfd428e04f17c48534c83147",
            strip_prefix = "rules_proto-8b81c3ccfdd0e915e46ffa888d3cdb6116db6fa5",
        )

    # Required for Protobuf.
    if not native.existing_rule("rules_python"):
        http_archive(
            name = "rules_python",
            # Commit from 2020 April 09
            urls = ["https://github.com/bazelbuild/rules_python/archive/a0fbf98d4e3a232144df4d0d80b577c7a693b570.tar.gz"],
            sha256 = "76a8fd4e7eca2a3590f816958faa0d83c9b2ce9c32634c5c375bcccf161d3bb5",
            strip_prefix = "rules_python-a0fbf98d4e3a232144df4d0d80b577c7a693b570",
        )

    # Absl for C++
    if not native.existing_rule("com_google_absl"):
        http_archive(
            name = "com_google_absl",
            # Commit from 2020 May 05
            urls = [
                "https://github.com/abseil/abseil-cpp/archive/d85783fd0b1bb32b3d3e04d18367cec8d96c9e9a.tar.gz",
            ],
            sha256 = "1755156cedcfc25548418e9bcc8e1c7a28a68596295e98fea1a78d2b88c7dc2a",
            strip_prefix = "abseil-cpp-d85783fd0b1bb32b3d3e04d18367cec8d96c9e9a",
        )

    # Protobuf
    if not native.existing_rule("com_google_protobuf"):
        http_archive(
            name = "com_google_protobuf",
            strip_prefix = "protobuf-3.11.4",
            urls = ["https://github.com/google/protobuf/archive/v3.11.4.tar.gz"],
            sha256 = "a79d19dcdf9139fa4b81206e318e33d245c4c9da1ffed21c87288ed4380426f9",
        )

    # gRPC
    if not native.existing_rule("com_github_grpc_grpc"):
        http_archive(
            name = "com_github_grpc_grpc",
            urls = ["https://github.com/grpc/grpc/archive/v1.28.1.tar.gz"],
            sha256 = "4cbce7f708917b6e58b631c24c59fe720acc8fef5f959df9a58cdf9558d0a79b",
            patches = ["@com_google_asylo//asylo/distrib:grpc_1_28_1.patch"],
            strip_prefix = "grpc-1.28.1",
        )

    # Google benchmark.
    if not native.existing_rule("com_github_google_benchmark"):
        http_archive(
            name = "com_github_google_benchmark",
            # Commit from 2020 April 23.
            urls = ["https://github.com/google/benchmark/archive/56898e9a92fba537671d5462df9c5ef2ea6a823a.zip"],
            strip_prefix = "benchmark-56898e9a92fba537671d5462df9c5ef2ea6a823a",
            sha256 = "7f45be0bff07d787d75c3864212e9ea5ebba57593b2e487c783d11da70ef6857",
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
                "https://github.com/curl/curl/archive/curl-7_69_1.tar.gz",
            ],
            sha256 = "6d5d2b9c19f31cd42f85d5cd0643122745411de605d3e599fb2a909585aa1196",
            strip_prefix = "curl-curl-7_69_1",
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
            urls = ["https://github.com/bazelbuild/rules_go/archive/v0.22.2.tar.gz"],
            sha256 = "dd79e4e3884119528ccb79586cac662aabb433bc44fa6ab80421a6d11b23781c",
            strip_prefix = "rules_go-0.22.2",
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
            # Commit from 2020 April 29
            urls = ["https://github.com/golang/crypto/archive/4b2356b1ed79e6be3deca3737a3db3d132d2847a.tar.gz"],
            sha256 = "c8eee3eb2e2d01eff51b961f0ac8c6c757aa3744ed15e2c068b58eca989114af",
            strip_prefix = "crypto-4b2356b1ed79e6be3deca3737a3db3d132d2847a",
        )

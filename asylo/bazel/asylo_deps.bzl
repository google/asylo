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
            # Commit from 2020 August 12
            urls = [
                "https://github.com/google/googletest/archive/10ade8473b698a8fe14ddb518c2abd228669657a.tar.gz",
            ],
            sha256 = "b06e0b1e4ee765bc40266fce4bfd699d6f22ae8755c3df8cfa6053ec2dac8b16",
            strip_prefix = "googletest-10ade8473b698a8fe14ddb518c2abd228669657a",
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
            # Commit from 2020 August 12
            urls = [
                "https://github.com/google/boringssl/archive/461b00f40594d6f219efded8aedef9710dd51502.tar.gz",
            ],
            sha256 = "47a134e8ef8a4849208cc0daf47b0dc551689c0a4dea091a80b65b2b5a8de75f",
            strip_prefix = "boringssl-461b00f40594d6f219efded8aedef9710dd51502",
        )

    # RE2 regular-expression framework. Used by some unit-tests.
    if not native.existing_rule("com_googlesource_code_re2"):
        http_archive(
            name = "com_googlesource_code_re2",
            urls = ["https://github.com/google/re2/archive/2020-08-01.tar.gz"],
            sha256 = "6f4c8514249cd65b9e85d3e6f4c35595809a63ad71c5d93083e4d1dcdf9e0cd6",
            strip_prefix = "re2-2020-08-01",
        )

    # Required for Absl, Googletest, Protobuf.
    if not native.existing_rule("rules_cc"):
        http_archive(
            name = "rules_cc",
            # Commit from 2020 July 28
            urls = ["https://github.com/bazelbuild/rules_cc/archive/1477dbab59b401daa94acedbeaefe79bf9112167.tar.gz"],
            sha256 = "b87996d308549fc3933f57a786004ef65b44b83fd63f1b0303a4bbc3fd26bbaf",
            strip_prefix = "rules_cc-1477dbab59b401daa94acedbeaefe79bf9112167",
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
            # Commit from 2020 June 03
            urls = ["https://github.com/bazelbuild/rules_proto/archive/486aaf1808a15b87f1b6778be6d30a17a87e491a.tar.gz"],
            sha256 = "dedb72afb9476b2f75da2f661a00d6ad27dfab5d97c0460cf3265894adfaf467",
            strip_prefix = "rules_proto-486aaf1808a15b87f1b6778be6d30a17a87e491a",
        )

    # Required for Protobuf.
    if not native.existing_rule("rules_python"):
        http_archive(
            name = "rules_python",
            # Commit from 2020 August 03
            urls = ["https://github.com/bazelbuild/rules_python/archive/e3df8bcf0f675d20aaf752c8ba32a0259dd79996.tar.gz"],
            sha256 = "ae3c1380c3c19d47fb474f201862dde7c14601130be2befa73bb02211267e960",
            strip_prefix = "rules_python-e3df8bcf0f675d20aaf752c8ba32a0259dd79996",
        )

    # Absl for C++
    if not native.existing_rule("com_google_absl"):
        http_archive(
            name = "com_google_absl",
            # Commit from 2020 August 12
            urls = [
                "https://github.com/abseil/abseil-cpp/archive/1b7e751e58ce7d40ac7d1ffd944a8e6928994dfa.tar.gz",
            ],
            sha256 = "741a80d684fe0ee498025cc389e8fd617adefbbae09ece6834a15ba2b98a7ed8",
            strip_prefix = "abseil-cpp-1b7e751e58ce7d40ac7d1ffd944a8e6928994dfa",
        )

    # Protobuf
    if not native.existing_rule("com_google_protobuf"):
        http_archive(
            name = "com_google_protobuf",
            strip_prefix = "protobuf-3.12.3",
            urls = ["https://github.com/google/protobuf/archive/v3.12.3.tar.gz"],
            sha256 = "71030a04aedf9f612d2991c1c552317038c3c5a2b578ac4745267a45e7037c29",
        )

    # gRPC
    if not native.existing_rule("com_github_grpc_grpc"):
        http_archive(
            name = "com_github_grpc_grpc",
            urls = ["https://github.com/grpc/grpc/archive/v1.31.0.tar.gz"],
            sha256 = "1236514199d3deb111a6dd7f6092f67617cd2b147f7eda7adbafccea95de7381",
            patches = ["@com_google_asylo//asylo/distrib:grpc_1_31_0.patch"],
            strip_prefix = "grpc-1.31.0",
        )

    # Google benchmark.
    if not native.existing_rule("com_github_google_benchmark"):
        http_archive(
            name = "com_github_google_benchmark",
            # Commit from 2020 July 30
            urls = ["https://github.com/google/benchmark/archive/1302d2ce094a9753b0f81a81ea74c0fa71fae582.zip"],
            strip_prefix = "benchmark-1302d2ce094a9753b0f81a81ea74c0fa71fae582",
            sha256 = "63db6689e3c4f3281c9c620de3094c9910e7a9f503cba020e9cdc1d62c55c5f0",
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
                "https://github.com/curl/curl/archive/curl-7_71_1.tar.gz",
            ],
            sha256 = "3e16bb4a97429a1fa5d7cab7088eeb9fc59b477ea95989ff36ca64cd3bf7364f",
            strip_prefix = "curl-curl-7_71_1",
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
            urls = ["https://github.com/bazelbuild/rules_go/archive/v0.23.8.tar.gz"],
            sha256 = "43493ee1d2c0e745aa39907549800a3c0081b6d8b7496f8e4f69da8e6af70a51",
            strip_prefix = "rules_go-0.23.8",
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
            # Commit from 2020 July 28
            urls = ["https://github.com/golang/crypto/archive/123391ffb6de907695e1066dc40c1ff09322aeb6.tar.gz"],
            sha256 = "33dc94cf3550384c9e5c2236ce00fd7baa1f53543599f35210020bb0f17f2d74",
            strip_prefix = "crypto-123391ffb6de907695e1066dc40c1ff09322aeb6",
        )

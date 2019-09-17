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
    "@com_google_asylo//asylo/bazel:installation_path.bzl",
    "installation_path",
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
            # Commit from 2019 July 18
            urls = [
                "https://github.com/google/googletest/archive/b77e5c76252bac322bb82c5b444f050bd0d92451.tar.gz",
            ],
            sha256 = "b666893f592a7728331e10f36e991e5f6090998dc267e511899215c52835512d",
            strip_prefix = "googletest-b77e5c76252bac322bb82c5b444f050bd0d92451",
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
            # Commit from 2019 July 17
            urls = [
                "https://github.com/google/boringssl/archive/63a4e5c923d647213a435e0ef026faf5cdb7728f.tar.gz",
            ],
            sha256 = "da15106c359924741e0ed741fe348bbcf8bbb5143d53d934b74b25179bdff208",
            strip_prefix = "boringssl-63a4e5c923d647213a435e0ef026faf5cdb7728f",
        )

    # RE2 regular-expression framework. Used by some unit-tests.
    if not native.existing_rule("com_googlesource_code_re2"):
        http_archive(
            name = "com_googlesource_code_re2",
            urls = ["https://github.com/google/re2/archive/2019-07-01.tar.gz"],
            sha256 = "de6c3ee49b2cecdfd2936af18d6947db36726590e566b5915db3746784c55745",
            strip_prefix = "re2-2019-07-01",
        )

    # Required for Absl, Googletest.
    if not native.existing_rule("rules_cc"):
        http_archive(
            name = "rules_cc",
            # Commit from 2019 September 3
            urls = ["https://github.com/bazelbuild/rules_cc/archive/cb2dfba6746bfa3c3705185981f3109f0ae1b893.tar.gz"],
            sha256 = "13ec82e03a878f429a12b618c78412053b559d25351375cbf1bf91c883717b5b",
            strip_prefix = "rules_cc-cb2dfba6746bfa3c3705185981f3109f0ae1b893",
        )

    # Absl for C++
    if not native.existing_rule("com_google_absl"):
        http_archive(
            name = "com_google_absl",
            # Commit from 2019 July 18
            urls = [
                "https://github.com/abseil/abseil-cpp/archive/278b26058c036833a4f7f3047d3f4d9296527f87.tar.gz",
            ],
            sha256 = "6f6bdbd73097dda8912941752f9f3a2ec4acd9fcd15d46fdf618db79ed3f94f1",
            strip_prefix = "abseil-cpp-278b26058c036833a4f7f3047d3f4d9296527f87",
        )

    # Absl for python
    if not native.existing_rule("io_abseil_py"):
        http_archive(
            name = "io_abseil_py",
            urls = ["https://github.com/abseil/abseil-py/archive/pypi-v0.7.1.tar.gz"],
            sha256 = "3d0f39e0920379ff1393de04b573bca3484d82a5f8b939e9e83b20b6106c9bbe",
            strip_prefix = "abseil-py-pypi-v0.7.1",
        )

    # Protobuf
    if not native.existing_rule("com_google_protobuf"):
        http_archive(
            name = "com_google_protobuf",
            strip_prefix = "protobuf-3.9.0",
            urls = ["https://github.com/google/protobuf/archive/v3.9.0.tar.gz"],
            sha256 = "2ee9dcec820352671eb83e081295ba43f7a4157181dad549024d7070d079cf65",
        )

    # gRPC
    if not native.existing_rule("com_github_grpc_grpc"):
        http_archive(
            name = "com_github_grpc_grpc",
            urls = ["https://github.com/grpc/grpc/archive/v1.23.0.tar.gz"],
            sha256 = "f56ced18740895b943418fa29575a65cc2396ccfa3159fa40d318ef5f59471f9",
            patches = ["@com_google_asylo//asylo/distrib:grpc_1_23_0.patch"],
            patch_tool = "patch",
            strip_prefix = "grpc-1.23.0",
        )

    # Required by gRPC
    if not native.existing_rule("build_bazel_rules_apple"):
        http_archive(
            name = "build_bazel_rules_apple",
            urls = ["https://github.com/bazelbuild/rules_apple/archive/0.18.0.tar.gz"],
            sha256 = "53a8f9590b4026fbcfefd02c868e48683b44a314338d03debfb8e8f6c50d1239",
            strip_prefix = "rules_apple-0.18.0",
        )

    # Required by gRPC
    if not native.existing_rule("build_bazel_apple_support"):
        http_archive(
            name = "build_bazel_apple_support",
            urls = ["https://github.com/bazelbuild/apple_support/archive/0.7.1.tar.gz"],
            sha256 = "140fa73e1c712900097aabdb846172ffa0a5e9523b87d6c564c13116a6180a62",
            strip_prefix = "apple_support-0.7.1",
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
            urls = ["https://github.com/bazelbuild/bazel-skylib/releases/download/0.8.0/bazel-skylib.0.8.0.tar.gz"],
            sha256 = "2ef429f5d7ce7111263289644d233707dba35e39696377ebab8b0bc701f7818e",
        )

    # Required by protobuf_python
    if not native.existing_rule("six_archive"):
        http_archive(
            name = "six_archive",
            build_file = "@com_google_protobuf//:six.BUILD",
            url = "https://pypi.python.org/packages/source/s/six/six-1.10.0.tar.gz",
            sha256 = "105f8d68616f8248e24bf0e9372ef04d3cc10104f1980f54d57b2ce73a5ad56a",
        )

    native.bind(
        name = "six",
        actual = "@six_archive//:six",
    )

    # Required by protobuf_python
    native.bind(
        name = "python_headers",
        actual = "@com_google_protobuf//util/python:python_headers",
    )

    # Required by protobuf and gRPC
    http_archive(
        name = "zlib",
        build_file = "@com_google_protobuf//:third_party/zlib.BUILD",
        sha256 = "c3e5e9fdd5004dcb542feda5ee4f0ff0744628baf8ed2dd5d66f8ca1197cb1a1",
        strip_prefix = "zlib-1.2.11",
        urls = ["https://zlib.net/zlib-1.2.11.tar.gz"],
    )

    # Jinja for code_generator.py
    if not native.existing_rule("com_github_pallets_jinja"):
        http_archive(
            name = "com_github_pallets_jinja",
            url = "https://github.com/pallets/jinja/archive/2.10.1.tar.gz",
            build_file_content = """py_library(
    name = "jinja2",
    visibility = ["//visibility:public"],
    srcs = glob(["jinja2/*.py"]),
    deps = ["@com_github_pallets_markupsafe//:markupsafe"],
)""",
            sha256 = "e9baab084b8d84b511c75aca98bba8585041dbe971d5476ee53d9c6eea1b58b3",
            strip_prefix = "jinja-2.10.1",
        )

    # Markupsafe for Jinja
    if not native.existing_rule("com_github_pallets_markupsafe"):
        http_archive(
            name = "com_github_pallets_markupsafe",
            url = "https://github.com/pallets/markupsafe/archive/1.1.1.tar.gz",
            build_file_content = """py_library(
    name = "markupsafe",
    visibility = ["//visibility:public"],
    srcs = glob(["markupsafe/*.py"]),
)""",
            sha256 = "222a10e3237d92a9cd45ed5ea882626bc72bc5e0264d3ed0f2c9129fa69fc167",
            strip_prefix = "markupsafe-1.1.1/src",
        )

def asylo_go_deps():
    """Macro to include Asylo's Go dependencies in a WORKSPACE."""

    # go rules for EKEP's go_binary usage.
    if not native.existing_rule("io_bazel_rules_go"):
        http_archive(
            name = "io_bazel_rules_go",
            urls = ["https://github.com/bazelbuild/rules_go/archive/0.19.1.tar.gz"],
            sha256 = "9df48dcb181f297255c20b6405bc6a0cab445d8f0fcdc3c2af29f6aa98de727f",
            strip_prefix = "rules_go-0.19.1",
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
            # Commit from 2019 July 01
            urls = ["https://github.com/golang/crypto/archive/4def268fd1a49955bfb3dda92fe3db4f924f2285.tar.gz"],
            sha256 = "a967af929cf232a8a363e575f54cf5a97468599e259b00239062c7014ba13e2c",
            strip_prefix = "crypto-4def268fd1a49955bfb3dda92fe3db4f924f2285",
        )

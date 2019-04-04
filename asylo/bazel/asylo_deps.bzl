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
    if not native.existing_rule("com_google_asylo_backend_provider"):
        _asylo_backend_deps(name = "com_google_asylo_backend_provider")

def asylo_testonly_deps():
    """Macro to include Asylo's testing-only dependencies in a WORKSPACE."""

    # GoogleTest/GoogleMock framework. Used by most unit-tests.
    if not native.existing_rule("com_google_googletest"):
        http_archive(
            name = "com_google_googletest",
            urls = [
                "https://github.com/google/googletest/archive/eb9225ce361affe561592e0912320b9db84985d0.tar.gz",
            ],
            sha256 = "a4cb4b0c3ebb191b798594aca674ad47eee255dcb4c26885cf7f49777703484f",
            strip_prefix = "googletest-eb9225ce361affe561592e0912320b9db84985d0",
        )

    # gflags
    if not native.existing_rule("com_github_gflags_gflags"):
        http_archive(
            name = "com_github_gflags_gflags",
            # Release v2.2.2
            urls = ["https://github.com/gflags/gflags/archive/v2.2.2.tar.gz"],
            sha256 = "34af2f15cf7367513b352bdcd2493ab14ce43692d2dcd9dfc499492966c64dcf",
            strip_prefix = "gflags-2.2.2",
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
            # Non-release commit to master-with-bazel branch from March 8, 2018
            urls = [
                "https://github.com/google/boringssl/archive/241dc59bb90f8c45ebc8473fc7599b861a93bfa6.tar.gz",
            ],
            sha256 = "379e5f0f29e1429b00b44b87b66776d123dd18410b457e0a18e4f0eeff4b94c9",
            strip_prefix = "boringssl-241dc59bb90f8c45ebc8473fc7599b861a93bfa6",
        )

    # RE2 regular-expression framework. Used by some unit-tests.
    if not native.existing_rule("com_googlesource_code_re2"):
        http_archive(
            name = "com_googlesource_code_re2",
            urls = ["https://github.com/google/re2/archive/2018-03-01.tar.gz"],
            sha256 = "51dc7ee9d1a68ee0209672ac4bdff56766c56606dfcdd57aed022015c4784178",
            strip_prefix = "re2-2018-03-01",
        )

    # Absl for C++
    if not native.existing_rule("com_google_absl"):
        http_archive(
            name = "com_google_absl",
            # Head commit on 2019-01-31.
            urls = [
                "https://github.com/abseil/abseil-cpp/archive/d78310fe5a82f2e0e6e16509ef8079c8d7e4674e.tar.gz",
            ],
            sha256 = "4c2e4194bbddcb5162933e45fe574d2c4e77a2ef00818b8dac0392459707bfff",
            strip_prefix = "abseil-cpp-d78310fe5a82f2e0e6e16509ef8079c8d7e4674e",
        )

    # Absl for python
    if not native.existing_rule("io_abseil_py"):
        http_archive(
            name = "io_abseil_py",
            # Pre-release commit dated 01/30/2018
            urls = ["https://github.com/abseil/abseil-py/archive/5e343642d987268df199b4c851b7dd3d687ac316.tar.gz"],
            sha256 = "3c83ba6be3df1ea6d2dd1608830853981d47d2a0faa6c9505e4c8022fc41c912",
            strip_prefix = "abseil-py-5e343642d987268df199b4c851b7dd3d687ac316",
        )

    # Protobuf
    if not native.existing_rule("com_google_protobuf"):
        http_archive(
            name = "com_google_protobuf",
            strip_prefix = "protobuf-3.6.1.2",
            urls = ["https://github.com/google/protobuf/archive/v3.6.1.2.tar.gz"],
            sha256 = "2244b0308846bb22b4ff0bcc675e99290ff9f1115553ae9671eba1030af31bc0",
        )

    # gRPC
    if not native.existing_rule("com_github_grpc_grpc"):
        patch_repository(
            name = "com_github_grpc_grpc",
            urls = ["https://github.com/grpc/grpc/archive/v1.19.1.tar.gz"],
            sha256 = "f869c648090e8bddaa1260a271b1089caccbe735bf47ac9cd7d44d35a02fb129",
            patches = ["@com_google_asylo//asylo/distrib:grpc_1_19_1.patch"],
            strip_prefix = "grpc-1.19.1",
        )

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

    # required by protobuf_python
    if not native.existing_rule("six_archive"):
        http_archive(
            name = "six_archive",
            build_file = "@com_google_protobuf//:six.BUILD",
            # Release 1.10.0
            url = "https://pypi.python.org/packages/source/s/six/six-1.10.0.tar.gz",
            sha256 = "105f8d68616f8248e24bf0e9372ef04d3cc10104f1980f54d57b2ce73a5ad56a",
        )

    native.bind(
        name = "six",
        actual = "@six_archive//:six",
    )

    # required by protobuf_python
    native.bind(
        name = "python_headers",
        actual = "@com_google_protobuf//util/python:python_headers",
    )

    # Jinja for code_generator.py
    if not native.existing_rule("com_github_pallets_jinja"):
        http_archive(
            name = "com_github_pallets_jinja",
            # Jinja release 2.10
            url = "https://github.com/pallets/jinja/archive/2.10.tar.gz",
            build_file_content = """py_library(
    name = "jinja2",
    visibility = ["//visibility:public"],
    srcs = glob(["jinja2/*.py"]),
    deps = ["@com_github_pallets_markupsafe//:markupsafe"],
)""",
            sha256 = "0d31d3466c313a9ca014a2d904fed18cdac873a5ba1f7b70b8fd8b206cd860d6",
            strip_prefix = "jinja-2.10",
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
            # Markupsafe release 1.1.1
            sha256 = "222a10e3237d92a9cd45ed5ea882626bc72bc5e0264d3ed0f2c9129fa69fc167",
            strip_prefix = "markupsafe-1.1.1/src",
        )

def asylo_go_deps():
    """Macro to include Asylo's Go dependencies in a WORKSPACE."""

    # go rules for EKEP's go_binary usage.
    if not native.existing_rule("io_bazel_rules_go"):
        http_archive(
            name = "io_bazel_rules_go",
            url = "https://github.com/bazelbuild/rules_go/releases/download/0.17.0/rules_go-0.17.0.tar.gz",
            sha256 = "492c3ac68ed9dcf527a07e6a1b2dcbf199c6bf8b35517951467ac32e421c06c1",
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
            # Non-release commit from January 31, 2019. golang/crypto does not
            # have releases.
            urls = ["https://github.com/golang/crypto/archive/b8fe1690c61389d7d2a8074a507d1d40c5d30448.tar.gz"],
            sha256 = "21bded0f669be39373c16b5bff02916aeaf971f0f5d8696f69fa89297844586d",
            strip_prefix = "crypto-b8fe1690c61389d7d2a8074a507d1d40c5d30448",
        )

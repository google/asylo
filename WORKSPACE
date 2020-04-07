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

# Bazel workspace file for Asylo builds.
workspace(name = "com_google_asylo")

load(
    "//asylo/bazel:asylo_deps.bzl",
    "asylo_backend_deps",
    "asylo_deps",
    "asylo_go_deps",
    "asylo_testonly_deps",
)

asylo_deps()

asylo_backend_deps()

asylo_testonly_deps()

# The following two lines are not strictly necessary, since Asylo
# is suited for multiple backends. In its current form, SGX is the only backend
# available, so these following two lines are default included in the WORKSPACE
# for ease of use.
load("//asylo/bazel:sgx_deps.bzl", "sgx_deps")

sgx_deps()

# Remote backend dependencies.
load("@com_google_asylo//asylo/bazel:remote_deps.bzl", "remote_deps")

remote_deps()

# The grpc dependency is defined by asylo_deps, and load must be top-level,
# so this has to come after asylo_deps().
load("@com_github_grpc_grpc//bazel:grpc_deps.bzl", "grpc_deps")

grpc_deps()

# Projects using gRPC as an external dependency must call both grpc_deps() and
# grpc_extra_deps().
load("@com_github_grpc_grpc//bazel:grpc_extra_deps.bzl", "grpc_extra_deps")

grpc_extra_deps()

# The go targets in Asylo are non-critical, so these dependencies need not be
# pulled in by Asylo users.
asylo_go_deps()

# io_bazel_rules is defined by asylo_go_deps(). Skylark loads cannot be
# produced by macros, so this must come after asylo_go_deps() in WORKSPACE.
load(
    "@io_bazel_rules_go//go:deps.bzl",
    "go_register_toolchains",
    "go_rules_dependencies",
)

# Load go bazel rules and toolchain.
go_rules_dependencies()

go_register_toolchains()

# Load Java dependencies
load("@com_google_asylo//asylo/bazel:java_deps.bzl", "asylo_java_deps")

asylo_java_deps()

load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")

# The following 5 dependencies are for documentation generation.
http_archive(
    name = "io_bazel_skydoc",
    sha256 = "fa548bfea1d485239e6aa20d3d6dd08f53c87d4f468eb57af4d14e311b32990a",
    strip_prefix = "skydoc-0afcfc62f32c644529fa5cdd8ffeec53a46462d6",
    urls = ["https://github.com/bazelbuild/skydoc/archive/0afcfc62f32c644529fa5cdd8ffeec53a46462d6.tar.gz"],
)

load("@io_bazel_skydoc//:setup.bzl", "skydoc_repositories")

skydoc_repositories()

load("@io_bazel_rules_sass//:package.bzl", "rules_sass_dependencies")

rules_sass_dependencies()

load("@build_bazel_rules_nodejs//:defs.bzl", "node_repositories")

node_repositories()

load("@io_bazel_rules_sass//:defs.bzl", "sass_repositories")

sass_repositories()

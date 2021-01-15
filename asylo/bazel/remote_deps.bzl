#
# Copyright 2019 Asylo authors
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

"""Remote backend direct dependencies for WORKSPACE to use."""

load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")
load("@com_github_grpc_grpc//bazel:grpc_deps.bzl", "grpc_deps")

# website-docs-metadata
# ---
#
# title:  //asylo/bazel:remote_deps.bzl
#
# overview: Repository rules for importing dependencies needed for the remote backend
#
# location: /_docs/reference/api/bazel/remote_deps_bzl.md
#
# layout: docs
#
# type: markdown
#
# toc: true
#
# ---
# {% include home.html %}

def remote_deps():
    """Macro to include Asylo remote backend dependencies in a WORKSPACE."""

    if "io_opencensus_cpp" not in native.existing_rules():
        http_archive(
            name = "io_opencensus_cpp",
            # Commit from 2021 January 05
            urls = ["https://github.com/census-instrumentation/opencensus-cpp/archive/afe0460f92fb78e6d6cf8c8a30ced9bc5e2e57d3.tar.gz"],
            sha256 = "5a9928d3901fda00c348ef2fab46aebcbcdf8f036042c254c4b4d3600d683eee",
            strip_prefix = "opencensus-cpp-afe0460f92fb78e6d6cf8c8a30ced9bc5e2e57d3",
        )

    # Remote uses grpc for communications between proxy client and server.
    grpc_deps()

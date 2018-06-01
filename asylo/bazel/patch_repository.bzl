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

"""Implements a repository_rule for applying patches to archives."""

def _patch_repository_impl(repository_ctx):
    """Implements a repository rule to apply a patch to a fetched archive."""
    repository_ctx.download_and_extract(
        url = repository_ctx.attr.urls,
        sha256 = repository_ctx.attr.sha256,
        output = "",
        stripPrefix = repository_ctx.attr.strip_prefix,
    )
    repository_ctx.execute([
        "patch",
        "-p0",
        "-i",
        repository_ctx.path(repository_ctx.attr.patch),
    ])

# This is implemented as part of http_archive in
# @io_bazel//tools/build_defs/repo/http.bzl, but the bootstrapping of getting
# dependencies to define our dependencies is too cumbersome of an interface for
# users to depend on Asylo (A macro cannot use native.http_archive to fetch
# io_bazel and then call load. The load statement must be at the top level).
patch_repository = repository_rule(
    implementation = _patch_repository_impl,
    local = True,
    attrs = {
        "urls": attr.string_list(allow_empty = False, mandatory = True),
        "sha256": attr.string(),
        "patch": attr.label(mandatory = True, allow_single_file = True),
        "strip_prefix": attr.string(),
    },
)

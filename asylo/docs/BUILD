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

"""Targets for public starlark rule and macro documentation."""

licenses(["notice"])

load("@io_bazel_skydoc//stardoc:stardoc.bzl", "stardoc")
load("@bazel_skylib//:bzl_library.bzl", "bzl_library")

bzl_library(
    name = "asylo_bzl_internal_dependendency",
    srcs = ["//asylo/bazel:copts.bzl"],
)

stardoc(
    name = "asylo_bzl-docs",
    out = "asylo_bzl.md",
    func_template = "bzl_function.vm",
    input = "//asylo/bazel:asylo.bzl",
    deps = [
        ":asylo_bzl_internal_dependendency",
        "//asylo/docs/linux_sgx:sgx_sdk_bzl",
        "@com_google_asylo_backend_provider//:enclave_info_bzl",
    ],
)

stardoc(
    name = "dlopen_enclave_bzl-docs",
    out = "dlopen_enclave_bzl.md",
    func_template = "bzl_function.vm",
    input = "//asylo/bazel:dlopen_enclave.bzl",
    deps = ["@com_google_asylo_backend_provider//:enclave_info_bzl"],
)

bzl_library(
    name = "asylo_deps_internal_dependency",
    srcs = ["//asylo/bazel:installation_path.bzl"],
)

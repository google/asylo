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

load("@bazel_skylib//:bzl_library.bzl", "bzl_library")
load("@io_bazel_skydoc//stardoc:stardoc.bzl", "stardoc")

licenses(["notice"])

bzl_library(
    name = "asylo_bzl_internal_dependendency",
    deps = [
        ":starlark_language_rules",
        "//asylo/bazel:asylo_copy_from_host_bzl",
        "//asylo/bazel:asylo_internal_bzl",
        "//asylo/bazel:asylo_transitions_bzl",
        "//asylo/bazel:copts_bzl",
        "//asylo/docs/linux_sgx:sgx_sdk_bzl",
    ],
)

bzl_library(
    name = "asylo_bzl",
    deps = [
        ":asylo_bzl_internal_dependendency",
        ":starlark_language_rules",
        "//asylo/bazel:asylo_bzl",
    ],
)

stardoc(
    name = "asylo_bzl-docs",
    out = "asylo_bzl.md",
    func_template = "bzl_function.vm",
    input = "//asylo/bazel:asylo.bzl",
    deps = [
        ":asylo_bzl_internal_dependendency",
        "//asylo/docs/linux_sgx:sgx_sdk_bzl",
        "@com_google_asylo_backend_provider//:bzl_srcs",
    ],
)

stardoc(
    name = "dlopen_enclave_bzl-docs",
    out = "dlopen_enclave_bzl.md",
    func_template = "bzl_function.vm",
    input = "//asylo/bazel:dlopen_enclave.bzl",
    deps = [
        ":asylo_bzl",
        "@com_google_asylo_backend_provider//:bzl_srcs",
    ],
)

bzl_library(
    name = "tool_srcs",
    srcs = ["@bazel_tools//tools:bzl_srcs"],
)

stardoc(
    name = "asylo_deps_bzl-docs",
    out = "asylo_deps_bzl.md",
    func_template = "bzl_function.vm",
    input = "//asylo/bazel:asylo_deps.bzl",
    deps = [
        ":asylo_deps_internal_dependency",
        ":tool_srcs",
    ],
)

stardoc(
    name = "sgx_deps_bzl-docs",
    out = "sgx_deps_bzl.md",
    func_template = "bzl_function.vm",
    input = "//asylo/bazel:sgx_deps.bzl",
    deps = [
        ":asylo_deps_internal_dependency",
        ":tool_srcs",
    ],
)

bzl_library(
    name = "asylo_deps_internal_dependency",
    srcs = ["//asylo/bazel:installation_path.bzl"],
)

bzl_library(
    name = "starlark_language_rules",
    srcs = [
        "@rules_cc//cc:action_names.bzl",
        "@rules_cc//cc:defs.bzl",
        "@rules_cc//cc:find_cc_toolchain.bzl",
        "@rules_cc//cc/private/rules_impl:srcs",
    ],
)

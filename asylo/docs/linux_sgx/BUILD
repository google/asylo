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

"""Asylo-added starlark rules and macros for linux-sgx."""

load("@bazel_skylib//:bzl_library.bzl", "bzl_library")
load("@io_bazel_skydoc//stardoc:stardoc.bzl", "stardoc")

licenses(["notice"])

stardoc(
    name = "sgx_sdk_bzl-docs",
    out = "sgx_sdk_bzl.md",
    input = "@linux_sgx//:sgx_sdk.bzl",
    deps = ["@com_google_asylo_backend_provider//:bzl_srcs"],
)

bzl_library(
    name = "sgx_sdk_bzl",
    srcs = ["@linux_sgx//:sgx_sdk.bzl"],
    visibility = ["//visibility:public"],
)

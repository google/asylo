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

"""Repository rule for installing Linux SGX backend dependencies."""

load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")

# website-docs-metadata
# ---
#
# title:  //asylo/bazel:sgx_deps.bzl
#
# overview: Repository rules for importing dependencies needed for the SGX backends
#
# location: /_docs/reference/api/bazel/sgx_deps_bzl.md
#
# layout: docs
#
# type: markdown
#
# toc: true
#
# ---
# {% include home.html %}

def sgx_deps():
    """Macro to include Asylo's SGX backend dependencies in a WORKSPACE."""

    # Intel's SGX SDK with patches to make it fit our toolchain.
    if not native.existing_rule("linux_sgx"):
        http_archive(
            name = "linux_sgx",
            urls = ["https://github.com/intel/linux-sgx/archive/sgx_2.6.tar.gz"],
            sha256 = "9d66602c0437d3fa5eb099cbe76815ebd5cca60bc25b4e4af60d2b81bb742d90",
            patches = [
                "@com_google_asylo//asylo/distrib/sgx_x86_64:linux_sgx_2_6.patch",
                "@com_google_asylo//asylo/distrib/sgx_x86_64:enclave_test_pem.patch",
            ],
            strip_prefix = "linux-sgx-sgx_2.6",
        )

    # Intel's SGX Data Center Attestation Primitives with patches to make it
    # build with Bazel.
    if not native.existing_rule("sgx_dcap"):
        http_archive(
            name = "sgx_dcap",
            urls = ["https://github.com/intel/SGXDataCenterAttestationPrimitives/archive/DCAP_1.2.tar.gz"],
            sha256 = "36ae4227056f16d2e3e45b1a9601993ac26a3aaf27762219cbcfa98312a988ce",
            patches = ["@com_google_asylo//asylo/distrib:sgx_dcap_1_2.patch"],
            strip_prefix = "SGXDataCenterAttestationPrimitives-DCAP_1.2",
        )

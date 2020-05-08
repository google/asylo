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
    """Macro to include Asylo's SGX backend dependencies in a WORKSPACE.

    SGX backend dependencies have Intel's highest level of LVI mitigation
    ("All-Loads-Mitigation") applied automatically [1]. This can be customized
    on a per-target basis by specifying one of "lvi_all_loads_mitigation",
    "lvi_control_flow_mitigation", or "lvi_no_auto_mitigation" in the list of
    `transitive_features` on the corresponding unsigned enclave target, or with
    a top-level `--features=lvi_*_mitigation` flag passed to Bazel.

    [1]: https://software.intel.com/security-software-guidance/insights/deep-dive-load-value-injection
    """

    # Intel's SGX SDK with patches to make it fit our toolchain.
    if not native.existing_rule("linux_sgx"):
        http_archive(
            name = "linux_sgx",
            urls = ["https://github.com/intel/linux-sgx/archive/sgx_2.9.tar.gz"],
            sha256 = "95d18cf266ad1dd69c888277980451ace6a30934729ec415f29d601e3e826f1f",
            patches = [
                "@com_google_asylo//asylo/distrib/sgx_x86_64:linux_sgx_2_9.patch",
                "@com_google_asylo//asylo/distrib/sgx_x86_64:enclave_test_pem.patch",
            ],
            strip_prefix = "linux-sgx-sgx_2.9",
        )

    # Intel's SGX Data Center Attestation Primitives with patches to make it
    # build with Bazel.
    if not native.existing_rule("sgx_dcap"):
        http_archive(
            name = "sgx_dcap",
            urls = ["https://github.com/intel/SGXDataCenterAttestationPrimitives/archive/DCAP_1.5.tar.gz"],
            sha256 = "3ba9dcc40fdfe3c5a194be47b9c635e0e7be5a4b416e6346a95726a62857cc3e",
            patches = ["@com_google_asylo//asylo/distrib:sgx_dcap_1_5.patch"],
            strip_prefix = "SGXDataCenterAttestationPrimitives-DCAP_1.5",
        )

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

load(
    "@com_google_asylo//asylo/bazel:patch_repository.bzl",
    "patch_repository",
)

def sgx_deps():
    """Macro to include Asylo's SGX backend dependencies in a WORKSPACE."""

    # Intel's SGX SDK with patches to make it fit our toolchain.
    if not native.existing_rule("linux_sgx"):
        patch_repository(
            name = "linux_sgx",
            urls = ["https://github.com/intel/linux-sgx/archive/sgx_2.4.tar.gz"],
            sha256 = "5a46343823d6dca329b85d82c2ffb58c985908c196f2059932a57854a8a76b3a",
            patches = [
                "@com_google_asylo//asylo/distrib/sgx_x86_64:linux_sgx_2_4.patch",
                "@com_google_asylo//asylo/distrib/sgx_x86_64:enclave_test_pem.patch",
            ],
            strip_prefix = "linux-sgx-sgx_2.4",
        )

    # Intel's SGX Data Center Attestation Primitives with patches to make it
    # build with Bazel.
    if not native.existing_rule("sgx_dcap"):
        patch_repository(
            name = "sgx_dcap",
            urls = ["https://github.com/intel/SGXDataCenterAttestationPrimitives/archive/DCAP_1.0.1.tar.gz"],
            sha256 = "54093b468e6340cccbaf24d68f4ea13a409372efe12cad3e0cac889c1ce19604",
            patches = ["@com_google_asylo//asylo/distrib:sgx_dcap_1_0_1.patch"],
            strip_prefix = "SGXDataCenterAttestationPrimitives-DCAP_1.0.1",
        )

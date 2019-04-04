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
            urls = ["https://github.com/intel/linux-sgx/archive/sgx_2.3.tar.gz"],
            sha256 = "c412b810efb94e9be15d716578483b2fc197b4982fc02b6d13f5dfff3f1d9b14",
            patches = [
                "@com_google_asylo//asylo/distrib/sgx_x86_64:linux_sgx_2_3.patch",
                "@com_google_asylo//asylo/distrib/sgx_x86_64:enclave_test_pem.patch",
            ],
            strip_prefix = "linux-sgx-sgx_2.3",
        )

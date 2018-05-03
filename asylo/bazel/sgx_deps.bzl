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
    "@com_google_asylo//asylo/bazel:installation_path.bzl",
    "installation_path",
)
load(
    "@com_google_asylo//asylo/bazel:patch_repository.bzl",
    "patch_repository",
)

def _instantiate_crosstool_impl(repository_ctx):
    """Instantiates the SGX crosstool template with the installation path.

  The installation path can be an attribute or found from 1 of 3 canonical
  locations (resolved in the following order):
    * $HOME/.asylo/sgx_toolchain_location [first line has the path]
    * /usr/local/share/asylo/sgx_toolchain_location [first line has the path]
    * [default fallback] /opt/asylo/toolchains/sgx_x86_64

  Args:
    repository_ctx: The repository_rule implementation object.

  Returns:
    Void.
  """
    toolchain_location = installation_path(
        repository_ctx,
        "sgx_toolchain_location",
        repository_ctx.attr.installation_path,
        "/opt/asylo/toolchains/sgx_x86_64",
        "sgx toolchain",
    )

    repository_ctx.symlink(toolchain_location, "toolchain")

_instantiate_crosstool = repository_rule(
    implementation = _instantiate_crosstool_impl,
    local = True,
    attrs = {"installation_path": attr.string()},
)

def sgx_deps(installation_path = None):
    """Macro to include Asylo's SGX backend dependencies in a WORKSPACE.

  Args:
    installation_path: The absolute path to the installed SGX toolchain.
                       This can be omitted if the path is the first line of
                       /usr/local/share/asylo/sgx_toolchain_location
  """
    _instantiate_crosstool(
        name = "com_google_asylo_sgx_backend",
        installation_path = installation_path,
    )

    # Intel's SGX SDK with patches to make it fit our toolchain.
    if "linux_sgx" not in native.existing_rules():
        patch_repository(
            name = "linux_sgx",
            urls = ["https://github.com/intel/linux-sgx/archive/sgx_1.9.tar.gz"],
            sha256 = "f858b4873f4f18a355987b1262038bf6ed39417f30259e2c49d4352da6d787a1",
            patch = "@com_google_asylo//asylo/distrib/sgx_x86_64:linux_sgx_1_9.patch",
            strip_prefix = "linux-sgx-sgx_1.9",
        )

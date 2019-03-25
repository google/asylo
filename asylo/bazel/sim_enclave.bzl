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

"""Rule definitions for creating targets for simulated Asylo enclaves."""

load("@com_google_asylo_backend_provider//:enclave_info.bzl", "EnclaveInfo")

SimEnclaveInfo = provider()

def _reprovide_binary_with_enclave_info_impl(ctx):
    return [
        DefaultInfo(
            files = ctx.attr.binary[DefaultInfo].files,
            data_runfiles = ctx.attr.binary[DefaultInfo].data_runfiles,
            default_runfiles = ctx.attr.binary[DefaultInfo].default_runfiles,
        ),
        SimEnclaveInfo(),
        EnclaveInfo(),
    ]

_reprovide_binary_with_enclave_info = rule(
    implementation = _reprovide_binary_with_enclave_info_impl,
    attrs = {
        "binary": attr.label(mandatory = True),
    },
)

def sim_enclave(
        name,
        deps = [],
        **kwargs):
    """Build rule for creating a simulated enclave shared object file.

    A rule like cc_binary, but builds name_simulated.so and provides
    name as a target that may be consumed as an enclave in Asylo.

    Creates two targets:
      name: A binary that may be provided to an enclave loader's enclaves.
      name_simulated.so: The underlying cc_binary which is reprovided as an
                         enclave target. If name has a ".so" suffix, then it
                         is replaced with "_simulated.so".

    Args:
      name: The simulated enclave target name.
      deps: Dependencies for the cc_binary
      **kwargs: cc_binary arguments.
    """
    if not kwargs.pop("linkshared", True):
        fail("A sim_enclave must be build with linkshared = True")
    if not kwargs.pop("linkstatic", True):
        fail("A sim_enclave must be build with linkstatic = True")

    binary_name = name + "_simulated.so"
    if ".so" in name:
        binary_name = name.replace(".so", "_simulated.so", 1)

    native.cc_binary(
        name = binary_name,
        deps = deps + [
            "//asylo/platform/primitives:trusted_primitives",
            "//asylo/platform/primitives/sim:trusted_sim",
        ],
        linkopts = [
            "-Wl,-Bsymbolic",
            "-static",
        ],
        linkshared = True,
        # Link with runtime libraries and don't error on unresolved symbols.
        features = ["dynamic_linking_mode"],
        linkstatic = False,  # Allow the .so to be created, not .a.
        **kwargs
    )
    _reprovide_binary_with_enclave_info(
        name = name,
        testonly = kwargs.get("testonly", 0),
        binary = binary_name,
    )

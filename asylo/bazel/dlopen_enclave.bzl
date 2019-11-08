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

"""Rule definitions for creating targets for dlopen Asylo enclaves."""

load("//asylo/bazel:asylo.bzl", "enclave_loader", "enclave_test")
load("@com_google_asylo_backend_provider//:enclave_info.bzl", "AsyloBackendInfo", "EnclaveInfo")

# website-docs-metadata
# ---
#
# title:  Asylo dlopen backend build rules
#
# overview: Build rules for the process-separated dlopen enclave backend.
#
# location: /_docs/reference/api/bazel/dlopen_enclave_bzl.md
#
# layout: docs
#
# type: markdown
#
# toc: true
#
# ---
# {% include home.html %}

DlopenEnclaveInfo = provider()

def _asylo_dlopen_backend_impl(ctx):
    return [AsyloBackendInfo(
        forward_providers = [EnclaveInfo, DlopenEnclaveInfo, CcInfo],
    )]

asylo_dlopen_backend = rule(
    doc = "Declares name of the Asylo dlopen backend. Used in backend transitions.",
    implementation = _asylo_dlopen_backend_impl,
    attrs = {},
)

def _reprovide_binary_with_enclave_info_impl(ctx):
    return [
        DefaultInfo(
            files = ctx.attr.binary[DefaultInfo].files,
            data_runfiles = ctx.attr.binary[DefaultInfo].data_runfiles,
            default_runfiles = ctx.attr.binary[DefaultInfo].default_runfiles,
        ),
        DlopenEnclaveInfo(),
        EnclaveInfo(),
    ]

_reprovide_binary_with_enclave_info = rule(
    implementation = _reprovide_binary_with_enclave_info_impl,
    attrs = {
        "binary": attr.label(mandatory = True),
    },
)

def primitives_dlopen_enclave(
        name,
        deps = [],
        **kwargs):
    """Build rule for creating a dlopen enclave shared object file.

    This build rule is intended for use by the primitives layer, for building
    enclaves not relying on TrustedApplication.

    A rule like cc_binary, but builds name_dlopen.so and provides
    name as a target that may be consumed as an enclave in Asylo.

    Creates two targets:
      name: A binary that may be provided to an enclave loader's enclaves.
      name_dlopen.so: The underlying cc_binary which is reprovided as an
                         enclave target. If name has a ".so" suffix, then it
                         is replaced with "_dlopen.so".

    Args:
      name: The dlopen enclave target name.
      deps: Dependencies for the cc_binary
      **kwargs: cc_binary arguments.
    """
    if not kwargs.pop("linkshared", True):
        fail("A primitives_dlopen_enclave must be build with linkshared = True")
    if not kwargs.pop("linkstatic", True):
        fail("A primitives_dlopen_enclave must be build with linkstatic = True")

    binary_name = name + "_dlopen.so"
    if ".so" in name:
        binary_name = name.replace(".so", "_dlopen.so", 1)

    native.cc_binary(
        name = binary_name,
        deps = deps + [
            "//asylo/platform/primitives:trusted_primitives",
            "//asylo/platform/primitives/dlopen:trusted_dlopen",
        ],
        linkopts = ["-Wl,-Bsymbolic"],
        linkshared = True,
        features = ["mostly_static_linking_mode"],
        linkstatic = False,  # Allow the .so to be created, not .a.
        **kwargs
    )
    _reprovide_binary_with_enclave_info(
        name = name,
        testonly = kwargs.get("testonly", 0),
        binary = binary_name,
    )

def dlopen_enclave_loader(
        name,
        enclaves = {},
        embedded_enclaves = {},
        loader_args = [],
        remote_proxy = None,
        **kwargs):
    """Thin wrapper around enclave loader, adds necessary linkopts and testonly=1

    Args:
      name: Name for build target.
      enclaves: Dictionary from enclave names to target dependencies. The
        dictionary must be injective. This dictionary is used to format each
        string in `loader_args` after each enclave target is interpreted as the
        path to its output binary.
      embedded_enclaves: Dictionary from ELF section names (that do not start
        with '.') to target dependencies. Each target in the dictionary is
        embedded in the loader binary under the corresponding ELF section.
      loader_args: List of arguments to be passed to `loader`. Arguments may
        contain {enclave_name}-style references to keys from the `enclaves` dict,
        each of which will be replaced with the path to the named enclave.
      remote_proxy: Host-side executable that is going to run remote enclave
        proxy server which will actually load the enclave(s). If empty, the
        enclave(s) are loaded locally.
      **kwargs: cc_binary arguments.
    """

    if "manual" not in kwargs.get("tags", []):
        kwargs["tags"] = kwargs.get("tags", []) + ["manual"]

    enclave_loader(
        name,
        enclaves = enclaves,
        embedded_enclaves = embedded_enclaves,
        loader_args = loader_args,
        testonly = 1,
        remote_proxy = remote_proxy,
        **kwargs
    )

def dlopen_enclave_test(
        name,
        **kwargs):
    """Thin wrapper around enclave test, adds 'asylo-dlopen' tag and necessary linkopts

    Args:
      name: enclave_test name
      **kwargs: same as enclave_test kwargs
    """

    tags = kwargs.pop("tags", [])
    if "asylo-dlopen" not in tags:
        tags += ["asylo-dlopen"]

    enclave_test(
        name,
        tags = tags,
        **kwargs
    )

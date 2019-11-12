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
load("@com_google_asylo_backend_provider//:enclave_info.bzl", "backend_tools")

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

def _primitives_dlopen_enclave_impl(ctx):
    providers = backend_tools.cc_binary(
        ctx,
        ctx.label.name.replace(".so", ""),
        extra_linkopts = ["-Wl,-Bsymbolic"],
        extra_features = ["mostly_static_linking_mode"],
        extra_deps = [ctx.attr._trusted_primitives, ctx.attr._trusted_dlopen],
    )
    return providers + [backend_tools.EnclaveInfo(), DlopenEnclaveInfo()]

primitives_dlopen_enclave = rule(
    implementation = _primitives_dlopen_enclave_impl,
    attrs = backend_tools.merge_dicts(backend_tools.cc_binary_attrs, {
        "_trusted_primitives": attr.label(
            default = "//asylo/platform/primitives:trusted_primitives",
        ),
        "_trusted_dlopen": attr.label(
            default = "//asylo/platform/primitives/dlopen:trusted_dlopen",
        ),
    }),
    fragments = ["cpp"],
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
    enclave_loader(
        name,
        enclaves = enclaves,
        embedded_enclaves = embedded_enclaves,
        loader_args = loader_args,
        backends = ["//asylo/platform/primitives/dlopen"],
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
    enclave_test(
        name,
        backends = ["//asylo/platform/primitives/dlopen"],
        **kwargs
    )

def _forward_debug_sign(ctx):
    # Signing is a no-op. Just copy the target through. There are no runfiles
    # for enclave targets.
    binary_output = ctx.actions.declare_file(ctx.label.name)
    ctx.actions.run_shell(
        inputs = [ctx.file.unsigned],
        command = "cp {} {}".format(ctx.file.unsigned.path, binary_output.path),
        outputs = [binary_output],
    )
    return [
        DefaultInfo(
            files = depset([binary_output]),
            executable = binary_output,
        ),
        OutputGroupInfo(bin = depset([binary_output])),
        backend_tools.EnclaveInfo(),
        DlopenEnclaveInfo(),
    ]

def _asylo_dlopen_backend_impl(ctx):
    return [backend_tools.AsyloBackendInfo(
        forward_providers = [backend_tools.EnclaveInfo, DlopenEnclaveInfo, CcInfo],
        unsigned_enclave_implementation = _primitives_dlopen_enclave_impl,
        debug_sign_implementation = _forward_debug_sign,
    )]

asylo_dlopen_backend = rule(
    doc = "Declares name of the Asylo dlopen backend. Used in backend transitions.",
    implementation = _asylo_dlopen_backend_impl,
    attrs = {},
)

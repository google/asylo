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

load("@com_google_asylo_backend_provider//:enclave_info.bzl", "backend_tools")
load("@com_google_asylo_backend_provider//:transitions.bzl", "transitions")
load("//asylo/bazel:asylo.bzl", "enclave_loader", "enclave_test")
load("//asylo/bazel:asylo_internal.bzl", "internal")

# website-docs-metadata
# ---
#
# title:  //asylo/bazel:dlopen_enclave.bzl
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

DlopenEnclaveInfo = provider(
    doc = ("A provider attached to a dlopen enclave target for compile-time " +
           "type-checking purposes"),
)

def _primitives_dlopen_enclave_impl(ctx):
    providers = backend_tools.cc_binary(
        ctx,
        ctx.label.name.replace(".so", ""),
        extra_linkopts = ["-Wl,-Bsymbolic"],
        extra_features = ["mostly_static_linking_mode"],
        extra_deps = [ctx.attr._trusted_primitives, ctx.attr._trusted_dlopen],
    )
    return providers + [backend_tools.EnclaveInfo(), DlopenEnclaveInfo()]

def _make_primitives_dlopen_enclave(transition):
    transition_dict = {
        "backend": attr.label(
            default = "//asylo/platform/primitives/dlopen",
            providers = [backend_tools.AsyloBackendInfo],
        ),
        "_allowlist_function_transition": attr.label(
            default = "//tools/allowlists/function_transition_allowlist",
        ),
    }
    return rule(
        doc = "Defines a DlOpen enclave binary, similar to cc_binary.",
        implementation = _primitives_dlopen_enclave_impl,
        cfg = transitions.toolchain if transition else None,
        attrs = backend_tools.merge_dicts(backend_tools.cc_binary_attrs(), {
            "_trusted_primitives": attr.label(
                default = "//asylo/platform/primitives:trusted_primitives",
            ),
            "_trusted_dlopen": attr.label(
                default = "//asylo/platform/primitives/dlopen:trusted_dlopen",
            ),
        }, transition_dict if transition else {}),
        fragments = ["cpp"],
    )

_primitives_dlopen_enclave_old = _make_primitives_dlopen_enclave(False)

_primitives_dlopen_enclave_new = _make_primitives_dlopen_enclave(True)

def primitives_dlopen_enclave(name, **kwargs):
    """Defines a cc_binary enclave that uses the dlopen backend.

    Args:
        name: The rule name.
        **kwargs: The arguments to cc_binary.
    """
    _impl = _primitives_dlopen_enclave_old
    kwargs = dict(kwargs)
    if transitions.supported(native.package_name()):
        _impl = _primitives_dlopen_enclave_new
        kwargs["tags"] = kwargs.get("tags", []) + ["asylo-transition"]
    else:
        kwargs["tags"] = kwargs.get("tags", []) + ["asylo-cfh"]
    _impl(name = name, **kwargs)

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
    asylo = internal.package()
    enclave_loader(
        name,
        enclaves = enclaves,
        embedded_enclaves = embedded_enclaves,
        loader_args = loader_args,
        backends = [asylo + "/platform/primitives/dlopen"],
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

    asylo = internal.package()
    enclave_test(
        name,
        backends = [asylo + "/platform/primitives/dlopen"],
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
        untrusted_sign_implementation = _forward_debug_sign,
    )]

asylo_dlopen_backend = rule(
    doc = "Declares name of the Asylo dlopen backend. Used in backend transitions.",
    implementation = _asylo_dlopen_backend_impl,
    attrs = {},
)

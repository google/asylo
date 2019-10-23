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

"""Starlark support for Asylo backends."""

# This provider is accessible to all enclave backends to label their targets as
# enclaves specifically. The enclave_binary and enclave_test macros then use
# this information to understand data dependencies and generate command-line
# arguments to automatically send to the program.
EnclaveInfo = provider()

# Each backend defines a rule that defines itself as an Asylo backend label.
# The provider is used by backend transition rules to do a couple things:
#
#   1. Ensure the passed label is the right type (declared to be a backend).
#   2. Copy important providers through the transition, such as CcInfo, the
#      fact that the target is an enclave (i.e., EnclaveInfo), and which
#      kind of enclave it is (e.g., SGXEnclaveInfo). Each enclave backend has
#      its own rules for defining and using an enclave target, so those
#      providers need to be present for those rules to work correctly.
AsyloBackendInfo = provider(
    doc = "Provided by all Asylo backends." +
          " The forward_providers field is a list of all providers that enclave" +
          " binaries should forward through a transition." +
          " Both EnclaveInfo and CcInfo are good baselines.",
    fields = ["forward_providers"],
)

BACKEND_LABEL = "//third_party/asylo/distrib/backend:backend"

def _asylo_backend_impl(ctx):
    return [AsyloBackendInfo(forward_providers = [EnclaveInfo, CcInfo])]

asylo_backend = rule(implementation = _asylo_backend_impl, attrs = {})

def _asylo_backend_transition_impl(settings, attr):
    _ignore = (settings)
    return {BACKEND_LABEL: attr.backend}

asylo_backend_transition = transition(
    implementation = _asylo_backend_transition_impl,
    inputs = [],
    outputs = [BACKEND_LABEL],
)

def _asylo_maybe_backend_transition_impl(settings, attr):
    return {BACKEND_LABEL: attr.backend or settings[BACKEND_LABEL]}

asylo_maybe_backend_transition = transition(
    implementation = _asylo_maybe_backend_transition_impl,
    inputs = [BACKEND_LABEL],
    outputs = [BACKEND_LABEL],
)

def _forward_target_transition(ctx, executable):
    """Copies cc_target output from a transitioned toolchain to the host.

    Args:
        ctx: Starlark context object.
        executable: True iff the cc_target is executable.

    Returns:
        List of providers.
    """

    # The transition could be a 1:N split transition, but in this case there is
    # only 1 transition target. Thus index by 0 here.
    split_target = ctx.attr.cc_target[0]
    binary_output = ctx.actions.declare_file(ctx.label.name)

    # Copy the cc_target to the expected output location since an executable
    # rule must produce its own executable file.
    ctx.actions.run_shell(
        inputs = [ctx.file.cc_target],
        command = "cp {} {}".format(ctx.file.cc_target.path, binary_output.path),
        outputs = [binary_output],
    )
    new_runfiles = ctx.runfiles(
        files = [binary_output],
        transitive_files = split_target[DefaultInfo].data_runfiles.files,
    )
    result = [
        DefaultInfo(
            files = depset([binary_output]),
            data_runfiles = new_runfiles,
            default_runfiles = new_runfiles,
            executable = binary_output if executable else None,
        ),
        OutputGroupInfo(bin = depset([binary_output])),
    ]

    # Forward the EnclaveInfo provider to allow enclaves to flow to enclave
    # rule positions.
    if ctx.attr.backend:
        for provider in ctx.attr.backend[AsyloBackendInfo].forward_providers:
            if provider in split_target:
                result += [split_target[provider]]
    return result

# All of the following function definitions are to work around starlark's lack
# of lambdas.

def _forward_target_transition_executable(ctx):
    return _forward_target_transition(ctx, executable = True)

def _forward_target_transition_library(ctx):
    return _forward_target_transition(ctx)

def _with_transition_impl(executable):
    if executable:
        return _forward_target_transition_executable
    return _forward_target_transition_library

_BACKEND_DOC = "The Asylo backend label"

def _make_asylo_backend_rule(executable = False, test = False):
    kind_doc = "cc_library"
    if test:
        kind_doc = "cc_test"
    elif executable:
        kind_doc = "cc_binary"
    return rule(
        doc = "Copies a {} target through an explicit backend".format(kind_doc) +
              " transition and forwards runfile info and backend-relevant" +
              " providers.",
        implementation = _with_transition_impl(executable or test),
        executable = executable,
        test = test,
        attrs = {
            "cc_target": attr.label(
                doc = "The target to forward through the backend transition",
                cfg = asylo_backend_transition,
                allow_single_file = True,
                mandatory = True,
                providers = [DefaultInfo],
            ),
            "backend": attr.label(
                doc = _BACKEND_DOC,
                providers = [AsyloBackendInfo],
                mandatory = True,
            ),
        },
    )

transitions = struct(
    backend = asylo_backend_transition,
    maybe_backend = asylo_maybe_backend_transition,
)

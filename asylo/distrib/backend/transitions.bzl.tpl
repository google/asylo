"""Starlark support for backend and toolchain transitions."""

load("@com_google_asylo_backend_provider//:enclave_info.bzl", "AsyloBackendInfo")

BACKEND_LABEL = "@com_google_asylo_backend_provider//:backend"
PRETRANSITION_TAGS = [
    "asylo-pretransition",
    "manual",
]

def _placeholder(**kwargs):
    fail("Transition rules in external repositories are unsupported in Bazel.")

def _empty_transition_impl(settings, attr):
    _ignore = (settings, attr)
    return {}

empty_transition = _placeholder

def _asylo_toolchain_and_backend_transition_impl(settings, attr):
    """Returns the configuration to use the Asylo toolchain."""
    result = {
        "//command_line_option:crosstool_top": "@com_google_asylo_toolchain//toolchain:crosstool",
        "//command_line_option:custom_malloc": "//third_party/unsupported_toolchains/enclave/toolchains:malloc",
        "//command_line_option:dynamic_mode": "off",
        "//command_line_option:host_crosstool_top": "//third_party/crosstool",
        BACKEND_LABEL: attr.backend or settings[BACKEND_LABEL],
    }
    return result

asylo_toolchain_transition = _placeholder

def _asylo_backend_transition_impl(settings, attr):
    _ignore = (settings)
    return {BACKEND_LABEL: attr.backend}

asylo_backend_transition = _placeholder

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
                result.append(split_target[provider])
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

def make_asylo_toolchain_rule(executable = False, test = False, backend_attr = ""):
    """Returns a rule that transitions to the Asylo toolchain and optional backend.

    Args:
        executable: True iff the rule defines an executable.
        test: True iff the rule defines a test.
        backend_attr: The "backend" attribute's default value.

    Returns:
        A starlark rule object.
    """
    attrs = {
        "cc_target": attr.label(
            doc = "The target to forward through the transition" +
                  ("s" if backend_attr else ""),  # Pluralize as necessary.
            cfg = asylo_toolchain_transition,
            allow_single_file = True,
            providers = [DefaultInfo],
            mandatory = True,
        ),
    }
    attrs["backend"] = attr.label(
        doc = _BACKEND_DOC,
        default = None if not backend_attr else backend_attr,
        providers = [AsyloBackendInfo],
    )

    has_executable = executable or test
    kind_doc = "cc_library"
    transition_doc = "an Asylo toolchain transition"
    if test:
        kind_doc = "cc_test"
    elif executable:
        kind_doc = "cc_binary"
    if backend_attr:
        transition_doc += " and {} backend transition".format(backend_attr)
    return rule(
        doc = "Copies a {} target through {}".format(kind_doc, transition_doc) +
              (" and forwards runfile info and" + " backend-relevant providers."),
        implementation = _with_transition_impl(has_executable),
        executable = has_executable,
        test = test,
        attrs = attrs,
    )

def _make_asylo_backend_rule(executable = False, test = False):
    has_executable = executable or test
    kind_doc = "cc_library"
    if test:
        kind_doc = "cc_test"
    elif executable:
        kind_doc = "cc_binary"
    return rule(
        doc = "Copies a {} target through an explicit backend".format(kind_doc) +
              " transition and forwards runfile info and backend-relevant" +
              " providers.",
        implementation = _with_transition_impl(has_executable),
        executable = has_executable,
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

_SUPPORTED_PKGS = [
    # Bazel (v1.0.1) does not support transitions from external dependencies,
    # which com_google_asylo_backend_provider is, so no packages are supported
    # yet.
]

def transitions_supported(package_name):
    """Returns true if a given package has been converted to use transitions.

    Args:
        package_name: The package name that is using an enclave rule.

    Returns:
        True only if package_name is expected to work with transitions.
    """
    for pkg in _SUPPORTED_PKGS:
        if package_name.startswith(pkg):
            return True
    return False

with_asylo_binary = _placeholder
with_asylo_test = _placeholder
with_asylo_library = _placeholder

with_backend_binary = _placeholder
with_backend_test = _placeholder
with_backend_library = _placeholder

transitions = struct(
    toolchain = asylo_toolchain_transition,
    backend = asylo_backend_transition,
    asylo_binary = with_asylo_binary,
    asylo_test = with_asylo_test,
    asylo_library = with_asylo_library,
    backend_binary = with_backend_binary,
    backend_test = with_backend_test,
    backend_library = with_backend_library,
    empty_transition = empty_transition,
    make_rule = make_asylo_toolchain_rule,
    pre_tags = PRETRANSITION_TAGS,
    supported = transitions_supported,
)

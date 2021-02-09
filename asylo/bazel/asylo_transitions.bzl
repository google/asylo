"""Rules that cross toolchain boundaries  by using Bazel transitions."""

load("@com_google_asylo_backend_provider//:enclave_info.bzl", "backend_tools")
load("@com_google_asylo_backend_provider//:transitions.bzl", "transitions")
load(":asylo_internal.bzl", "internal")

def _cc_backend_unsigned_enclave_impl(ctx):
    return ctx.attr.backend[backend_tools.AsyloBackendInfo].unsigned_enclave_implementation(ctx)

def _make_cc_backend_unsigned_enclave(experimental):
    return rule(
        doc = "Defines an unsigned enclave target in the provided backend.",
        implementation = _cc_backend_unsigned_enclave_impl,
        cfg = transitions.toolchain,
        attrs = backend_tools.merge_dicts(
            backend_tools.cc_binary_attrs(),
            {
                "backend": attr.label(
                    mandatory = True,
                    providers = [backend_tools.AsyloBackendInfo],
                ),
                "_allowlist_function_transition": attr.label(
                    default = "//tools/allowlists/function_transition_allowlist",
                ),
            },
            internal.dlopen_implicit_cc_binary_attrs(True) if experimental else {},
            internal.sgx_implicit_cc_binary_attrs,
        ),
        fragments = ["cpp"],
    )

cc_backend_unsigned_enclave = _make_cc_backend_unsigned_enclave(experimental = False)
cc_backend_unsigned_enclave_experimental = _make_cc_backend_unsigned_enclave(experimental = True)

def _backend_sign_enclave_with_untrusted_key_impl(ctx):
    return ctx.attr.backend[backend_tools.AsyloBackendInfo].untrusted_sign_implementation(ctx)

backend_sign_enclave_with_untrusted_key = rule(
    executable = True,
    doc = "Defines the 'signed' version of an unsigned enclave target in" +
          " the provided backend.",
    implementation = _backend_sign_enclave_with_untrusted_key_impl,
    attrs = {
        "backend": attr.label(
            mandatory = True,
            providers = [backend_tools.AsyloBackendInfo],
        ),
        "unsigned": attr.label(
            mandatory = True,
            allow_single_file = True,
        ),
        "config": attr.label(
            default = "//asylo/bazel:default_sign_config",
            allow_single_file = True,
        ),
        "key": attr.label(
            mandatory = True,
            allow_single_file = True,
        ),
        "sign_tool": attr.label(
            mandatory = True,
            allow_single_file = True,
            executable = True,
            cfg = "exec",
        ),
    },
)

def cc_enclave_test(
        name,
        srcs,
        # Passed as an argument to avoid cyclic dependency on asylo.bzl.
        cc_unsigned_enclave,
        sign_enclave_with_untrusted_key,
        enclave_runner_test,
        enclave_config = "",
        remote_proxy = None,
        tags = [],
        deps = [],
        test_in_initialize = False,
        backends = backend_tools.should_be_all_backends,
        unsigned_name_by_backend = {},
        signed_name_by_backend = {},
        test_name_by_backend = {},
        **kwargs):
    """Build target that runs a cc_test srcs inside of an enclave.

    This macro creates two targets, one sign_enclave_with_untrusted_key target with the test
    source. And another test runner application to launch the test enclave.

    Args:
      name: Target name for will be <name>_enclave.
      srcs: Same as cc_test srcs.
      cc_unsigned_enclave: A Starlark macro or rule for defining a cc_binary-
          like target in the Asylo toolchain in any or all backends.
      sign_enclave_with_untrusted_key: A Starlark macro or rule for signing an
          unsigned enclave. Signing key not assumed secret.
      enclave_runner_test: A Starlark macro or rule for combining an enclave
          loader and an enclave to run as a test.
      enclave_config: A backend-specific configuration target to be passed to
          the signer. Optional.
      remote_proxy: Host-side executable that is going to run remote enclave
          proxy server which will actually load the enclave(s). If empty, the
          enclave(s) are loaded locally.
      tags: Same as cc_test tags.
      deps: Same as cc_test deps.
      test_in_initialize: If True, tests run in Initialize, rather than Run. This
          allows us to ensure the initialization and post-initialization execution
          environments provide the same runtime behavior and semantics.
      backends: The asylo backend labels the binary uses. Must specify at least
          one. Defaults to all supported backends. If more than one, then
          name is an alias to a select on backend value to backend-specialized
          targets. See enclave_info.bzl:all_backends documentation for details.
      unsigned_name_by_backend: An optional dictionary from backend label to
          backend-specific name for the defined unsigned enclaves.
      signed_name_by_backend: An optional dictionary from backend label to
          backend-specific name for the defined signed enclaves.
      test_name_by_backend: An optional dictionary from backend label to
          backend-specific name for the test target.
      **kwargs: cc_test arguments.
    """
    return internal.cc_enclave_test(
        name = name,
        srcs = srcs,
        cc_unsigned_enclave = cc_unsigned_enclave,
        sign_enclave_with_untrusted_key = sign_enclave_with_untrusted_key,
        enclave_runner_test = enclave_runner_test,
        host_test = internal.package() + "/bazel:test_shim_loader",
        enclave_config = enclave_config,
        remote_proxy = remote_proxy,
        tags = tags,
        deps = deps,
        test_in_initialize = test_in_initialize,
        backends = backends,
        unsigned_name_by_backend = unsigned_name_by_backend,
        signed_name_by_backend = signed_name_by_backend,
        test_name_by_backend = test_name_by_backend,
        **kwargs
    )

def _enclave_runner_script_impl(ctx):
    """Generates a runnable wrapper script around an enclave loader.

    Given a loader and its enclave/data dependencies, call the loader with
    user-provided arguments. Performs string interpolation over the arguments, to
    populate paths to enclaves.

    Args:
      ctx: A bazel rule context

    Returns:
      The rule's providers. Indicates the data dependencies as runfiles.
    """
    data = ctx.attr.data + ctx.attr.backend_dependent_data
    data_files = ctx.files.data + ctx.files.backend_dependent_data
    args = internal.interpolate_enclave_paths(ctx.attr.enclaves, ctx.attr.loader_args)
    args = [ctx.expand_location(arg, data) for arg in args]
    files = [ctx.file.loader] + ctx.files.enclaves + data_files

    if ctx.file.remote_proxy:
        args = args + ["--remote_proxy='" + ctx.file.remote_proxy.short_path + "'"]
        files = files + [ctx.file.remote_proxy]

    script_src = internal.enclave_runner_script_template.format(
        loader = ctx.file.loader.short_path,
        args = " ".join(args),
    )

    script_file = ctx.actions.declare_file(ctx.label.name)

    ctx.actions.write(
        content = script_src,
        is_executable = True,
        output = script_file,
    )

    return [DefaultInfo(
        executable = script_file,
        runfiles = ctx.runfiles(files = files),
    )]

def _make_enclave_runner_rule(test = False):
    """Returns a rule that generates a script for executing enclave loaders.

    Args:
      test: Whether the rule should be executable as a test.

    Returns:
      The rule.
    """

    return rule(
        implementation = _enclave_runner_script_impl,
        executable = not test,
        test = test,
        attrs = {
            "data": attr.label_list(allow_files = True),
            "enclaves": attr.label_keyed_string_dict(
                allow_files = True,
                cfg = transitions.backend,
                providers = [backend_tools.EnclaveInfo],
            ),
            "loader": attr.label(
                mandatory = True,
                allow_single_file = True,
                cfg = transitions.backend,
            ),
            "remote_proxy": attr.label(
                default = None,
                allow_single_file = True,
            ),
            "loader_args": attr.string_list(),
            "backend": attr.label(
                mandatory = True,
                providers = [backend_tools.AsyloBackendInfo],
            ),
            "backend_dependent_data": attr.label_list(
                cfg = transitions.backend,
                allow_files = True,
                doc = "Like data, but undergoes a backend transition first.",
            ),
            "_allowlist_function_transition": attr.label(
                default = "//tools/allowlists/function_transition_allowlist",
            ),
        },
    )

enclave_runner_script = _make_enclave_runner_rule()
enclave_runner_test = _make_enclave_runner_rule(test = True)

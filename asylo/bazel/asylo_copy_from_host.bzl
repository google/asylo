"""Rules that cross toolchain boundaries without using transitions."""

load("@com_google_asylo_backend_provider//:enclave_info.bzl", "backend_tools")
load(":asylo_internal.bzl", "internal")

def _parse_label(label):
    """Parse a label into (package, name).

    Args:
      label: string in relative or absolute form.

    Returns:
      Pair of strings: package, relative_name
    """
    if label.startswith("//"):  # Absolute label.
        label = label[2:]  # drop the leading //
        colon_split = label.split(":")
        if len(colon_split) == 1:  # no ":" in label
            pkg = label
            _, _, target = label.rpartition("/")
        else:
            pkg, target = colon_split  # fails if len(colon_split) != 2
    else:
        colon_split = label.split(":")
        if len(colon_split) == 1:  # no ":" in label
            pkg, target = native.package_name(), label
        else:
            pkg2, target = colon_split  # fails if len(colon_split) != 2
            pkg = native.package_name() + ("/" + pkg2 if pkg2 else "")
    return pkg, target

def copy_from_host(target, output, name = "", visibility = None):
    """Genrule that builds target with host CROSSTOOL.

    Args:
      target: The host target to be copied.
      output: Location of the target copy made by the rule.
      name: Optional name of the rule; if missing, generated automatically
            from the target.
      visibility: Optional visibility of the rule by other packages;
            default is '//visibility:private' unless default_visibility
            is specified in the package.

    """
    _, local_name = _parse_label(target)
    name = name if name else local_name + "_as_host"
    native.genrule(
        name = name,
        srcs = [],
        outs = [output],
        # Instead of running the "tool" for build-time file generation, copy it
        # to the output so it can be used within the context of a different
        # toolchain.
        cmd = "cp $(location %s) $@" % target,
        executable = 1,
        output_to_bindir = 1,
        # Builds target on the exec platform, which has coincidentally been the
        # same as the host platform. This allows using both the Asylo toolchain
        # and the host toolchain in the same build without using the
        # experimental transitions feature. Only works for executable targets.
        tools = [target],
        testonly = 1,
        visibility = visibility,
    )

def embed_enclaves(name, elf_file, enclaves, **kwargs):
    """Build rule for embedding one or more enclaves into an ELF file.

    Each enclave is embedded in a new ELF section that does not get loaded into
    memory automatically when the elf file is run.

    If the original binary already has a section with the same name as one of
    the given section names, objcopy (and the bazel invocation) will fail with
    an error message stating that the file is in the wrong format.

    Args:
      name: The name of a new ELF file containing the contents of the original
        ELF file and the embedded enclaves.
      elf_file: The ELF file to embed the enclaves in. This target is built with
        the host toolchain.
      enclaves: A dictionary from new ELF section names to the enclave files
        that should be embedded in those sections. The section names may not
        start with ".", since section names starting with "." are reserved for
        the system.
      **kwargs: genrule arguments.
    """
    elf_file_from_host = name + "_elf_file_from_host"
    copy_from_host(target = elf_file, output = elf_file_from_host)
    internal.embed_enclaves(
        name = name,
        elf_file = elf_file_from_host,
        enclaves = enclaves,
        **kwargs
    )

def cc_enclave_test(
        name,
        srcs,
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
      unsigned_name_by_backend: An optional dictionary from backend label to backend-
          specific target label for the defined unsigned enclaves.
      signed_name_by_backend: An optional dictionary from backend label to backend-
          specific target label for the defined signed enclaves.
      test_name_by_backend: An optional dictionary from backend label to
          backend-specific name for the test target.
      **kwargs: cc_test arguments.
    """
    asylo = internal.package()

    # Create a copy of the gtest enclave runner
    host_test_name = name + "_host_driver"
    copy_from_host(
        target = asylo + "/bazel:test_shim_loader",
        output = host_test_name,
        name = name + "_as_host",
    )
    internal.cc_enclave_test(
        name = name,
        srcs = srcs,
        cc_unsigned_enclave = cc_unsigned_enclave,
        sign_enclave_with_untrusted_key = sign_enclave_with_untrusted_key,
        enclave_runner_test = enclave_runner_test,
        host_test = host_test_name,
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

def _backend_sign_enclave_with_untrusted_key_impl(ctx):
    return ctx.attr.backend[backend_tools.AsyloBackendInfo].untrusted_sign_implementation(ctx)

backend_sign_enclave_with_untrusted_key = rule(
    executable = True,
    doc = "Defines the 'signed' version of an unsigned enclave target in" +
          " the provided backend.",
    implementation = _backend_sign_enclave_with_untrusted_key_impl,
    attrs = {
        "backend": attr.label(
            doc = "An Asylo backend label.",
            mandatory = True,
            providers = [backend_tools.AsyloBackendInfo],
        ),
        "unsigned": attr.label(
            doc = "The label of the unsigned enclave target.",
            mandatory = True,
            allow_single_file = True,
        ),
        "config": attr.label(
            doc = "An enclave signer configuration label.",
            mandatory = True,
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

def _cc_backend_unsigned_enclave_impl(ctx):
    return ctx.attr.backend[backend_tools.AsyloBackendInfo].unsigned_enclave_implementation(ctx)

def _make_cc_backend_unsigned_enclave(experimental):
    return rule(
        doc = "Defines an unsigned enclave target in the provided backend.",
        implementation = _cc_backend_unsigned_enclave_impl,
        attrs = backend_tools.merge_dicts(
            backend_tools.cc_binary_attrs(),
            {
                "backend": attr.label(
                    mandatory = True,
                    providers = [backend_tools.AsyloBackendInfo],
                ),
            },
            internal.dlopen_implicit_cc_binary_attrs(False) if experimental else {},
            internal.sgx_implicit_cc_binary_attrs,
        ),
        fragments = ["cpp"],
    )

cc_backend_unsigned_enclave = _make_cc_backend_unsigned_enclave(experimental = False)
cc_backend_unsigned_enclave_experimental = _make_cc_backend_unsigned_enclave(experimental = True)

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
    loader_args = [ctx.expand_location(arg, data) for arg in ctx.attr.loader_args]
    args = internal.interpolate_enclave_paths(
        ctx.attr.enclaves,
        ctx.attr.loader_args,
    )
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
                providers = [backend_tools.EnclaveInfo],
            ),
            "loader": attr.label(
                # If the loader contains embedded enclaves, then it needs to be
                # built with the enclave toolchain, since host-toolchain targets
                # cannot depend on enclave-toolchain targets. As such, it is the
                # responsiblity of the caller to ensure that the loader is built
                # correctly.
                mandatory = True,
                allow_single_file = True,
            ),
            "remote_proxy": attr.label(allow_single_file = True),
            "loader_args": attr.string_list(),
            # Ignored. Added for compatibility with transition rules.
            "backend": attr.label(
                doc = "Unused attribute.",
                default = "@com_google_asylo_backend_provider//:nothing",
            ),
            "backend_dependent_data": attr.label_list(allow_files = True, doc = "Same as data."),
        },
    )

enclave_runner_script = _make_enclave_runner_rule()
enclave_runner_test = _make_enclave_runner_rule(test = True)

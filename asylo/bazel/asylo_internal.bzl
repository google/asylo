"""Shared rules and macros within the Asylo implementation."""

load("@com_google_asylo_backend_provider//:enclave_info.bzl", "backend_tools")
load("@com_google_asylo_backend_provider//:transitions.bzl", "transitions")

def dlopen_implicit_cc_binary_attrs(transition):
    """Returns the implicit rule attributes to include for dlopen backend.

    Args:
        transition: True if the implicit labels should be considered after
            transitioning the backend and toolchain.
    """
    return {
        "_trusted_primitives": attr.label(
            cfg = transitions.toolchain if transition else None,
            default = "//asylo/platform/primitives:trusted_primitives",
        ),
        "_trusted_dlopen": attr.label(
            cfg = transitions.toolchain if transition else None,
            default = "//asylo/platform/primitives/dlopen:trusted_dlopen_generic",
        ),
    }

SGX_IMPLICIT_CC_BINARY_ATTRS = {
    "_lds": attr.label(
        default = "@linux_sgx//:enclave_lds",
        allow_single_file = True,
    ),
}

def asylo_package():
    """Returns an appropriate-to-caller package name for Asylo."""

    return "//asylo" if native.package_name().startswith("asylo") else "@com_google_asylo//asylo"

def internal_embed_enclaves(name, elf_file, enclaves, **kwargs):
    """Build rule for embedding one or more enclaves into an ELF file.

    Each enclave is embedded in a new ELF section that does not get loaded into
    memory automatically when the elf file is run.

    If the original binary already has a section with the same name as one of
    the given section names, objcopy (and the bazel invocation) will fail with
    an error message stating that the file is in the wrong format.

    Args:
      name: The name of a new ELF file containing the contents of the original
        ELF file and the embedded enclaves.
      elf_file: The ELF file to embed the enclaves in.
      enclaves: A dictionary from new ELF section names to the enclave files
        that should be embedded in those sections. The section names may not
        start with ".", since section names starting with "." are reserved for
        the system.
      **kwargs: genrule arguments.
    """

    # GNU-objcopy can't both add a section and set its alignment at the same
    # time. We add the sections in an intermediate step and then align them
    # with a second objcopy.
    genrule_name = name + "_rule"
    intermediate_name = name + "_unaligned"
    objcopy_add_flags = []
    objcopy_align_flags = []
    for section_name, enclave_file in enclaves.items():
        if len(section_name) == 0:
            fail("Section names must be non-empty")
        if section_name[0] == ".":
            fail("User-defined section names may not begin with \".\"")

        # Flags to add each enclave in its own section.
        objcopy_add_flags += [
            "--add-section",
            "\"{section_name}\"=\"$(location {enclave_file})\"".format(
                section_name = section_name,
                enclave_file = enclave_file,
            ),
        ]

        # Alignment flags for the second objcopy
        objcopy_align_flags += [
            "--set-section-flags",
            "\"{section_name}\"=\"code,readonly\"".format(section_name = section_name),
            "--set-section-alignment",
            "\"{section_name}\"=4096".format(section_name = section_name),
        ]
    native.genrule(
        name = genrule_name,
        srcs = enclaves.values() + [elf_file],
        outs = [name],
        output_to_bindir = 1,
        # There can only be one output if the rule is executable, so use a temp
        # file.
        cmd = " && ".join([
            "INTERMEDIATE=$$(mktemp)",
            "$(OBJCOPY) {flags} $(location {elf}) $${{INTERMEDIATE}}".format(
                flags = " ".join(objcopy_add_flags),
                elf = elf_file,
            ),
            "$(OBJCOPY) {flags} $${{INTERMEDIATE}} $@".format(
                flags = " ".join(objcopy_align_flags),
            ),
            "rm $${INTERMEDIATE}",
        ]),
        tags = ["manual"] + kwargs.pop("tags", []),
        toolchains = ["@com_google_asylo_toolchain//toolchain:crosstool"],
        **kwargs
    )

def internal_invert_enclave_name_mapping(names_to_targets):
    """Inverts a name-to-target dict to target-to-name.

    Skylark supports the `label_keyed_string_dict` attribute, which maps Targets
    to strings. This attribute is used to associate enclave targets with enclave
    names.

    For macro users, it is more natural to declare mappings from enclave names to
    enclave targets. As Skylark does not support an attribute that maps strings to
    Targets, this function is used to invert user-supplied dictionaries such that
    they can be passed to this file's custom Skylark rules.

    This function will fail() if `enclaves` is not injective; no two names can map
    to the same enclave target.

    Args:
      names_to_targets: {string: string} Dictionary from enclave names to targets.

    Returns:
      {string: string} Dictionary from enclave targets to names.
    """
    targets_to_names = {}

    # It is an error if multiple names map to the same target. If this dict ends
    # up non-empty this method will fail().
    targets_with_multiple_names = {}

    for name, target in names_to_targets.items():
        existing_name = targets_to_names.get(target, None)
        if existing_name:
            targets_with_multiple_names[target] = \
                targets_with_multiple_names.get(target, [existing_name]) + [name]
        else:
            targets_to_names[target] = name

    if targets_with_multiple_names:
        err_strs = [
            'Enclave target "{target}" mapped to by names {names}'.format(
                target = target,
                names = names,
            )
            for target, names in targets_with_multiple_names.items()
        ]

        fail("Cannot map multiple enclave names to the same enclave target.\n" +
             "\n".join(err_strs))

    return targets_to_names

def internal_cc_enclave_test(
        name,
        srcs,
        # Passed as an argument to avoid cyclic dependency on asylo.bzl.
        cc_unsigned_enclave,
        sign_enclave_with_untrusted_key,
        enclave_runner_test,
        host_test = "//asylo/bazel:test_shim_loader",
        enclave_config = "",
        remote_proxy = None,
        tags = [],
        deps = [],
        backend_dependent_data = [],
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
      host_test: The label of the host test shim.
      enclave_config: A backend-specific configuration target to be passed to
          the signer. Optional.
      remote_proxy: Host-side executable that is going to run remote enclave
          proxy server which will actually load the enclave(s). If empty, the
          enclave(s) are loaded locally.
      tags: Same as cc_test tags.
      deps: Same as cc_test deps.
      backend_dependent_data: Like data, but first underdoes a backend
          transition.
      test_in_initialize: If True, tests run in Initialize, rather than Run. This
          allows us to ensure the initialization and post-initialization execution
          environments provide the same runtime behavior and semantics.
      backends: The asylo backend labels the binary uses. Must specify at least
          one. Defaults to all supported backends. If more than one, then
          name is an alias to a select on backend value to backend-specialized
          targets. See enclave_info.bzl:all_backends documentation for details.
      unsigned_name_by_backend: An optional dictionary from backend label to backend-
          specific target name for the defined unsigned enclaves.
      signed_name_by_backend: An optional dictionary from backend label to backend-
          specific target name for the defined signed enclaves.
      test_name_by_backend: An optional dictionary from backend label to backend-
          specific test nametarget label for the defined signed enclaves.
      **kwargs: cc_test arguments.
    """

    # Work around the constant requirement for the default argument value:
    if host_test == "//asylo/bazel:test_shim_loader":
        host_test = internal.package() + "/bazel:test_shim_loader"

    # Build the gtest enclave using the test file and gtest "main" enclave shim
    enclave_name = name + ".so"
    unsigned_enclave_name = name + "_unsigned.so"
    enclave_target = ":" + enclave_name

    # Collect any arguments to cc_unsigned_enclave that override the defaults
    size = kwargs.pop("size", None)  # Meant for the test.
    data = kwargs.pop("data", [])  # Meant for the test.
    test_args = kwargs.pop("test_args", [])  # Meant for the test.
    cc_unsigned_enclave(
        name = unsigned_enclave_name,
        srcs = srcs,
        deps = deps + [internal.package() + "/bazel:test_shim_enclave"],
        testonly = 1,
        tags = tags,
        backends = backends,
        name_by_backend = unsigned_name_by_backend,
        **kwargs
    )
    sign_enclave_with_untrusted_key(
        name = enclave_name,
        name_by_backend = signed_name_by_backend,
        unsigned = unsigned_enclave_name,
        backends = backends,
        testonly = 1,
        config = enclave_config,
    )

    # //asylo/bazel:test_shim_loader expects the path to
    # :enclave_test_shim to be provided as the --enclave_path command-line flag.
    enclaves = {"shim": enclave_target}
    loader_args = ['--enclave_path="{shim}"'] + test_args
    if test_in_initialize:
        loader_args.append("--test_in_initialize")
    else:
        loader_args.append("--notest_in_initialize")

    # Execute the gtest enclave using the gtest enclave runner
    test_kwargs = {
        "loader": host_test,
        "loader_args": loader_args,
        "enclaves": internal_invert_enclave_name_mapping(enclaves),
        "data": data,
        "backend_dependent_data": backend_dependent_data,
        "remote_proxy": remote_proxy,
        "testonly": 1,
        "size": size,
        "tags": ["enclave_test"] + tags,
    }
    backend_tools.all_backends(
        rule_or_macro = enclave_runner_test,
        name = name,
        backends = backends,
        kwargs = test_kwargs,
        name_by_backend = test_name_by_backend,
        test = True,
    )

internal_enclave_runner_script_template = """#!/bin/bash

# Runfiles is hard. https://github.com/bazelbuild/bazel/issues/4054

if [[ -z "${{RUNFILES}}" ]]; then
  # Canonicalize the path to self.
  pushd "$(dirname "$0")" > /dev/null
  self="$(pwd -P)/$(basename "$0")"
  popd > /dev/null

  if [[ -e "${{self}}.runfiles" ]]; then
    RUNFILES="${{self}}.runfiles"
  elif [[ "${{self}}" == *".runfiles/"* ]]; then
    # Runfiles dir found in self path, so select the nearest containing
    # .runfiles directory.
    RUNFILES="${{self%.runfiles/*}}.runfiles"
  fi
fi

# The loader and argument paths are not relative to ${{RUNFILES}}. Rather, they
# are relative to a directory in ${{RUNFILES}}. The name of this directory is
# specified in "${{RUNFILES}}/MANIFEST", as the first path segment of any listed
# file. For example, MANIFEST may have the contents
# ```
# foo/path/to/loader
# foo/path/to/enclave
# foo/path/to/data
# ```
# In this case, the loader and argument paths are relative to
# "${{RUNFILES}}/foo".

if [[ ! -z "${{RUNFILES}}" && -e "${{RUNFILES}}/MANIFEST" ]]; then
  root_dir_name=$(head -n 1 "${{RUNFILES}}/MANIFEST" | cut -d "/" -f1)

  # Test that the path to the loader is valid before cd'ing.
  if [[ -e "${{RUNFILES}}/${{root_dir_name}}/{loader}" ]]; then
    cd "${{RUNFILES}}/${{root_dir_name}}"
  fi
fi

# This script will still function under `bazel run` even if the above algorithm
# could not change to the proper root directory.

exec "./{loader}" {args} "$@"
"""

def internal_interpolate_enclave_paths(enclaves, args):
    """Replaces {name}-style labels in `args` with enclave paths from `enclaves`.

    `enclaves` maps enclave targets to names. `args` is a list of arguments,
    which may contain the names in {name}-syntax. This function replaces
    occurrences of {name} in `args` with the corresponding enclave's path.

    Example: {Target_1: 'enclave_1'} turns ['--path={enclave_1}'] into
    ['--path=<path/to/Target_1>']

    Note that the paths are relative to the file's "root". In practice this is
    beneath the "runfiles" directory.

    Args:
      enclaves: {Target: string} Mapping from enclave targets to names.
      args: [string] List of arguments to the loader.

    Returns:
      [string] List of arguments to the loader, with names replaced with paths to
        enclaves.
    """

    # It is assumed that `enclaves` is injective, that no two enclaves map to the
    # same name. This is enforced by _invert_enclave_name_mapping.
    names_to_paths = {
        name: enclave.files.to_list()[0].short_path
        for enclave, name in enclaves.items()
    }

    return [arg.format(**names_to_paths) for arg in args]

internal = struct(
    cc_enclave_test = internal_cc_enclave_test,
    dlopen_implicit_cc_binary_attrs = dlopen_implicit_cc_binary_attrs,
    embed_enclaves = internal_embed_enclaves,
    enclave_runner_script_template = internal_enclave_runner_script_template,
    interpolate_enclave_paths = internal_interpolate_enclave_paths,
    invert_enclave_name_mapping = internal_invert_enclave_name_mapping,
    package = asylo_package,
    sgx_implicit_cc_binary_attrs = SGX_IMPLICIT_CC_BINARY_ATTRS,
)

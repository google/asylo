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

"""Macro definitions for Asylo testing."""

load("@com_google_asylo_backend_provider//:enclave_info.bzl", "EnclaveInfo")
load("@linux_sgx//:sgx_sdk.bzl", "sgx_enclave")

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

def _ensure_static_manual(args):
    """Set linkopts and tags keys of args for static linking and manual testing.

    Args:
      args: A map representing the arguments to either cc_binary or cc_test.

    Returns:
      The given args modified for linking and tagging.
    """

    # Fully static so the test can move and still operate
    args["linkstatic"] = 1
    args["copts"] = ["-g0"] + args.get("copts", [])
    return args

def copy_from_host(target, output, name = ""):
    """Genrule that builds target with host CROSSTOOL."""
    _, local_name = _parse_label(target)
    name = name if name else local_name + "_as_host"
    native.genrule(
        name = name,
        srcs = [],
        outs = [output],
        cmd = "cp $(location %s) $@" % target,
        executable = 1,
        output_to_bindir = 1,
        tools = [target],
        testonly = 1,
    )

def _invert_enclave_name_mapping(names_to_targets):
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
            'Enclave target "%s" mapped to by names %s' % (target, names)
            for target, names in targets_with_multiple_names.items()
        ]

        fail("Cannot map multiple enclave names to the same enclave target.\n" +
             "\n".join(err_strs))

    return targets_to_names

def _interpolate_enclave_paths(enclaves, args):
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

def _enclave_runner_script_impl(ctx):
    """Generates a runnable wrapper script around an enclave loader.

    Given a loader and its enclave/data dependencies, call the loader with
    user-provided arguments. Performs string interpolation over the arguments, to
    populate paths to enclaves.

    Arguments:
      ctx: A bazel rule context

    Returns:
      The rule's providers. Indicates the data dependencies as runfiles.
    """

    # Braces in this string are doubled-up to escape them in str.format().
    script_tmpl = """#!/bin/bash

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

    args = _interpolate_enclave_paths(ctx.attr.enclaves, ctx.attr.loader_args)

    script_src = script_tmpl.format(
        loader = ctx.executable.loader.short_path,
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
        runfiles = ctx.runfiles(files = [ctx.executable.loader] +
                                        ctx.files.enclaves +
                                        ctx.files.data),
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
            "loader": attr.label(
                executable = True,
                # If the loader contains embedded enclaves, then it needs to be
                # built with the enclave toolchain, since host-toolchain targets
                # cannot depend on enclave-toolchain targets. As such, it is the
                # responsiblity of the caller to ensure that the loader is built
                # correctly.
                cfg = "target",
                mandatory = True,
                allow_single_file = True,
            ),
            "loader_args": attr.string_list(),
            "enclaves": attr.label_keyed_string_dict(
                allow_files = True,
                providers = [EnclaveInfo],
            ),
            "data": attr.label_list(allow_files = True),
        },
    )

_enclave_runner_script = _make_enclave_runner_rule()
_enclave_runner_test = _make_enclave_runner_rule(test = True)

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
    genrule_name = name + "_rule"
    elf_file_from_host = name + "_elf_file_from_host"

    objcopy_flags = []
    for section_name, enclave_file in enclaves.items():
        if len(section_name) == 0:
            fail("Section names must be non-empty")
        if section_name[0] == ".":
            fail("User-defined section names may not begin with \".\"")
        objcopy_flags += [
            "--add-section",
            "\"{section_name}\"=\"$(location {enclave_file})\"".format(
                section_name = section_name,
                enclave_file = enclave_file,
            ),
        ]

    copy_from_host(target = elf_file, output = elf_file_from_host)
    native.genrule(
        name = genrule_name,
        srcs = enclaves.values() + [elf_file_from_host],
        outs = [name],
        output_to_bindir = 1,
        cmd = "$(OBJCOPY) {objcopy_flags} $(location {elf_file}) $@".format(
            objcopy_flags = " ".join(objcopy_flags),
            elf_file = elf_file_from_host,
        ),
        **kwargs
    )

def enclave_loader(
        name,
        enclaves = {},
        embedded_enclaves = {},
        loader_args = [],
        **kwargs):
    """Wraps a cc_binary with a dependency on enclave availability at runtime.

    Creates a loader for the given enclaves and containing the given embedded
    enclaves. Passes flags according to `loader_args`, which can contain
    references to targets from `enclaves`.

    This macro creates three build targets:
      1) name: shell script that runs `name_host_loader`.
      2) name_loader: cc_binary used as loader in `name`. This is a normal
                      native cc_binary. It cannot be directly run because there
                      is an undeclared dependency on the enclaves.
      3) name_host_loader: genrule that builds `name_loader` with the host
                           crosstool.

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
      **kwargs: cc_binary arguments.
    """
    loader_plain_name = name + "_loader"
    loader_name = name + "_host_loader"

    native.cc_binary(
        name = loader_plain_name,
        **_ensure_static_manual(kwargs)
    )

    # embed_enclaves ensures that the loader's ELF file is built with the host
    # toolchain, even when its enclaves argument is empty.
    embed_enclaves(
        name = loader_name,
        elf_file = loader_plain_name,
        enclaves = embedded_enclaves,
        executable = 1,
    )

    _enclave_runner_script(
        name = name,
        loader = loader_name,
        loader_args = loader_args,
        enclaves = _invert_enclave_name_mapping(enclaves),
        data = kwargs.get("data", []),
    )

def sim_enclave(name, **kwargs):
    """Build rule for creating simulated enclave object files signed for testing.

    The enclave simulation backend currently makes use of the SGX simulator.
    However, this is subject to change and users of this rule should not make
    assumptions about it being related to SGX.

    Args:
      name: The name of the signed enclave object file.
      **kwargs: cc_binary arguments.
    """
    sgx_enclave(name, **kwargs)

def enclave_test(
        name,
        enclaves = {},
        embedded_enclaves = {},
        test_args = [],
        tags = [],
        **kwargs):
    """Build target for testing one or more instances of 'sgx_enclave'.

    Creates a cc_test for a given enclave. Passes flags according to
    `test_args`, which can contain references to targets from `enclaves`.

    Args:
      name: Name for build target.
      enclaves: Dictionary from enclave names to target dependencies. The
        dictionary must be injective. This dictionary is used to format each
        string in `test_args` after each enclave target is interpreted as the
        path to its output binary.
      embedded_enclaves: Dictionary from ELF section names (that do not start
        with '.') to target dependencies. Each target in the dictionary is
        embedded in the test binary under the corresponding ELF section.
      test_args: List of arguments to be passed to the test binary. Arguments may
        contain {enclave_name}-style references to keys from the `enclaves` dict,
        each of which will be replaced with the path to the named enclave. This
        replacement only occurs for non-embedded enclaves.
      tags: Label attached to this test to allow for querying.
      **kwargs: cc_test arguments.

    This macro creates three build targets:
      1) name: sh_test that runs the enclave_test.
      2) name_driver: cc_test used as test loader in `name`. This is a normal
                      native cc_test. It cannot be directly run because there is
                      an undeclared dependency on enclave.
      3) name_host_driver: genrule that builds name_driver with host crosstool.
    """

    test_name = name + "_driver"
    loader_name = name + "_host_driver"

    data = kwargs.get("data", [])
    kwargs.pop("data", None)

    flaky = kwargs.pop("flaky", None)
    size = kwargs.pop("size", None)
    native.cc_binary(
        name = test_name,
        testonly = 1,
        **_ensure_static_manual(kwargs)
    )

    # embed_enclaves ensures that the test loader's ELF file is built with the
    # host toolchain, even when its enclaves argument is empty.
    embed_enclaves(
        name = loader_name,
        elf_file = test_name,
        enclaves = embedded_enclaves,
        testonly = 1,
    )

    _enclave_runner_test(
        name = name,
        loader = loader_name,
        loader_args = test_args,
        enclaves = _invert_enclave_name_mapping(enclaves),
        data = data,
        flaky = flaky,
        size = size,
        testonly = 1,
        tags = ["enclave_test"] + tags,
    )

def cc_test(
        name,
        enclave_test_name = "",
        enclave_test_config = "",
        srcs = [],
        deps = [],
        **kwargs):
    """Build macro that creates a cc_test target and a cc_enclave_test target.

    This macro generates a cc_test target, which will run a gtest test suite
    normally, and optionally a cc_enclave_test, which will run the test suite
    inside of an enclave.

    Args:
      name: Same as native cc_test name.
      enclave_test_name: Name for the generated cc_enclave_test. Optional.
      enclave_test_config: An sgx_enclave_configuration target to be passed to
          the enclave. Optional.
      srcs: Same as native cc_test srcs.
      deps: Same as native cc_test deps.
      **kwargs: cc_test arguments.
    """
    native.cc_test(
        name = name,
        srcs = srcs,
        deps = deps,
        **kwargs
    )

    if enclave_test_name:
        cc_enclave_test(
            name = enclave_test_name,
            srcs = srcs,
            enclave_config = enclave_test_config,
            deps = deps,
            **kwargs
        )

def cc_test_and_cc_enclave_test(
        name,
        enclave_test_name = "",
        enclave_test_config = "",
        srcs = [],
        deps = [],
        **kwargs):
    """An alias for cc_test with a default enclave_test_name.

    This macro is identical to cc_test, except it passes in an enclave
    test name automatically. It is provided for convenience of overriding the
    default definition of cc_test without having to specify enclave test names.
    If this behavior is not desired, use cc_test instead, which will not create
    and enclave test unless given an enclave test name.

    This is most useful if imported as
      load(
          "//asylo/bazel:asylo.bzl",
          cc_test = "cc_test_and_cc_enclave_test",
      )
    so any cc_test defined in the BUILD file will generate both native and
    enclave tests.

    Args:
      name: See documentation for name in native cc_test rule.
      enclave_test_name: See documentation for enclave_test_name in cc_test above.
          If not provided and name ends with "_test", then defaults to name with
          "_test" replaced with "_enclave_test". If not provided and name does
          not end with "_test", then defaults to name appended with "_enclave".
      enclave_test_config: An sgx_enclave_configuration target to be passed to
          the enclave. Optional.
      srcs: See documentation for srcs in native cc_test rule.
      deps: See documentation for deps in native cc_test rule.
      **kwargs: See documentation for **kwargs in native cc_test rule.
    """
    if not enclave_test_name:
        if name.endswith("_test"):
            enclave_test_name = "_enclave_test".join(name.rsplit("_test", 1))
        else:
            enclave_test_name = name + "_enclave"
    cc_test(
        name = name,
        enclave_test_name = enclave_test_name,
        enclave_test_config = enclave_test_config,
        srcs = srcs,
        deps = deps,
        **kwargs
    )

def cc_enclave_test(
        name,
        srcs,
        enclave_config = "",
        tags = [],
        deps = [],
        test_in_initialize = False,
        **kwargs):
    """Build target that runs a cc_test srcs inside of an enclave.

    This macro creates two targets, one sgx_enclave target with the test source.
    And another test runner application to launch the test enclave.

    Args:
      name: Target name for will be <name>_enclave.
      srcs: Same as cc_test srcs.
      enclave_config: An sgx_enclave_configuration target to be passed to the
          enclave. Optional.
      tags: Same as cc_test tags.
      deps: Same as cc_test deps.
      test_in_initialize: If True, tests run in Initialize, rather than Run. This
          allows us to ensure the initialization and post-initialization execution
          environments provide the same runtime behavior and semantics.
      **kwargs: cc_test arguments.
    """

    # Create a copy of the gtest enclave runner
    host_test_name = name + "_host_driver"
    copy_from_host(
        target = "//asylo/bazel:test_shim_loader",
        output = host_test_name,
        name = name + "_as_host",
    )

    # Build the gtest enclave using the test file and gtest "main" enclave shim
    enclave_name = name + ".so"
    enclave_target = ":" + enclave_name

    # Collect any arguments to sgx_enclave that override the defaults
    enclave_kwargs = {}
    if enclave_config:
        enclave_kwargs["config"] = enclave_config

    sgx_enclave(
        name = enclave_name,
        srcs = srcs,
        deps = deps + ["//asylo/bazel:test_shim_enclave"],
        testonly = 1,
        **enclave_kwargs
    )

    # //asylo/bazel:test_shim_loader expects the path to
    # :enclave_test_shim to be provided as the --enclave_path command-line flag.
    enclaves = {"shim": enclave_target}
    loader_args = ['--enclave_path="{shim}"']
    if test_in_initialize:
        loader_args.append("--test_in_initialize")
    else:
        loader_args.append("--notest_in_initialize")

    # Execute the gtest enclave using the gtest enclave runner
    _enclave_runner_test(
        name = name,
        loader = host_test_name,
        loader_args = loader_args,
        enclaves = _invert_enclave_name_mapping(enclaves),
        data = kwargs.get("data", []),
        testonly = 1,
        tags = ["enclave_test"] + tags,
    )

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

load("//asylo/bazel:copts.bzl", "ASYLO_DEFAULT_COPTS")
load("@com_google_asylo_backend_provider//:enclave_info.bzl", "backend_tools")
load("@linux_sgx//:sgx_sdk.bzl", "sgx")

# website-docs-metadata
# ---
#
# title:  Asylo C++ build rules
#
# overview: Build rules for defining enclaves and tests.
#
# location: /_docs/reference/api/bazel/asylo_bzl.md
#
# layout: docs
#
# type: markdown
#
# toc: true
#
# ---
# {% include home.html %}

# Backend tags are used by testing infrastructure to determine which platform
# flags to provide when running tests or building targets.
#
# For example, the enclave_runtime and posix targets can be built with
# any enclave backend, so their tags include ASYLO_ALL_BACKENDS.
# The trusted_sgx target is SGX-only, so its only backend tag is asylo-sgx.
ASYLO_ALL_BACKENDS = [
    "asylo-dlopen",
    "asylo-sgx-hw",
    "asylo-sgx-sim",
]

INTERNAL_SHOULD_BE_ALL_BACKENDS = sgx.backend_labels

DLOPEN_IMPLICIT_CC_BINARY_ATTRS = {
    "_trusted_primitives": attr.label(default = "//asylo/platform/primitives:trusted_primitives"),
    "_trusted_dlopen": attr.label(default = "//asylo/platform/primitives/dlopen:trusted_dlopen_generic"),
}

SGX_IMPLICIT_CC_BINARY_ATTRS = {
    "_lds": attr.label(default = "@linux_sgx//:enclave_lds", allow_single_file = True),
}

ASYLO_ALL_BACKEND_TAGS = ASYLO_ALL_BACKENDS + [
    "manual",
]

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
        cmd = "cp $(location %s) $@" % target,
        executable = 1,
        output_to_bindir = 1,
        tools = [target],
        testonly = 1,
        visibility = visibility,
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

    Args:
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
    files = [ctx.executable.loader] + ctx.files.enclaves + ctx.files.data

    if ctx.executable.remote_proxy:
        args = args + ["--remote_proxy='" + ctx.executable.remote_proxy.short_path + "'"]
        files = files + [ctx.executable.remote_proxy]

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
            "remote_proxy": attr.label(
                default = None,
                executable = True,
                cfg = "target",
                mandatory = False,
                allow_single_file = True,
            ),
            "loader_args": attr.string_list(),
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
        tags = ["manual"],
        toolchains = ["@bazel_tools//tools/cpp:current_cc_toolchain"],
        **kwargs
    )

def enclave_loader(
        name,
        enclaves = {},
        embedded_enclaves = {},
        loader_args = [],
        remote_proxy = None,
        backends = INTERNAL_SHOULD_BE_ALL_BACKENDS,
        deprecation = None,
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
      remote_proxy: Host-side executable that is going to run remote enclave
        proxy server which will actually load the enclave(s). If empty, the
        enclave(s) are loaded locally.
      backends: The asylo backend labels the binary uses. May be a list of
          backend label strings, or a dictionary with backend label string keys
          and struct values with fields "config_settings" and "tags". The
          config_settings field is a list of labels to config_setting targets
          that individually determine that the build configuration selects
          that backend. The tags field is a list of tags that apply to targets
          of that backend. Must specify at least one. Defaults to all supported
          backends. If more than one, then name is an alias to a select on
          backend value to backend-specialized targets. The loader sources
          should be written such that backend-conditional compilation selects
          the right loader code, or supported backends' enclaves can be
          detected and loaded correctly ot run time.
      deprecation: A string deprecation message for uses of this macro that
          have been marked deprecated. Optional.
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
        testonly = kwargs.get("testonly", 0),
        elf_file = loader_plain_name,
        enclaves = embedded_enclaves,
        executable = 1,
    )

    _enclave_runner_script(
        name = name,
        testonly = kwargs.get("testonly", 0),
        loader = loader_name,
        loader_args = loader_args,
        enclaves = _invert_enclave_name_mapping(enclaves),
        remote_proxy = remote_proxy,
        tags = kwargs.get("tags", []) + backend_tools.tags(backends),
        deprecation = deprecation,
        visibility = kwargs.get("visibility", []),
        data = kwargs.get("data", []),
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
        testonly = 1,
        remote_proxy = remote_proxy,
        backends = ["//asylo/platform/primitives/dlopen"],
        deprecation =
            "asylo.bzl:dlopen_enclave_loader is deprecated and will go" +
            " away in the future. Please load from dlopen_enclave.bzl or use" +
            " enclave_loader directly with" +
            " backends = [\"//asylo/platform/primitives/dlopen\"]",
        **kwargs
    )

def _cc_backend_unsigned_enclave_impl(ctx):
    return ctx.attr.backend[backend_tools.AsyloBackendInfo].unsigned_enclave_implementation(ctx)

def _backend_debug_sign_enclave_impl(ctx):
    return ctx.attr.backend[backend_tools.AsyloBackendInfo].debug_sign_implementation(ctx)

cc_backend_unsigned_enclave = rule(
    doc = "Defines an unsigned enclave target in the provided backend.",
    implementation = _cc_backend_unsigned_enclave_impl,
    attrs = backend_tools.merge_dicts(
        backend_tools.cc_binary_attrs,
        {
            "backend": attr.label(mandatory = True, providers = [backend_tools.AsyloBackendInfo]),
        },
        DLOPEN_IMPLICIT_CC_BINARY_ATTRS,
        SGX_IMPLICIT_CC_BINARY_ATTRS,
    ),
    fragments = ["cpp"],
)

backend_debug_sign_enclave = rule(
    executable = True,
    doc = "Defines the 'signed' version of an unsigned enclave target in" +
          " the provided backend.",
    implementation = _backend_debug_sign_enclave_impl,
    attrs = {
        "backend": attr.label(mandatory = True, providers = [backend_tools.AsyloBackendInfo]),
        "unsigned": attr.label(mandatory = True, allow_single_file = True),
        "config": attr.label(
            default = "//asylo/bazel:default_sign_config",
            allow_single_file = True,
        ),
        "_key": attr.label(
            default = "//asylo/bazel:debug_key",
            allow_single_file = True,
        ),
        "_sign_tool": attr.label(
            default = Label("//asylo/bazel:sign_tool"),
            allow_single_file = True,
            executable = True,
            cfg = "host",
        ),
    },
)

def cc_unsigned_enclave(
        name,
        backends = INTERNAL_SHOULD_BE_ALL_BACKENDS,
        name_by_backend = {},
        **kwargs):
    """Creates a C++ unsigned enclave target in all or any backend.

    Args:
      name: The rule name.
      backends: The asylo backend labels the binary uses. Must specify at least
          one. Defaults to all supported backends. If more than one, then
          name is an alias to a select on backend value to backend-specialized
          targets.
      name_by_backend: An optional dictionary from backend label to backend-
          specific target label.
      **kwargs: Remainder arguments to the backend rule.
    """
    backend_tools.all_backends(cc_backend_unsigned_enclave, name, backends, name_by_backend, kwargs)

def debug_sign_enclave(
        name,
        unsigned,
        backends = INTERNAL_SHOULD_BE_ALL_BACKENDS,
        config = None,
        testonly = 0,
        name_by_backend = {}):
    """Signs an unsigned enclave according the the backend's signing procedure.

    Args:
        name: The signed enclave target name.
        unsigned: The label to the unsigned enclave.
        backends: The asylo backend labels the binary uses. Must specify at least
          one. Defaults to all supported backends. If more than one, then
          name is an alias to a select on backend value to backend-specialized
          targets.
        config: A label to a config target that the backend-specific signing
            tool uses.
        testonly: True if the target should only be used in tests.
      name_by_backend: An optional dictionary from backend label to backend-
          specific target label.
    """
    kwargs = {"unsigned": unsigned, "testonly": testonly}
    if config:
        kwargs["config"] = config
    backend_tools.all_backends(backend_debug_sign_enclave, name, backends, name_by_backend, kwargs)

# The section to embed the application enclave in.
_APPLICATION_WRAPPER_ENCLAVE_SECTION = "enclave"

def cc_enclave_binary(
        name,
        application_enclave_config = "",
        enclave_build_config = "",
        application_library_linkstatic = True,
        backends = INTERNAL_SHOULD_BE_ALL_BACKENDS,
        unsigned_name_by_backend = {},
        signed_name_by_backend = {},
        **kwargs):
    """Creates a cc_binary that runs an application inside an enclave.

    Mostly compatible with the cc_binary interface. The following options are
    not supported:

      * linkshared
      * malloc
      * stamp

    Usage of unsupported aspects of the cc_binary interface will result in build
    failures.

    fork() inside Asylo is enabled by default in this rule.

    Args:
      name: Name for the build target.
      application_enclave_config: A target that defines a function called
          ApplicationConfig() returning and EnclaveConfig. The returned config
          is passed to the application enclave. Optional.
      enclave_build_config: A backend-specific configuration target to be
          passed to the enclave signer. Optional.
      application_library_linkstatic: When building the application as a
          library, whether to allow that library to be statically linked. See
          the `linkstatic` option on `cc_library`. Optional.
      backends: The asylo backend labels the binary uses. Must specify at least
          one. Defaults to all supported backends. If more than one, then
          name is an alias to a select on backend value to backend-specialized
          targets.
      unsigned_name_by_backend: An optional dictionary from backend label to backend-
          specific target label for the defined unsigned enclaves.
      signed_name_by_backend: An optional dictionary from backend label to backend-
          specific target label for the defined signed enclaves.
      **kwargs: cc_binary arguments.
    """
    application_library_name = name + "_application_library"
    unsigned_enclave_name = name + "_application_enclave_unsigned.so"
    enclave_name = name + "_application_enclave.so"

    enclave_kwargs = {}
    loader_kwargs = {}

    # The "args" attribute should be moved to the loader since cc_library does
    # not support it. The whole-application wrapper contains all the machinery
    # necessary to propagate the arguments.
    if "args" in kwargs:
        loader_kwargs["args"] = kwargs.pop("args")

    # Wrapping shared libraries in enclaves is not supported.
    if "linkshared" in kwargs:
        fail("linkshared option not supported in cc_enclave_binary")

    # "linkstatic" has a different meaning on cc_library than on cc_binary. If
    # a user asks for it on cc_enclave_binary, then the loader should get the
    # attribute.
    if "linkstatic" in kwargs:
        loader_kwargs["linkstatic"] = kwargs.pop("linkstatic")

    # Changing the enclave malloc() implementation is currently not supported.
    if "malloc" in kwargs:
        fail("malloc option not supported in cc_enclave_binary")

    # Licenses should be visibile from the user-visible rule, i.e. the loader.
    if "output_licenses" in kwargs:
        loader_kwargs["output_licenses"] = kwargs.pop("output_licenses")

    # "stamp" currently not supported.
    if "stamp" in kwargs:
        fail("stamp option not supported in cc_enclave_binary")

    if "testonly" in kwargs:
        enclave_kwargs["testonly"] = kwargs["testonly"]
        loader_kwargs["testonly"] = kwargs["testonly"]

    # The user probably wants their tags applied to the loader.
    loader_kwargs["tags"] = kwargs.pop("tags", [])

    native.cc_library(
        name = application_library_name,
        linkstatic = application_library_linkstatic,
        alwayslink = application_library_linkstatic,
        **kwargs
    )

    if not application_enclave_config:
        application_enclave_config = "//asylo/bazel/application_wrapper:default_config"

    cc_unsigned_enclave(
        name = unsigned_enclave_name,
        copts = ASYLO_DEFAULT_COPTS,
        deps = [
            ":" + application_library_name,
            "//asylo/bazel/application_wrapper:application_wrapper_enclave_core",
        ],
        backends = backends,
        name_by_backend = unsigned_name_by_backend,
        **enclave_kwargs
    )
    debug_sign_enclave(
        name = enclave_name,
        unsigned = unsigned_enclave_name,
        config = enclave_build_config,
        backends = backends,
        name_by_backend = signed_name_by_backend,
    )

    enclave_loader(
        name = name,
        embedded_enclaves = {_APPLICATION_WRAPPER_ENCLAVE_SECTION: ":" + enclave_name},
        copts = ASYLO_DEFAULT_COPTS,
        # This option prevents the linker from discarding the definition of
        # GetApplicationConfig() before it encounters a reference to it.
        linkopts = ["-Wl,--undefined=GetApplicationConfig"],
        deps = [
            application_enclave_config,
            "//asylo/bazel/application_wrapper:application_wrapper_driver",
        ],
        backends = backends,
        **loader_kwargs
    )

def enclave_test(
        name,
        enclaves = {},
        embedded_enclaves = {},
        test_args = [],
        remote_proxy = None,
        tags = [],
        backends = INTERNAL_SHOULD_BE_ALL_BACKENDS,
        deprecation = None,
        **kwargs):
    """Build target for testing one or more enclaves.

    Creates a cc_test for a given enclave. Passes flags according to
    `test_args`, which can contain references to targets from `enclaves`.

    This macro creates three build targets:
     1) name: sh_test that runs the enclave_test.
     2) name_driver: cc_test used as test loader in `name`. This is a normal
                     native cc_test. It cannot be directly run because there is
                     an undeclared dependency on enclave.
     3) name_host_driver: genrule that builds name_driver with host crosstool.

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
      remote_proxy: Host-side executable that is going to run remote enclave
        proxy server which will actually load the enclave(s). If empty, the
        enclave(s) are loaded locally.
      tags: Label attached to this test to allow for querying.
      backends: The asylo backend labels the binary uses. Must specify at least
          one. Defaults to all supported backends. If more than one, then
          name is an alias to a select on backend value to backend-specialized
          targets.
      deprecation: A string deprecation message for uses of this macro that
          have been marked deprecated. Optional.
      **kwargs: cc_test arguments.
    """

    test_name = name + "_driver"
    loader_name = name + "_host_driver"

    data = kwargs.pop("data", [])

    flaky = kwargs.pop("flaky", None)
    size = kwargs.pop("size", None)
    native.cc_binary(
        name = test_name,
        testonly = 1,
        **_ensure_static_manual(kwargs)
    )

    extended_tags = tags + backend_tools.tags(backends)

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
        remote_proxy = remote_proxy,
        testonly = 1,
        deprecation = deprecation,
        tags = ["enclave_test"] + extended_tags,
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
        deprecation =
            "asylo.bzl:dlopen_enclave_test is deprecated and will go" +
            " away in the future. Please load from dlopen_enclave.bzl or use" +
            " enclave_test directly with" +
            " backends = [\"//asylo/platform/primitives/dlopen\"]",
        **kwargs
    )

def cc_test(
        name,
        enclave_test_name = "",
        enclave_test_unsigned_name_by_backend = {},
        enclave_test_signed_name_by_backend = {},
        enclave_test_config = "",
        srcs = [],
        deps = [],
        backends = INTERNAL_SHOULD_BE_ALL_BACKENDS,
        **kwargs):
    """Build macro that creates a cc_test target and a cc_enclave_test target.

    This macro generates a cc_test target, which will run a gtest test suite
    normally, and optionally a cc_enclave_test, which will run the test suite
    inside of an enclave.

    Args:
      name: Same as native cc_test name.
      enclave_test_name: Name for the generated cc_enclave_test. Optional.
      enclave_test_unsigned_name_by_backend: Dictionary of backend label to
          test name for backend-specific unsigned enclave targets generated by
          cc_enclave_test. Optional.
      enclave_test_signed_name_by_backend: Dictionary of backend label to
          test name for backend-specific signed enclave targets generated by
          cc_enclave_test. Optional.
      enclave_test_config: A backend-specific configuration target to be passed
          to the enclave signer for each backend. Optional.
      srcs: Same as native cc_test srcs.
      deps: Same as native cc_test deps.
      backends: The asylo backend labels the binary uses. Must specify at least
          one. Defaults to all supported backends. If more than one, then
          name is an alias to a select on backend value to backend-specialized
          targets.
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
            unsigned_name_by_backend = enclave_test_unsigned_name_by_backend,
            signed_name_by_backend = enclave_test_signed_name_by_backend,
            enclave_config = enclave_test_config,
            backends = backends,
            deps = deps,
            **kwargs
        )

def cc_test_and_cc_enclave_test(
        name,
        enclave_test_name = "",
        enclave_test_config = "",
        srcs = [],
        deps = [],
        backends = INTERNAL_SHOULD_BE_ALL_BACKENDS,
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
      enclave_test_config: A backend-specific configuration target to be passed
          to the signer. Optional.
      srcs: See documentation for srcs in native cc_test rule.
      deps: See documentation for deps in native cc_test rule.
      backends: The asylo backend labels the binary uses. Must specify at least
          one. Defaults to all supported backends. If more than one, then
          name is an alias to a select on backend value to backend-specialized
          targets.
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
        backends = backends,
        **kwargs
    )

def cc_enclave_test(
        name,
        srcs,
        enclave_config = "",
        remote_proxy = None,
        tags = [],
        deps = [],
        test_in_initialize = False,
        backends = INTERNAL_SHOULD_BE_ALL_BACKENDS,
        unsigned_name_by_backend = {},
        signed_name_by_backend = {},
        **kwargs):
    """Build target that runs a cc_test srcs inside of an enclave.

    This macro creates two targets, one debug_sign_enclave target with the test
    source. And another test runner application to launch the test enclave.

    Args:
      name: Target name for will be <name>_enclave.
      srcs: Same as cc_test srcs.
      enclave_config: A backend-specific configuration target to be passed to
          the signer for each backend. Optional.
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
          targets.
      unsigned_name_by_backend: An optional dictionary from backend label to backend-
          specific target label for the defined unsigned enclaves.
      signed_name_by_backend: An optional dictionary from backend label to backend-
          specific target label for the defined signed enclaves.
      **kwargs: cc_test arguments.
    """

    # This is a temporary workaround to resolve conflicts in building Asylo
    # directly and importing Asylo as a dependency. Currently when we import
    # "com_google_asylo" from inside Asylo, bazel treats them as two different
    # sources and generates conflict symbol errors. Therefore we need to
    # differentiate the two cases based on the package name.
    if "asylo" in native.package_name():
        _workspace_name = "//asylo"
    else:
        _workspace_name = "@com_google_asylo//asylo"

    # Create a copy of the gtest enclave runner
    host_test_name = name + "_host_driver"
    copy_from_host(
        target = "//asylo/bazel:test_shim_loader",
        output = host_test_name,
        name = name + "_as_host",
    )

    # Build the gtest enclave using the test file and gtest "main" enclave shim
    enclave_name = name + ".so"
    unsigned_enclave_name = name + "_unsigned.so"
    enclave_target = ":" + enclave_name

    # Collect any arguments to cc_unsigned_enclave that override the defaults
    size = kwargs.pop("size", None)  # Meant for the test.
    data = kwargs.pop("data", [])  # Meant for the test.
    cc_unsigned_enclave(
        name = unsigned_enclave_name,
        srcs = srcs,
        deps = deps + ["//asylo/bazel:test_shim_enclave"],
        testonly = 1,
        tags = tags,
        backends = backends,
        name_by_backend = unsigned_name_by_backend,
        **kwargs
    )
    debug_sign_enclave(
        name = enclave_name,
        unsigned = unsigned_enclave_name,
        backends = backends,
        name_by_backend = signed_name_by_backend,
        testonly = 1,
        config = enclave_config,
    )

    # //asylo/bazel:test_shim_loader expects the path to
    # :enclave_test_shim to be provided as the --enclave_path command-line flag.
    enclaves = {"shim": enclave_target}
    loader_args = ['--enclave_path="{shim}"']
    if test_in_initialize:
        loader_args.append("--test_in_initialize")
    else:
        loader_args.append("--notest_in_initialize")

    extended_tags = list(tags)

    backend_tags = backend_tools.tags(backends)
    for tag in backend_tags:
        if tag not in tags:
            extended_tags += [tag]

    # Execute the gtest enclave using the gtest enclave runner
    _enclave_runner_test(
        name = name,
        loader = host_test_name,
        loader_args = loader_args,
        enclaves = _invert_enclave_name_mapping(enclaves),
        data = data,
        remote_proxy = remote_proxy,
        testonly = 1,
        size = size,
        tags = ["enclave_test"] + extended_tags,
    )

def sgx_enclave_test(name, srcs, **kwargs):
    """Build target for testing one or more instances of 'sgx.debug_enclave'.

    This macro invokes enclave_test with the "asylo-sgx" tag added.

    Args:
      name: The target name.
      srcs: Same as cc_test srcs.
      **kwargs: enclave_test arguments.
    """
    enclave_test(
        name,
        srcs = srcs,
        backends = sgx.backend_labels,
        deprecation =
            "asylo.bzl:sgx_enclave_test is deprecated and will go" +
            " away in the future. Please load from sgx_rules.bzl or use" +
            " enclave_test directly with backends = sgx.backend_labels.",
        **kwargs
    )

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
          " Both EnclaveInfo and CcInfo are good baselines. The" +
          " unsigned_enclave_implementation field is a Starlark rule" +
          " implementation function that has common attributes to all" +
          " unsigned enclave rules. The untrusted_sign_implementation field is a" +
          " Starlark rule implementation function that has common attributes" +
          " to all debug sign rules (unsigned, enclave_build_configuration).",
    fields = [
        "forward_providers",
        "unsigned_enclave_implementation",
        "untrusted_sign_implementation",
    ],
)

BACKEND_LABEL = "@com_google_asylo_backend_provider//:backend"

def backend_label_struct(
        config_settings = None,
        tags = None,
        name_derivation = None,
        order = None,
        base = None):
    """Create a backend label struct with optional initial values from base.

    If base is None, then all other arguments must be provided.

    Args:
        config_settings: A list of labels or None.
        tags: A list of tag strings or None.
        name_derivation: A string for adding a label name suffix.
        order: A preference order int or None. The lowest order backend is made
            the default for the all_backends's name's target.
        base: A struct with the same fields as other arguments to this
            function, or None. Used for struct values for fields given as None.

    Returns:
        A struct value with fields config_settings, tags, name_derivation, and
        order.
    """
    if base == None:
        if type(config_settings) != "list":
            fail("base = None; config_settings must be a list of strings")
        if type(tags) != "list":
            fail("base = None; tags must be a list of strings")
        if type(name_derivation) != "string":
            fail("base = None; name_derivation must be a string")
        if type(order) != "int" and type(order) != "float":
            fail("base = None; order must be a number")
        return struct(
            config_settings = config_settings,
            tags = tags,
            name_derivation = name_derivation,
            order = order,
        )
    return struct(
        config_settings = config_settings if config_settings != None else base.config_settings,
        tags = tags if tags != None else base.tags,
        name_derivation = name_derivation if name_derivation != None else base.name_derivation,
        order = order if order != None else base.order,
    )

def _lvi_all_loads_to_features(transitive_features = [], settings_features = []):
    """Adds `lvi_all_loads_mitigation` to a feature list of no other mitigation is specified.

    If either transitive_features or settings_features contains an LVI mitigation, the
    one specified under settings_features (ie. the top-level feature) takes precedence.
    """
    default_lvi = ["lvi_all_loads_mitigation"]
    transitive_lvi = [f for f in transitive_features if f.startswith("lvi_")]
    settings_lvi = [f for f in settings_features if f.startswith("lvi_")]

    all_features = transitive_features + settings_features
    non_lvi_features = [f for f in all_features if not f.startswith("lvi_")]

    return non_lvi_features + (settings_lvi or transitive_lvi or default_lvi)

def _identity_features(transitive_features = [], settings_features = []):
    """Does nothing to a given list of transitive and settings features."""
    return transitive_features + settings_features

def transitive_features_transform(backend):
    """Given a backend, returns a function manipulating transitive features.

    A limitation of not being able to access the backend provider in the
    transition implementation in `transitions.bzl` means that user-defined
    backends cannot implement a custom transtiive feature transformation.

    Args:
        backend: The name of a backend.

    Returns:
        A function that takes a list of transitive features, a list of settings
        features, and returns a possibly modified concatenation of the two.
    """
    canonical_dict = _canonical_backend_dict(ALL_BACKEND_LABELS)
    if backend in canonical_dict:
        if hasattr(canonical_dict[backend], "transitive_features_transform"):
            return canonical_dict[backend].transitive_features_transform
    return _identity_features

# When a backend is unspecified, target all of the following backends.
# The value type for this dictionary is named a "backend label struct"
_sgx_hw_backend = "@linux_sgx//:asylo_sgx_hw"
_sgx_sim_backend = "@linux_sgx//:asylo_sgx_sim"
ALL_BACKEND_LABELS = {
    "//asylo/platform/primitives/dlopen": struct(
        config_settings = [
            "//asylo/platform/primitives:asylo_dlopen",
        ],
        tags = [
            "asylo-dlopen",
            "manual",        ],
        name_derivation = "_dlopen",
        sign_tool = "@com_google_asylo_backend_provider//:true",
        debug_private_key = "@com_google_asylo_backend_provider//:empty",
        debug_default_config = "@com_google_asylo_backend_provider//:empty",
        order = 3,
    ),
    _sgx_sim_backend: struct(
        config_settings = ["@linux_sgx//:sgx_sim"],
        tags = [
            "asylo-sgx-sim",
            "manual",        ],
        name_derivation = "_sgx_sim",
        sign_tool = "@linux_sgx//:sgx_sign_tool",
        debug_private_key = "@linux_sgx//:enclave_test_private.pem",
        debug_default_config = "@linux_sgx//:enclave_debug_config",
        order = 1,
        transitive_features_transform = _lvi_all_loads_to_features,
    ),
    _sgx_hw_backend: struct(
        config_settings = ["@linux_sgx//:sgx_hw"],
        tags = [
            "asylo-sgx-hw",
            "manual",  # Hardware testing should be explicitly queried.
        ],
        name_derivation = "_sgx_hw",
        sign_tool = "@linux_sgx//:sgx_sign_tool",
        debug_private_key = "@linux_sgx//:enclave_test_private.pem",
        debug_default_config = "@linux_sgx//:enclave_debug_config",
        order = 2,
        transitive_features_transform = _lvi_all_loads_to_features,
    ),
}

INTERNAL_SHOULD_BE_ALL_BACKENDS = {
    _sgx_hw_backend: ALL_BACKEND_LABELS[_sgx_hw_backend],
    _sgx_sim_backend: ALL_BACKEND_LABELS[_sgx_sim_backend],
}

def _asylo_backend_impl(ctx):
    return [AsyloBackendInfo(forward_providers = [EnclaveInfo, CcInfo])]

asylo_backend = rule(implementation = _asylo_backend_impl, attrs = {})

def _cc_private_sources(srcs):
    """Returns a pair of the source files and header files in srcs"""
    source_suffixes = [".cc", ".cpp", ".cxx", ".c++", ".C", ".c"]
    header_suffixes = [".hh", ".hpp", ".hxx", ".h++", ".H", ".h"]
    sources = []
    headers = []
    for file in srcs:
        if any([file.path.endswith(suffix) for suffix in source_suffixes]):
            sources.append(file)
        elif any([file.path.endswith(suffix) for suffix in header_suffixes]):
            headers.append(file)
        else:
            fail("{} has wrong extension for a C/C++ source file".format(file.path))
    return sources, headers

DEFAULT_MALLOC = Label("@com_google_asylo_toolchain//toolchain:malloc")
ASYLO_TOOLCHAIN = Label("@com_google_asylo_toolchain//toolchain:crosstool")

def _cc_binary_attrs(
        executable = False,
        malloc = DEFAULT_MALLOC,
        toolchain = ASYLO_TOOLCHAIN):
    """Returns attributes for cc_binary-like rules.

    Used for both shared object binaries and executable binaries. Executables
    have different defaults for linkshared and linkstatic.

    Args:
        executable: True if and only if the binary should be executable.
        malloc: The malloc label to use.
        toolchain: Which toolchain the binary should be built with.

    Returns:
        A dictionary of attribute name string to attribute.
    """
    return {
        "srcs": attr.label_list(allow_files = True, doc = "srcs for cc_binary."),
        "deps": attr.label_list(doc = "deps for cc_binary."),
        "linkopts": attr.string_list(doc = "linkopts for cc_binary."),
        "copts": attr.string_list(doc = "copts for cc_binary."),
        "stamp": attr.bool(
            default = False,
            doc = "stamp for cc_binary, not supported. Must be false.",
        ),
        "defines": attr.string_list(doc = "defines for cc_binary."),
        "malloc": attr.label(
            doc = ("Custom malloc for cc_binary. Not supported. Must be the " +
                   "default malloc."),
        ),
        "includes": attr.string_list(doc = "includes for cc_binary."),
        # The data field is not allowed.
        "linkshared": attr.int(default = 0 if executable else 1, doc = "linkshared for cc_binary."),
        "linkstatic": attr.int(default = 0 if executable else 1, doc = "linkstatic for cc_binary."),
        # Attributes not in normal cc_binary.
        "_malloc": attr.label(default = malloc),  # The default malloc target.
        "additional_linker_inputs": attr.label_list(
            allow_files = [".lds"],
            allow_empty = True,
            doc = "Version scripts to pass to the linker.",
        ),
        "_cc_toolchain": attr.label(default = toolchain),
        "transitive_features": attr.string_list(doc = "Bazel features to propagate to all dependencies"),
    }

def merge_dicts(base, *extensions):
    """Combines all dictionaries combined left to right.

    Args:
        base: The base dictionary to be extended.
        *extensions: The dictionaries whose key/value pairs are written to the
            copy of base.

    Returns:
        A copy of base with all extension key/value pairs added.
    """
    result = dict(base)
    for extension in extensions:
        result.update(extension)
    return result

def native_cc_binary(
        ctx,
        basename,
        extra_features = [],
        extra_copts = [],
        extra_linkopts = [],
        extra_data = [],
        extra_deps = [],
        extra_linking_contexts = []):
    """Returns the providers cc_binary would produce on the same attributes.

    Useful in case macros cannot be used.

    Args:
        ctx: A Starlark rule context that has the following attributes from
            cc_binary: {srcs, deps, copts, linkopts, stamp, malloc, includes,
            defines, linkshared, linkstatic},  and the following additional
            attributes: additional_linker_inputs, _cc_toolchain
        basename: The name that output files use to derive their names.
        extra_features: More features to add on top of user-provided features.
        extra_copts: More copts to add on top of user-provided copts.
        extra_linkopts: More linkopts to add on top of user-provided linkopts.
        extra_data: More data dependencies to include in the target's runfiles.
        extra_deps: More deps to add on top of user-provided deps.
        extra_linking_contexts: More linking contexts to include in the
            target's linking.

    Returns:
        A list of CcInfo and DefaultInfo providers.
    """
    if ctx.attr.stamp:
        fail("Linkstamping is not supported")
    if ctx.attr.malloc:
        if ctx.attr.malloc.label not in [ctx.attr._malloc.label, DEFAULT_MALLOC]:
            fail("Custom malloc is not supported")
    extra_deps = extra_deps + [ctx.attr._malloc]
    cc_toolchain = ctx.attr._cc_toolchain[cc_common.CcToolchainInfo]
    features = ctx.attr.features + extra_features
    feature_configuration = cc_common.configure_features(
        ctx = ctx,
        cc_toolchain = cc_toolchain,
        requested_features = ctx.features + [feature for feature in features if not feature.startswith("-")],
        unsupported_features = ctx.disabled_features + [feature[1:] for feature in features if feature.startswith("-")],
    )

    deps = ctx.attr.deps + extra_deps
    compilation_contexts = []
    linking_contexts = []
    deps_linker_inputs = []
    for dep in deps:
        # Split transitions on the rule make each dep a list of deps. We use
        # a single transition, so take the 0th element.
        if type(dep) == "list":
            dep = dep[0]
        compilation_contexts.append(dep[CcInfo].compilation_context)
        linking_context = dep[CcInfo].linking_context
        linking_contexts.append(linking_context)
        deps_linker_inputs.append(linking_context.linker_inputs)

    (_source_files, _private_headers) = _cc_private_sources(ctx.files.srcs)
    (compilation_context, compilation_outputs) = cc_common.compile(
        name = basename,
        actions = ctx.actions,
        feature_configuration = feature_configuration,
        cc_toolchain = cc_toolchain,
        srcs = _source_files,
        private_hdrs = _private_headers,
        includes = ctx.attr.includes,
        defines = ctx.attr.defines,
        user_compile_flags = ctx.attr.copts + extra_copts,
        compilation_contexts = compilation_contexts,
    )
    additional_linker_inputs = ctx.attr.additional_linker_inputs
    output_type = "dynamic_library" if ctx.attr.linkshared else "executable"
    _linking_outputs = cc_common.link(
        name = basename,
        actions = ctx.actions,
        feature_configuration = feature_configuration,
        cc_toolchain = cc_toolchain,
        language = "c++",
        # The system malloc is used by default.
        compilation_outputs = compilation_outputs,
        linking_contexts = linking_contexts + extra_linking_contexts,
        user_link_flags = ctx.attr.linkopts + extra_linkopts,
        link_deps_statically = not (not ctx.attr.linkstatic),
        additional_inputs = additional_linker_inputs,
        output_type = output_type,
    )
    output_files = []

    _to_link = _linking_outputs.library_to_link
    executable = None
    if _linking_outputs.executable:
        executable = _linking_outputs.executable
        output_files.append(executable)
    elif _to_link:
        output_files.append(_to_link.pic_static_library or _to_link.dynamic_library)

    linker_inputs = depset([cc_common.create_linker_input(
        owner = ctx.label,
        libraries = depset([_to_link]) if _to_link else None,
        user_link_flags = depset(ctx.attr.linkopts),
        additional_inputs = depset(additional_linker_inputs),
    )], transitive = deps_linker_inputs)
    _linking_context = cc_common.create_linking_context(
        linker_inputs = linker_inputs,
    )
    return [
        CcInfo(linking_context = _linking_context, compilation_context = compilation_context),
        DefaultInfo(
            files = depset(output_files),
            runfiles = ctx.runfiles(extra_data),
            executable = executable,
        ),
    ]

def derived_name_from_backend(name, backend, info = None):
    """Returns a valid name that is a combination of name and backend.

    Args:
        name: The basis for the derived name.
        backend: The backend the derived name targets.
        info: A backend info struct that contains a name_derivation field, or
            None. Optional.

    Returns:
        A string.
    """
    name_derivation = ""
    if info and info.name_derivation:
        name_derivation = info.name_derivation
    else:
        name_derivation = backend.replace("/", "_").replace(":", "_").replace("@", "")
    suffix = ""

    # Accumulate suffixes so that _test.so is the final suffix.
    # Run a few times (can't write fixed-point loops in Starlark) to
    # allow multiple suffixes to accumulate.
    for _loop in [1, 2, 3, 4]:
        changed = False
        for tested_suffix in [".so", "_test"]:
            if name.endswith(tested_suffix):
                suffix = tested_suffix + suffix
                name = name[:-len(tested_suffix)]
                changed = True
        if not changed:
            break
    return name + name_derivation + suffix

def _canonical_backend_dict(backends):
    """Create a dictionary from a list of known backend labels.

    If backends is already a dictionary, returns backends. If a backend label
    is not in ALL_BACKEND_LABELS.keys(), then fails.
    If the dictionary or label list is empty, then fails.

    Args:
        backends: A list of label strings or a dictionary of label strings to
            backend label structs.

    Returns:
        A dictionary of label string keys and backend label struct values.
    """
    backend_dictionary = {}
    if type(backends) == "list":
        order = 1
        for backend in backends:
            if backend not in ALL_BACKEND_LABELS:
                fail(backend + " is not an Asylo-supported backend label. Please use a dictionary.")
            backend_dictionary[backend] = backend_label_struct(
                base = ALL_BACKEND_LABELS[backend],
                order = order,
            )
            order = order + 1
    else:
        backend_dictionary = dict(backends)

    if not backend_dictionary:
        fail("backends may not be empty")
    return backend_dictionary

def tags_from_backends(backends):
    """Returns the associated tags with each backend label.

    Args:
        backends: A list of backend label strings or a dictionary with backend
            label string keys and backend label struct values.

    Returns:
        A list of tag strings.
    """
    canonical_dict = _canonical_backend_dict(backends)
    backend_tags = []
    for label, info in canonical_dict.items():
        backend_tags += info.tags
    return backend_tags

def _preferred_backend(backend_dictionary):
    default_backend = ""
    best_order = None

    # There must be at least one item in backend_dictionary, so default_backend
    # will always be set to some key.
    for backend, item in backend_dictionary.items():
        if best_order == None or item.order < best_order:
            default_backend = backend
            best_order = item.order
    return default_backend

def _complete_backend_target_names(backend_dictionary, name, name_by_backend):
    result = dict(name_by_backend)
    for backend, info in backend_dictionary.items():
        if backend not in name_by_backend:
            result[backend] = derived_name_from_backend(name, backend, info)
    return result

def all_backends(
        rule_or_macro,
        name,
        backends,
        name_by_backend,
        kwargs,
        test = False,
        include_info = False,
        ):
    """Creates many backend-specific targets and a selector target.

    If backends is a singleton list or a dictionary with one key, then name
    is not a selector target, but rather just the rule_or_macro called with
    the one backend label and kwargs.

    Otherwise, targets are created with rule_or_macro called on a name,
    a backend, and spliced kwargs. The alias target's tags, visibility, and
    testonly fields are copied from kwargs.

    Args:
        rule_or_macro: a Starlark rule or macro that defines a target.
        name: The name of the selector target. Used as a basis for backend-
            specific names.
        backends: A list of supported asylo backend labels to use, or a
            dictionary with backend label keys mapping to structs with fields
            {config_setting, tags, name_derivation, order}. This allows
            all_backends to select a backend-name-derived target (if not
            specified by name_by_backend) on a user-specified config_setting
            for the backend value and apply backend-specific tags. The selected
            backend has the smallest order value in the dictionary, or is the
            first element of the backends list.
        name_by_backend: An optional dictionary from backend label to backend-
            specific target label.
        kwargs: A dictionary of argument to pass to the given rule_or_macro.
        test: True if rule_or_macro defines a test target.
        include_info: True if rule_or_macro accepts a backend_label_struct
            argument.
    """
    backend_dictionary = _canonical_backend_dict(backends)
    name_by_backend = _complete_backend_target_names(
        backend_dictionary,
        name,
        name_by_backend,
    )
    tags = kwargs.pop("tags", [])
    overall_tags = list(tags)

    testonly = kwargs.get("testonly", 0)
    visibility = kwargs.get("visibility", None)
    if visibility:
        visibility = list(kwargs["visibility"])

    default_backend = _preferred_backend(backend_dictionary)
    default_target = "//" + native.package_name() + ":" + name_by_backend[default_backend]

    selections = {"//conditions:default": default_target}
    for backend, info in backend_dictionary.items():
        backend_name = name_by_backend[backend]
        for config_setting in info.config_settings:
            selections[config_setting] = ":" + backend_name
        target_tags = list(info.tags)

        # The alias target will select any of the backend targets, so its tags
        # should include all the possible tags of its selections.
        overall_tags += target_tags
        if include_info:
            kwargs["backend_label_struct"] = info
        rule_or_macro(
            name = backend_name,
            backend = backend,
            tags = tags + target_tags,
            **kwargs
        )
    if test:
        native.test_suite(
            name = name,
            tests = [default_target],
            tags = backend_dictionary[default_backend].tags,
        )
    else:
        native.alias(
            name = name,
            actual = select(selections),
            tags = overall_tags,
            testonly = testonly,
            visibility = visibility,
        )

backend_tools = struct(
    derived_name = derived_name_from_backend,
    tags = tags_from_backends,
    all_backends = all_backends,
    should_be_all_backends = INTERNAL_SHOULD_BE_ALL_BACKENDS,
    cc_binary = native_cc_binary,
    cc_binary_attrs = _cc_binary_attrs,
    asylo = asylo_backend,
    all_labels = ALL_BACKEND_LABELS,
    EnclaveInfo = EnclaveInfo,
    AsyloBackendInfo = AsyloBackendInfo,
    flag = BACKEND_LABEL,
    merge_dicts = merge_dicts,
    malloc_label = DEFAULT_MALLOC,
    asylo_toolchain_label = ASYLO_TOOLCHAIN,
    transitive_features_transform = transitive_features_transform,
)

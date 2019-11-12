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

load("@bazel_tools//tools/cpp:toolchain_utils.bzl", "find_cpp_toolchain")

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
          " unsigned enclave rules. The debug_sign_implementation field is a" +
          " Starlark rule implementation function that has common attributes" +
          " to all debug sign rules (unsigned, enclave_build_configuration).",
    fields = [
        "forward_providers",
        "unsigned_enclave_implementation",
        "debug_sign_implementation",
    ],
)

BACKEND_LABEL = "@com_google_asylo_backend_provider//:backend"

# When a backend is unspecified, target all of the following backends.
# The value type for this dictionary is named a "backend label struct"
ALL_BACKEND_LABELS = {
    "//asylo/platform/primitives/dlopen": struct(
        config_settings = [
            "//asylo/platform/primitives:asylo_dlopen",
        ],
        tags = [
            "asylo-dlopen",
            "manual",        ],
    ),
    "@linux_sgx//:asylo_sgx_sim": struct(
        config_settings = [
            "@linux_sgx//:sgx_sim",
        ],
        tags = [
            "asylo-sgx-sim",
            "manual",        ],
    ),
    "@linux_sgx//:asylo_sgx_hw": struct(
        config_settings = [
            "@linux_sgx//:sgx_hw",
        ],
        tags = [
            "asylo-sgx-hw",
            "manual",        ],
    ),
}

def _asylo_backend_impl(ctx):
    return [AsyloBackendInfo(forward_providers = [EnclaveInfo, CcInfo])]

asylo_backend = rule(implementation = _asylo_backend_impl, attrs = {})

# The following definitions are useful for backend implementations.
def _static_libraries_to_link_from_contexts(linking_contexts):
    libraries_to_link = []
    for link_context in linking_contexts:
        lib_list = link_context.libraries_to_link
        if lib_list == None:
            continue
        if type(lib_list) != "list":
            lib_list = lib_list.to_list()
        for lib in lib_list:
            if lib and lib.static_library:
                libraries_to_link += [lib.static_library]
    return libraries_to_link

def _cc_private_sources(srcs):
    """Returns a pair of the source files and header files in srcs"""
    source_suffixes = [".cc", ".cpp", ".cxx", ".c++", ".C", ".c"]
    header_suffixes = [".hh", ".hpp", ".hxx", ".h++", ".H", ".h"]
    sources = []
    headers = []
    for file in srcs:
        if any([file.path.endswith(suffix) for suffix in source_suffixes]):
            sources += [file]
        elif any([file.path.endswith(suffix) for suffix in header_suffixes]):
            headers += [file]
        else:
            fail("{} has wrong extension for a C/C++ source file".format(file.path))
    return sources, headers

DEFAULT_MALLOC = Label("@com_google_asylo_toolchain//toolchain:malloc")

CC_BINARY_ATTRS = {
    "srcs": attr.label_list(allow_files = True),
    "deps": attr.label_list(),
    "linkopts": attr.string_list(),
    "copts": attr.string_list(),
    "stamp": attr.bool(default = False),
    "defines": attr.string_list(),
    "malloc": attr.label(default = DEFAULT_MALLOC),
    "includes": attr.string_list(),
    # The data field is not allowed.
    "linkshared": attr.int(default = 1),
    "linkstatic": attr.int(default = 1),
    # Attributes not in native.cc_binary.
    "additional_linker_inputs": attr.label_list(allow_files = [".lds"], allow_empty = True),
    "_cc_toolchain": attr.label(default = "@com_google_asylo_toolchain//toolchain:crosstool"),
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
        extra_deps: More deps to add on top of user-provided deps.
        extra_linking_contexts: More linking contexts to include in the
            target's linking.

    Returns:
        A list of CcInfo and DefaultInfo providers.
    """
    if ctx.attr.stamp:
        fail("Linkstamping is not supported")
    if ctx.attr.malloc.label != DEFAULT_MALLOC:
        fail("Custom malloc is not supported")
    cc_toolchain = find_cpp_toolchain(ctx)
    features = ctx.attr.features + extra_features
    feature_configuration = cc_common.configure_features(
        ctx = ctx,
        cc_toolchain = cc_toolchain,
        requested_features = ctx.features + [feature for feature in features if not feature.startswith("-")],
        unsupported_features = ctx.disabled_features + [feature[1:] for feature in features if feature.startswith("-")],
    )

    deps = ctx.attr.deps + extra_deps
    compilation_contexts = [dep[CcInfo].compilation_context for dep in deps]
    linking_contexts = [dep[CcInfo].linking_context for dep in deps]

    # Link in all dependencies' static libraries.
    libraries_to_link = _static_libraries_to_link_from_contexts(linking_contexts)

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
    if _to_link:
        if ctx.attr.linkshared and _to_link.dynamic_library:
            output_files += [_to_link.dynamic_library]
        elif not ctx.attr.linkshared and _to_link.static_pic_library:
            output_files += [_to_link.static_pic_library]
    _linking_context = cc_common.create_linking_context(
        libraries_to_link = libraries_to_link + output_files,
        user_link_flags = ctx.attr.linkopts,
        additional_inputs = additional_linker_inputs,
    )
    return [
        CcInfo(linking_context = _linking_context, compilation_context = compilation_context),
        DefaultInfo(files = depset(output_files)),
    ]

def derived_name_from_backend(name, backend):
    """Returns a valid name that is a combination of name and backend.

    Args:
        name: The basis for the derived name.
        backend: The backend the derived name targets.

    Returns:
        A string.
    """
    mangled_backend = backend.replace("/", "_").replace(":", "_").replace("@", "")
    return name + "_" + mangled_backend

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
        for backend in backends:
            if backend not in ALL_BACKEND_LABELS:
                fail(backend + " is not an Asylo-supported backend label. Please use a dictionary.")
            backend_dictionary[backend] = ALL_BACKEND_LABELS[backend]
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

def all_backends(
        rule_or_macro,
        name,
        backends,
        name_by_backend,
        kwargs):
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
            {config_setting, tags}. This allows all_backends to select on a
            user-specified config_setting for the backend value and apply
            backend-specific tags.
        name_by_backend: An optional dictionary from backend label to backend-
            specific target label.
        kwargs: A dictionary of argument to pass to the given rule_or_macro.
    """
    backend_dictionary = _canonical_backend_dict(backends)
    selections = {}
    tags = kwargs.pop("tags", [])
    overall_tags = list(tags)
    testonly = kwargs.get("testonly", 0)
    visibility = list(kwargs.get("visibility", ["//visibility:private"]))
    for backend, info in backend_dictionary.items():
        backend_name = name_by_backend.get(backend, derived_name_from_backend(name, backend))
        for config_setting in info.config_settings:
            selections[config_setting] = ":" + backend_name
        target_tags = list(info.tags)
        overall_tags += target_tags
        rule_or_macro(name = backend_name, backend = backend, tags = tags + target_tags, **kwargs)
    native.alias(
        name = name,
        actual = select(
            selections,
            no_match_error = "Must be build with a selected Asylo backend",
        ),
        tags = overall_tags,
        testonly = testonly,
        visibility = visibility,
    )

backend_tools = struct(
    derived_name = derived_name_from_backend,
    tags = tags_from_backends,
    all_backends = all_backends,
    cc_binary = native_cc_binary,
    cc_binary_attrs = CC_BINARY_ATTRS,
    asylo = asylo_backend,
    all_labels = ALL_BACKEND_LABELS,
    EnclaveInfo = EnclaveInfo,
    AsyloBackendInfo = AsyloBackendInfo,
    flag = BACKEND_LABEL,
    merge_dicts = merge_dicts,
)

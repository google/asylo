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

load("@com_google_asylo_backend_provider//:enclave_info.bzl", "backend_tools")
load("@com_google_asylo_backend_provider//:transitions.bzl", "transitions")
load("@linux_sgx//:sgx_sdk.bzl", "sgx")
load("@rules_cc//cc:defs.bzl", "cc_library", native_cc_test = "cc_test")
load(
    "//asylo/bazel:asylo_copy_from_host.bzl",
    _backend_sign_enclave_with_untrusted_key_old = "backend_sign_enclave_with_untrusted_key",
    _cc_backend_unsigned_enclave_experimental_old = "cc_backend_unsigned_enclave_experimental",
    _cc_backend_unsigned_enclave_old = "cc_backend_unsigned_enclave",
    _cc_enclave_test_old = "cc_enclave_test",
    _embed_enclaves_old = "embed_enclaves",
    _enclave_runner_script_old = "enclave_runner_script",
    _enclave_runner_test_old = "enclave_runner_test",
)
load("//asylo/bazel:asylo_internal.bzl", "internal")
load(
    "//asylo/bazel:asylo_transitions.bzl",
    _backend_sign_enclave_with_untrusted_key_new = "backend_sign_enclave_with_untrusted_key",
    _cc_backend_unsigned_enclave_experimental_new = "cc_backend_unsigned_enclave_experimental",
    _cc_backend_unsigned_enclave_new = "cc_backend_unsigned_enclave",
    _cc_enclave_test_new = "cc_enclave_test",
    _enclave_runner_script_new = "enclave_runner_script",
    _enclave_runner_test_new = "enclave_runner_test",
)
load("//asylo/bazel:copts.bzl", "ASYLO_DEFAULT_COPTS")

# website-docs-metadata
# ---
#
# title:  //asylo/bazel:asylo.bzl
#
# overview: Build rules for defining enclaves and tests.
#
# location: /_docs/reference/api/bazel/asylo_bzl.md
#
# order: 40
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

ASYLO_ALL_BACKEND_TAGS = ASYLO_ALL_BACKENDS + [
    "manual",
]

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
    _impl = _embed_enclaves_old
    kwargs = dict(kwargs)
    if transitions.supported(native.package_name()):
        _impl = internal.embed_enclaves
        kwargs["tags"] = kwargs.get("tags", []) + ["asylo-transition"]
    else:
        kwargs["tags"] = kwargs.get("tags", []) + ["asylo-cfh"]
    _impl(
        name = name,
        elf_file = elf_file,
        enclaves = enclaves,
        **kwargs
    )

def enclave_loader(
        name,
        enclaves = {},
        embedded_enclaves = {},
        loader_args = [],
        remote_proxy = None,
        backends = backend_tools.should_be_all_backends,
        loader_name_by_backend = {},
        name_by_backend = {},
        deprecation = None,
        **kwargs):
    """Wraps a cc_binary with a dependency on enclave availability at runtime.

    Creates a loader for the given enclaves and containing the given embedded
    enclaves. Passes flags according to `loader_args`, which can contain
    references to targets from `enclaves`.

    The loader is subject to a backend transition by the specified backends.

    This macro creates three build targets:
      1) name: shell script that runs `name_host_loader`.
      2) name_loader: cc_binary used as loader in `name`. This is a normal
                      cc_binary. It cannot be directly run because there
                      is an undeclared dependency on the enclaves.
      3) name_host_loader: genrule that builds `name_loader` with the host
                           crosstool.

    Args:
      name: Name for build target.
      enclaves: Dictionary from enclave names to target dependencies. The
        dictionary must be injective. This dictionary is used to format each
        string in `loader_args` after each enclave target is interpreted as the
        path to its output binary. Enclaves are built under a backend
        transition.
      embedded_enclaves: Dictionary from ELF section names (that do not start
        with '.') to target dependencies. Each target in the dictionary is
        embedded in the loader binary under the corresponding ELF section.
      loader_args: List of arguments to be passed to `loader`. Arguments may
        contain {enclave_name}-style references to keys from the `enclaves` dict,
        each of which will be replaced with the path to the named enclave.
      remote_proxy: Host-side executable that is going to run remote enclave
        proxy server which will actually load the enclave(s). If empty, the
        enclave(s) are loaded locally.
      backends: The asylo backend labels the binary uses. Must specify at least
          one. Defaults to all supported backends. If more than one, then
          name is an alias to a select on backend value to backend-specialized
          targets. See enclave_info.bzl:all_backends documentation for details.
      loader_name_by_backend: Dictionary of backend label to loader name for
        backend-specific enclave driver. Optional.
      name_by_backend: An optional dictionary from backend label to backend-
          specific loader script name.
      deprecation: A string deprecation message for uses of this macro that
          have been marked deprecated. Optional.
      **kwargs: cc_binary arguments.
    """

    loader_plain_name = name + "_loader"
    loader_name = name + "_host_loader"

    transitions.cc_binary(
        name = loader_plain_name,
        backends = backends,
        name_by_backend = loader_name_by_backend,
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
        visibility = kwargs.get("visibility", None),
    )

    script_kwargs = {
        "testonly": kwargs.get("testonly", 0),
        "loader": loader_name,
        "loader_args": loader_args,
        "enclaves": internal.invert_enclave_name_mapping(enclaves),
        "remote_proxy": remote_proxy,
        "tags": kwargs.get("tags", []),
        "deprecation": deprecation,
        "visibility": kwargs.get("visibility", None),
        "data": kwargs.get("data", []),
    }
    if transitions.supported(native.package_name()):
        script_kwargs["tags"] = kwargs.get("tags", []) + ["asylo-transition"]
        backend_tools.all_backends(
            rule_or_macro = _enclave_runner_script_new,
            name = name,
            backends = backends,
            kwargs = script_kwargs,
            name_by_backend = name_by_backend,
        )
    else:
        script_kwargs["tags"] = kwargs.get("tags", []) + ["asylo-cfh"] + backend_tools.tags(backends)
        _enclave_runner_script_old(name = name, **script_kwargs)

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
        testonly = 1,
        remote_proxy = remote_proxy,
        backends = [asylo + "/platform/primitives/dlopen"],
        deprecation =
            "asylo.bzl:dlopen_enclave_loader is deprecated and will go" +
            " away in the future. Please load from dlopen_enclave.bzl or use" +
            " enclave_loader directly with" +
            " backends = [\"//asylo/platform/primitives/dlopen\"]",
        **kwargs
    )

def cc_backend_unsigned_enclave(name, backend, **kwargs):
    """Defines a C++ unsigned enclave target in the provided backend.

    Args:
        name: The rule name.
        backend: An Asylo backend label.
        **kwargs: Arguments to cc_binary.
    """
    _impl = _cc_backend_unsigned_enclave_old
    kwargs = dict(kwargs)
    if transitions.supported(native.package_name()):
        _impl = _cc_backend_unsigned_enclave_new
        kwargs["tags"] = kwargs.get("tags", []) + ["asylo-transition"]
    else:
        kwargs["tags"] = kwargs.get("tags", []) + ["asylo-cfh"]
    _impl(name = name, backend = backend, **kwargs)

def cc_backend_unsigned_enclave_experimental(name, backend, **kwargs):
    """Defines a C++ unsigned enclave target in the provided backend.

    Args:
        name: The rule name.
        backend: An Asylo backend label.
        **kwargs: Arguments to cc_binary.
    """
    _impl = _cc_backend_unsigned_enclave_experimental_old
    kwargs = dict(kwargs)
    if transitions.supported(native.package_name()):
        _impl = _cc_backend_unsigned_enclave_experimental_new
        kwargs["tags"] = kwargs.get("tags", []) + ["asylo-transition"]
    else:
        kwargs["tags"] = kwargs.get("tags", []) + ["asylo-cfh"]
    _impl(name = name, backend = backend, **kwargs)

def backend_sign_enclave_with_untrusted_key(
        name,
        backend,
        unsigned,
        config = None,
        backend_label_struct = None,
        **kwargs):
    """Defines the 'signed' version of an unsigned enclave target.

    The signer is backend-specific.

    Args:
        name: The rule name.
        backend: An Asylo backend label.
        unsigned: The label of the unsigned enclave target.
        config: An enclave signer configuration label. Optional.
        backend_label_struct: Optional backend label struct (details in
            enclave_info.bzl)
        **kwargs: Generic rule arguments like tags and testonly.
    """
    kwargs = dict(kwargs)  # Copy kwargs to allow mutation.
    _impl = _backend_sign_enclave_with_untrusted_key_old
    if transitions.supported(native.package_name()):
        _impl = _backend_sign_enclave_with_untrusted_key_new
        kwargs["tags"] = kwargs.get("tags", []) + ["asylo-transition"]
    else:
        kwargs["tags"] = kwargs.get("tags", []) + ["asylo-cfh"]
    if backend_label_struct:
        kwargs["key"] = kwargs.get("key", None) or backend_label_struct.debug_private_key
        kwargs["config"] = config or backend_label_struct.debug_default_config
        kwargs["sign_tool"] = kwargs.get("sign_tool", None) or backend_label_struct.sign_tool
    elif config:
        kwargs["config"] = config
    _impl(
        name = name,
        backend = backend,
        unsigned = unsigned,
        **kwargs
    )

def cc_unsigned_enclave(
        name,
        backends = backend_tools.should_be_all_backends,
        name_by_backend = {},
        **kwargs):
    """Creates a C++ unsigned enclave target in all or any backend.

    Args:
      name: The rule name.
      backends: The asylo backend labels the binary uses. Must specify at least
        one. Defaults to all supported backends. If more than one, then
        name is an alias to a select on backend value to backend-specialized
        targets. See enclave_info.bzl:all_backends documentation for details.
      name_by_backend: An optional dictionary from backend label to backend-
        specific target label.
      **kwargs: Remainder arguments to the backend rule.
    """
    enclave_rule = cc_backend_unsigned_enclave

    asylo = "asylo"
    if asylo in native.package_name():
        enclave_rule = cc_backend_unsigned_enclave_experimental
    backend_tools.all_backends(
        enclave_rule,
        name,
        backends,
        name_by_backend,
        kwargs,
    )

def sign_enclave_with_untrusted_key(
        name,
        unsigned,
        key = None,
        backends = backend_tools.should_be_all_backends,
        config = None,
        testonly = 0,
        name_by_backend = {},
        visibility = None):
    """Signs an unsigned enclave according the the backend's signing procedure.

    Args:
        name: The signed enclave target name.
        unsigned: The label to the unsigned enclave.
        key: The untrusted private key for signing. Default value is defined by
            the backend.
        backends: The asylo backend labels the binary uses. Must specify at least
          one. Defaults to all supported backends. If more than one, then
          name is an alias to a select on backend value to backend-specialized
          targets. See enclave_info.bzl:all_backends documentation for details.
        config: A label to a config target that the backend-specific signing
          tool uses.
        testonly: True if the target should only be used in tests.
        name_by_backend: An optional dictionary from backend label to backend-
          specific target label.
        visibility: Optional target visibility.
    """
    kwargs = {"unsigned": unsigned, "testonly": testonly, "visibility": visibility}
    if config:
        kwargs["config"] = config
    if key:
        kwargs["key"] = key
    backend_tools.all_backends(
        backend_sign_enclave_with_untrusted_key,
        name,
        backends,
        name_by_backend,
        kwargs,
        include_info = True,
    )

def debug_sign_enclave(name, **kwargs):
    """Alias for sign_enclave_with_untrusted_key.

    Args:
        name: The rule name,
        **kwargs: The rest of the arguments to sign_enclave_with_untrusted_key.
    """
    sign_enclave_with_untrusted_key(name, **kwargs)

# The section to embed the application enclave in.
_APPLICATION_WRAPPER_ENCLAVE_SECTION = "enclave"

def cc_enclave_binary(
        name,
        application_enclave_config = "",
        enclave_build_config = "",
        application_library_linkstatic = True,
        backends = backend_tools.should_be_all_backends,
        unsigned_name_by_backend = {},
        signed_name_by_backend = {},
        testonly = 0,
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
        targets. See enclave_info.bzl:all_backends documentation for details.
      unsigned_name_by_backend: An optional dictionary from backend label to backend-
        specific target label for the defined unsigned enclaves.
      signed_name_by_backend: An optional dictionary from backend label to backend-
          specific target label for the defined signed enclaves.
      testonly: True if the targets should only be used in tests.
      **kwargs: cc_binary arguments.
    """
    application_library_name = name + "_application_library"
    unsigned_enclave_name = name + "_application_enclave_unsigned.so"
    enclave_name = name + "_application_enclave.so"

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

    # The user probably wants their tags applied to the loader.
    loader_kwargs["tags"] = kwargs.pop("tags", [])

    cc_library(
        name = application_library_name,
        linkstatic = application_library_linkstatic,
        alwayslink = application_library_linkstatic,
        testonly = testonly,
        **kwargs
    )

    asylo = internal.package()
    if not application_enclave_config:
        application_enclave_config = asylo + "/bazel/application_wrapper:default_config"

    cc_unsigned_enclave(
        name = unsigned_enclave_name,
        copts = ASYLO_DEFAULT_COPTS,
        deps = [
            ":" + application_library_name,
            asylo + "/bazel/application_wrapper:application_wrapper_enclave_core",
        ],
        backends = backends,
        name_by_backend = unsigned_name_by_backend,
        testonly = testonly,
    )
    sign_enclave_with_untrusted_key(
        name = enclave_name,
        unsigned = unsigned_enclave_name,
        config = enclave_build_config,
        backends = backends,
        name_by_backend = signed_name_by_backend,
        testonly = testonly,
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
            asylo + "/bazel/application_wrapper:application_wrapper_driver",
        ],
        backends = backends,
        testonly = testonly,
        **loader_kwargs
    )

def _enclave_runner_script(
        name,
        loader,
        loader_args = [],
        testonly = 0,
        enclaves = {},
        remote_proxy = None,
        tags = [],
        backend = None,
        deprecation = None,
        visibility = None,
        data = []):
    _impl = _enclave_runner_script_old
    if transitions.supported(native.package_name()):
        _impl = _enclave_runner_script_new
        tags = tags + ["asylo-transition"]
    else:
        tags = tags + ["asylo-cfh"]
    _impl(
        name = name,
        loader = loader,
        loader_args = loader_args,
        testonly = testonly,
        enclaves = enclaves,
        remote_proxy = remote_proxy,
        tags = tags,
        backend = None,
        deprecation = deprecation,
        visibility = visibility,
        data = data,
    )

def _enclave_runner_test(
        name,
        loader,
        loader_args = [],
        enclaves = {},
        data = [],
        backend_dependent_data = [],
        flaky = 0,
        size = None,
        remote_proxy = None,
        testonly = 0,
        deprecation = None,
        tags = [],
        backend = None):
    _impl = _enclave_runner_test_old
    if transitions.supported(native.package_name()):
        _impl = _enclave_runner_test_new
        tags = tags + ["asylo-transition"]
    else:
        tags = tags + ["asylo-cfh"]
    _impl(
        name = name,
        loader = loader,
        loader_args = loader_args,
        enclaves = enclaves,
        data = data,
        backend_dependent_data = backend_dependent_data,
        flaky = flaky,
        size = size,
        remote_proxy = remote_proxy,
        testonly = testonly,
        deprecation = deprecation,
        tags = tags,
        backend = backend,
    )

def enclave_test(
        name,
        enclaves = {},
        embedded_enclaves = {},
        test_args = [],
        remote_proxy = None,
        backend_dependent_data = [],
        tags = [],
        backends = backend_tools.should_be_all_backends,
        loader_name_by_backend = {},
        test_name_by_backend = {},
        deprecation = None,
        **kwargs):
    """Build target for testing one or more enclaves.

    Creates a cc_test for a given enclave. Passes flags according to
    `test_args`, which can contain references to targets from `enclaves`.

    This macro creates three build targets:
     1) name: sh_test that runs the enclave_test.
     2) name_driver: cc_test used as test loader in `name`. This is a normal
                     cc_test. It cannot be directly run because there is
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
        targets. See enclave_info.bzl:all_backends documentation for details.
      deprecation: A string deprecation message for uses of this macro that
        have been marked deprecated. Optional.
      **kwargs: cc_test arguments.
    """

    test_name = name + "_driver"
    loader_name = name + "_host_driver"

    data = kwargs.pop("data", [])

    flaky = kwargs.pop("flaky", None)
    size = kwargs.pop("size", None)
    transitions.cc_binary(
        name = test_name,
        backends = backends,
        name_by_backend = loader_name_by_backend,
        testonly = 1,
        backend_dependent_data = backend_dependent_data,
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

    test_kwargs = {
        "loader": loader_name,
        "loader_args": test_args,
        "enclaves": internal.invert_enclave_name_mapping(enclaves),
        "data": data,
        "backend_dependent_data": backend_dependent_data,
        "flaky": flaky,
        "size": size,
        "remote_proxy": remote_proxy,
        "testonly": 1,
        "deprecation": deprecation,
        "tags": ["enclave_test"] + tags,
    }

    # Create test targets for each backend.
    backend_tools.all_backends(
        rule_or_macro = _enclave_runner_test,
        name = name,
        name_by_backend = test_name_by_backend,
        backends = backends,
        kwargs = test_kwargs,
        test = True,
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
        backends = backend_tools.should_be_all_backends,
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
        targets. See enclave_info.bzl:all_backends documentation for details.
      **kwargs: cc_test arguments.
    """
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

    # Don't pass transitive_features to the native cc_test.
    kwargs.pop("transitive_features", None)

    native_cc_test(
        name = name,
        srcs = srcs,
        deps = deps,
        **kwargs
    )

def cc_test_and_cc_enclave_test(
        name,
        enclave_test_name = "",
        enclave_test_config = "",
        srcs = [],
        deps = [],
        backends = backend_tools.should_be_all_backends,
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
          targets. See enclave_info.bzl:all_backends documentation for details.
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
          targets. See enclave_info.bzl:all_backends documentation for details.
      unsigned_name_by_backend: An optional dictionary from backend label to backend-
          specific target label for the defined unsigned enclaves.
      signed_name_by_backend: An optional dictionary from backend label to backend-
          specific target label for the defined signed enclaves.
      test_name_by_backend: An optional dictionary from backend label to
          backend-specific name for the test target.
      **kwargs: cc_test arguments.
    """
    _impl = _cc_enclave_test_old

    if transitions.supported(native.package_name()):
        _impl = _cc_enclave_test_new
        tags = tags + ["asylo-transition"]
    else:
        tags = tags + ["asylo-cfh"]
    _impl(
        name = name,
        srcs = srcs,
        cc_unsigned_enclave = cc_unsigned_enclave,
        sign_enclave_with_untrusted_key = sign_enclave_with_untrusted_key,
        enclave_runner_test = _enclave_runner_test,
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

def _enclave_build_test_impl(ctx):
    script = ctx.actions.declare_file(ctx.label.name + "_test_script")
    ctx.actions.write(
        output = script,
        content = "#!/bin/bash\necho \"PASS\"\n",
        is_executable = True,
    )
    return [DefaultInfo(
        files = depset([script]),
        executable = script,
        runfiles = ctx.runfiles(ctx.files.enclaves),
    )]

def _make_enclave_build_test(transition):
    transition_dict = {
        "backend": attr.label(
            mandatory = True,
            providers = [backend_tools.AsyloBackendInfo],
        ),
        "_allowlist_function_transition": attr.label(
            default = "//tools/allowlists/function_transition_allowlist",
        ),
    }
    old_dict = {
        # Ignored, provided for symmetry.
        "backend": attr.label(
            default = "@com_google_asylo_backend_provider//:nothing",
        ),
    }
    return rule(
        implementation = _enclave_build_test_impl,
        test = True,
        attrs = backend_tools.merge_dicts(
            {
                "enclaves": attr.label_list(
                    cfg = transitions.backend if transition else None,
                    allow_files = True,
                ),
            },
            transition_dict if transition else old_dict,
        ),
    )

_enclave_build_test = _make_enclave_build_test(False)

_enclave_build_transition_test = _make_enclave_build_test(True)

def enclave_build_test(
        name,
        enclaves = [],
        tags = [],
        name_by_backend = {},
        backends = backend_tools.should_be_all_backends):
    """Tests that the given enclaves build in the specified backends.

    Args:
        name: The rule name and base name for backend-specific name
            derivations.
        enclaves: A list of enclave labels.
        tags: Tags to apply to the test targets.
        name_by_backend: An optional dictionary from backend label to backend-
            specific test name.
        backends: A list of Asylo backend labels.
    """
    kwargs = {
        "enclaves": enclaves,
        "tags": tags + ["enclave_test"],
    }
    build_rule = _enclave_build_test
    if transitions.supported(native.package_name()):
        build_rule = _enclave_build_transition_test
        kwargs = backend_tools.merge_dicts(
            kwargs,
            {"tags": kwargs.get("tags", []) + ["asylo-transition"]},
        )
    else:
        kwargs = backend_tools.merge_dicts(
            kwargs,
            {"tags": kwargs.get("tags", []) + ["asylo-cfh"]},
        )
    backend_tools.all_backends(
        rule_or_macro = build_rule,
        name = name,
        name_by_backend = name_by_backend,
        backends = backends,
        kwargs = kwargs,
        test = True,
    )

def sgx_enclave_test(name, srcs, **kwargs):
    """Build target for testing one or more instances of 'sign_enclave_with_untrusted_key'.

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

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

load("@com_google_asylo_backend_provider//:enclave_info.bzl", "enclave_info")
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

def _enclave_args(enclaves):
    """Collects enclave dependencies' paths with formatted argument string.

  Arguments:
    enclaves: depset of enclave dependencies.
  Returns:
    string: If 1 enclave, "--enclave_path=<path>", otherwise
            for each enclave, "--<enclave_name>=<path>" ...
  """
    for enclave in enclaves:
        if enclave_info not in enclave:
            fail("Expected all arguments to have the enclave_info provider: " +
                 enclave.label.name)
    enclave_args = []
    if len(enclaves) == 1:
        enclave_args.append("--enclave_path=\"{path}\"".format(
            path = enclaves[0].files.to_list()[0].short_path,
        ))
    else:
        for data in enclaves:
            runpath = data.files.to_list()[0].path
            enclave_args.append("--{name}={path}".format(
                name = data.label.name,
                path = runpath,
            ))
    return " ".join(enclave_args)

def _enclave_binary_wrapper_impl(ctx):
    """Generates a runnable wrapper script around an enclave driver.

  Given a binary and its data dependencies, call the binary with flags that
  provide enclave dependencies' paths. A single enclave is given as the flag
  --enclave_path=<path>. Multiple enclaves are disambiguated with their label
  name as the flag. For example, given data dependencies on both //pkg0:enclave0
  //pkg1:enclave1, the arguments passed are --enclave0=path/to/pkg0/enclave0.so
  and --enclave1=path/to/pkg1/enclave1.so.

  Arguments:
    ctx: A blaze rule context

  Returns:
    The rule's providers. Indicates the data dependencies as runfiles.
  """
    ctx.actions.write(
        content = "#!/bin/bash\n" +
                  "\n" +
                  "exec \"./{bin}\" {args} \"$@\"\n".format(
                      bin = ctx.executable.binary.short_path,
                      args = _enclave_args(ctx.attr.enclaves),
                  ),
        is_executable = True,
        output = ctx.outputs.executable,
    )

    return [DefaultInfo(runfiles = ctx.runfiles(files = [ctx.executable.binary] +
                                                        ctx.files.data +
                                                        ctx.files.enclaves))]

_enclave_binary_wrapper = rule(
    implementation = _enclave_binary_wrapper_impl,
    executable = True,
    attrs = {
        "binary": attr.label(
            mandatory = True,
            executable = True,
            cfg = "host",
            allow_single_file = True,
        ),
        "data": attr.label_list(allow_files = True),
        "enclaves": attr.label_list(allow_files = True, providers = [enclave_info]),
    },
)

_enclave_script_test = rule(
    implementation = _enclave_binary_wrapper_impl,
    test = True,
    attrs = {
        "binary": attr.label(
            cfg = "host",
            executable = True,
            mandatory = True,
            allow_single_file = True,
        ),
        "data": attr.label_list(allow_files = True),
        "enclaves": attr.label_list(allow_files = True, providers = [enclave_info]),
    },
)

def debug_enclave_driver(name, enclaves, **kwargs):
    """Wraps cc_binary with dependency on enclave availability at runtime.

  Creates a cc_binary for a given enclave. The cc_binary will be passed
  '--enclave_path=<path to instance of |enclave|>' for 1 enclave, or
  '--<enclave_name>=<path to instance of |enclave_name.so|>' for many enclaves.

  Args:
    name: Name for build target.
    enclaves: Enclave target dependencies.
    **kwargs: cc_binary arguments.

  This macro creates three build targets:
    1) name: shell script that runs the debug_enclave_driver.
    2) name_driver: cc_binary used as driver in name. This is a normal
                    native cc_binary. It cannot be directly run because there
                    is an undeclared dependency on the enclaves.
    3) name_host_driver: genrule that builds name_driver with host crosstool.
  """
    binary_name = name + "_driver"
    host_binary_name = name + "_host_driver"
    native.cc_binary(name = binary_name, **_ensure_static_manual(kwargs))
    copy_from_host(target = binary_name, output = host_binary_name)
    _enclave_binary_wrapper(
        name = name,
        binary = host_binary_name,
        data = kwargs.get("data", []),
        enclaves = enclaves,
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

def enclave_test(name, enclave = False, enclaves = [], tags = [], **kwargs):
    """Build target for testing one or more instances of 'sgx_enclave'.

  Creates a cc_test for a given enclave. The cc_test will be passed
  '--enclave_path=<path to instance of |enclave|>' for 1 enclave, or
  '--<enclave_name>=<path to instance of |enclave_name.so|>' for many enclaves.

  Args:
    name: Name for build target.
    enclave: [deprecated, use enclaves] The sgx_enclave target to test against.
    enclaves: The sgx_enclave targets to test against.
    tags: Label attached to this test to allow for querying.
    **kwargs: cc_test arguments.

  This macro creates three build targets:
    1) name: sh_test that runs the enclave_test.
    2) name_driver: cc_test used as test driver in name. This is a normal
                    native cc_test. It cannot be directly run because there is
                    an undeclared dependency on enclave.
    3) name_host_driver: genrule that builds name_driver with host crosstool.
  """

    test_name = name + "_driver"
    host_test_name = name + "_host_driver"

    native.cc_test(
        name = test_name,
        **_ensure_static_manual(kwargs)
    )
    copy_from_host(target = test_name, output = host_test_name)

    _enclave_script_test(
        name = name,
        data = kwargs.get("data", []),
        enclaves = enclaves + ([enclave] if enclave else []),
        binary = host_test_name,
        testonly = 1,
        tags = ["enclave_test"] + tags,
    )

def cc_test(name, enclave_test_name = "", srcs = [], deps = [], **kwargs):
    """Build macro that creates a cc_test target and a cc_enclave_test target.

  This macro generates a cc_test target, which will run a gtest test suite
  normally, and optionally a cc_enclave_test, which will run the test suite
  inside of an enclave.

  Args:
    name: Same as native cc_test name.
    enclave_test_name: Name for the generated cc_enclave_test. Optional.
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
            deps = deps,
            **kwargs
        )

def cc_test_and_cc_enclave_test(name, enclave_test_name = "", srcs = [], deps = [], **kwargs):
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
        srcs = srcs,
        deps = deps,
        **kwargs
    )

def cc_enclave_test(name, srcs, tags = [], deps = [], **kwargs):
    """Build target that runs a cc_test srcs inside of an enclave.

  This macro creates two targets, one sgx_enclave target with the test source.
  And another test runner application to launch the test enclave.

  Args:
    name: Target name for will be <name>_enclave.
    srcs: Same as cc_test srcs.
    tags: Same as cc_test tags.
    deps: Same as cc_test deps.
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
    sgx_enclave(
        name = enclave_name,
        srcs = srcs,
        deps = deps + ["//asylo/bazel:test_shim_enclave"],
        testonly = 1,
    )

    # Execute the gtest enclave using the gtest enclave runner
    _enclave_script_test(
        name = name,
        data = kwargs.get("data", []),
        enclaves = [enclave_target],
        binary = host_test_name,
        testonly = 1,
        tags = ["enclave_test"] + tags,
    )

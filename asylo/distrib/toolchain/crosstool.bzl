#
# Copyright 2019 Asylo authors
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

"""Defines the Asylo toolchain CROSSTOOL"""

load("@bazel_tools//tools/build_defs/cc:action_names.bzl", "ACTION_NAMES")
load(
    "@bazel_tools//tools/cpp:cc_toolchain_config_lib.bzl",
    "action_config",
    "feature",
    "feature_set",
    "flag_group",
    "flag_set",
    "tool",
    "tool_path",
    "variable_with_value",
    "with_feature_set",
)

def _get_tools(compiler):
    if compiler == "gcc":
        return struct(
            ar = tool_path(
                name = "ar",
                path = "bin/x86_64-elf-ar",
            ),
            cpp = tool_path(
                name = "cpp",
                path = "bin/x86_64-elf-cpp",
            ),
            gcc = tool_path(
                name = "gcc",
                path = "bin/x86_64-elf-gcc",
            ),
            gpp = tool_path(
                name = "g++",
                path = "bin/x86_64-elf-g++",
            ),
            gcov = tool_path(
                name = "gcov",
                path = "bin/x86_64-elf-gcov",
            ),
            ld = tool_path(
                name = "ld",
                path = "bin/x86_64-elf-ld",
            ),
            nm = tool_path(
                name = "nm",
                path = "bin/x86_64-elf-nm",
            ),
            objcopy = tool_path(
                name = "objcopy",
                path = "bin/x86_64-elf-objcopy",
            ),
            objdump = tool_path(
                name = "objdump",
                path = "bin/x86_64-elf-objdump",
            ),
            strip = tool_path(
                name = "strip",
                path = "bin/x86_64-elf-strip",
            ),
        )
    else:
        fail("Unsupported compiler: " + compiler)

def _get_include_directories(compiler):
    if compiler == "gcc":
        return [
            "asylo/platform/posix/include",
            "asylo/platform/system/include",
            "external/com_google_asylo/asylo/platform/posix/include",
            "external/com_google_asylo/asylo/platform/system/include",
            "x86_64-elf/include",
            "x86_64-elf/include/c++/7.4.0",
            "x86_64-elf/include/c++/7.4.0/x86_64-elf",
            "x86_64-elf/include/c++/7.4.0/backward",
            "lib/gcc/x86_64-elf/7.4.0/include",
            "lib/gcc/x86_64-elf/7.4.0/include-fixed",
        ]
    else:
        fail("Unsupported compiler: " + compiler)

def _impl(ctx):
    if (ctx.attr.cpu == "k8"):
        toolchain_identifier = "asylo_k8"
    elif (ctx.attr.cpu == "sgx_x86_64"):
        toolchain_identifier = "asylo_sgx_x86_64"
    else:
        fail("Unreachable")

    host_system_name = "x86_64-local-linux-gnu"

    target_system_name = "x86_64-newlib-asylo"

    if (ctx.attr.cpu == "k8"):
        target_cpu = "k8"
    elif (ctx.attr.cpu == "sgx_x86_64"):
        target_cpu = "sgx_x86_64"
    else:
        fail("Unreachable")

    target_libc = "newlib-2.5.0.20180922"

    compiler = ctx.attr.compiler

    abi_version = "sgx_x86_64"

    abi_libc_version = "newlib-2.5.0.20180922"

    cc_target_os = "asylo"

    builtin_sysroot = None

    tools = _get_tools(compiler)

    all_link_actions = [
        ACTION_NAMES.cpp_link_executable,
        ACTION_NAMES.cpp_link_dynamic_library,
        ACTION_NAMES.cpp_link_nodeps_dynamic_library,
    ]

    cpp_header_parsing_action = action_config(
        action_name = ACTION_NAMES.cpp_header_parsing,
        implies = [
            "user_compile_flags",
            "sysroot",
            "unfiltered_compile_flags",
            "compiler_input_flags",
            "compiler_output_flags",
        ],
        tools = [tool(path = tools.gcc.path)],
    )

    cpp_module_compile_action = action_config(
        action_name = ACTION_NAMES.cpp_module_compile,
        implies = [
            "user_compile_flags",
            "sysroot",
            "unfiltered_compile_flags",
            "compiler_input_flags",
            "compiler_output_flags",
        ],
        tools = [tool(path = tools.gcc.path)],
    )

    cpp_link_static_library_action = action_config(
        action_name = ACTION_NAMES.cpp_link_static_library,
        implies = [
            "archiver_flags",
            "libraries_to_link",
            "linker_param_file",
        ],
        tools = [tool(path = tools.ar.path)],
    )

    cpp_link_nodeps_dynamic_library_action = action_config(
        action_name = ACTION_NAMES.cpp_link_nodeps_dynamic_library,
        implies = [
            "has_configured_linker_path",
            "symbol_counts",
            "strip_debug_symbols",
            "shared_flag",
            "linkstamps",
            "output_execpath_flags",
            "runtime_library_search_directories",
            "library_search_directories",
            "libraries_to_link",
            "user_link_flags",
            "linker_param_file",
            "sysroot",
        ],
        tools = [tool(path = tools.gcc.path)],
    )

    cpp_compile_action = action_config(
        action_name = ACTION_NAMES.cpp_compile,
        implies = [
            "user_compile_flags",
            "sysroot",
            "unfiltered_compile_flags",
            "compiler_input_flags",
            "compiler_output_flags",
        ],
        tools = [tool(path = "bin/x86_64-elf-g++")],
    )

    c_compile_action = action_config(
        action_name = ACTION_NAMES.c_compile,
        implies = [
            "user_compile_flags",
            "sysroot",
            "unfiltered_compile_flags",
            "compiler_input_flags",
            "compiler_output_flags",
        ],
        tools = [tool(path = tools.gcc.path)],
    )

    assemble_action = action_config(
        action_name = ACTION_NAMES.assemble,
        implies = [
            "user_compile_flags",
            "sysroot",
            "unfiltered_compile_flags",
            "compiler_input_flags",
            "compiler_output_flags",
        ],
        tools = [tool(path = tools.gcc.path)],
    )

    cpp_module_codegen_action = action_config(
        action_name = ACTION_NAMES.cpp_module_codegen,
        implies = [
            "user_compile_flags",
            "sysroot",
            "unfiltered_compile_flags",
            "compiler_input_flags",
            "compiler_output_flags",
        ],
        tools = [tool(path = tools.gcc.path)],
    )

    preprocess_assemble_action = action_config(
        action_name = ACTION_NAMES.preprocess_assemble,
        implies = [
            "user_compile_flags",
            "sysroot",
            "unfiltered_compile_flags",
            "compiler_input_flags",
            "compiler_output_flags",
        ],
        tools = [tool(path = tools.gcc.path)],
    )

    cpp_link_dynamic_library_action = action_config(
        action_name = ACTION_NAMES.cpp_link_dynamic_library,
        implies = [
            "has_configured_linker_path",
            "symbol_counts",
            "strip_debug_symbols",
            "shared_flag",
            "linkstamps",
            "output_execpath_flags",
            "runtime_library_search_directories",
            "library_search_directories",
            "libraries_to_link",
            "user_link_flags",
            "linker_param_file",
            "sysroot",
        ],
        tools = [tool(path = tools.gcc.path)],
    )

    strip_action = action_config(
        action_name = ACTION_NAMES.strip,
        flag_sets = [
            flag_set(
                flag_groups = [
                    flag_group(
                        flags = [
                            "-S",
                            "-p",
                            "-o",
                            "%{output_file}",
                            "-R",
                            ".gnu.switches.text.quote_paths",
                            "-R",
                            ".gnu.switches.text.bracket_paths",
                            "-R",
                            ".gnu.switches.text.system_paths",
                            "-R",
                            ".gnu.switches.text.cpp_defines",
                            "-R",
                            ".gnu.switches.text.cpp_includes",
                            "-R",
                            ".gnu.switches.text.cl_args",
                            "-R",
                            ".gnu.switches.text.lipo_info",
                            "-R",
                            ".gnu.switches.text.annotation",
                        ],
                    ),
                    flag_group(
                        flags = ["%{stripopts}"],
                        iterate_over = "stripopts",
                    ),
                    flag_group(flags = ["%{input_file}"]),
                ],
            ),
        ],
        tools = [tool(path = tools.strip.path)],
    )

    cpp_link_executable_action = action_config(
        action_name = ACTION_NAMES.cpp_link_executable,
        implies = [
            "symbol_counts",
            "strip_debug_symbols",
            "linkstamps",
            "output_execpath_flags_executable",
            "runtime_library_search_directories",
            "library_search_directories",
            "libraries_to_link",
            "force_pic_flags",
            "user_link_flags",
            "linker_param_file",
            "sysroot",
        ],
        tools = [tool(path = tools.gcc.path)],
    )

    cpp_link_interface_dynamic_library_action = action_config(
        action_name = "c++-link-interface-dynamic-library",
        implies = [
            "strip_debug_symbols",
            "runtime_library_search_directories",
            "library_search_directories",
            "libraries_to_link",
            "linker_param_file",
        ],
        tools = [tool(path = tools.ld.path)],
    )

    linkstamp_compile_action = action_config(
        action_name = ACTION_NAMES.linkstamp_compile,
        implies = [
            "user_compile_flags",
            "sysroot",
            "unfiltered_compile_flags",
            "compiler_input_flags",
            "compiler_output_flags",
        ],
        tools = [tool(path = tools.gcc.path)],
    )

    action_configs = [
        strip_action,
        c_compile_action,
        cpp_compile_action,
        linkstamp_compile_action,
        assemble_action,
        cpp_header_parsing_action,
        cpp_module_compile_action,
        cpp_module_codegen_action,
        preprocess_assemble_action,
        cpp_link_executable_action,
        cpp_link_dynamic_library_action,
        cpp_link_static_library_action,
        cpp_link_nodeps_dynamic_library_action,
        cpp_link_interface_dynamic_library_action,
    ]

    lipo_feature = feature(
        name = "lipo",
        flag_sets = [
            flag_set(
                actions = [ACTION_NAMES.c_compile, ACTION_NAMES.cpp_compile],
                flag_groups = [flag_group(flags = ["-fripa"])],
            ),
        ],
        requires = [
            feature_set(features = ["autofdo"]),
            feature_set(features = ["fdo_optimize"]),
            feature_set(features = ["fdo_instrument"]),
        ],
    )

    linker_param_file_feature = feature(
        name = "linker_param_file",
        flag_sets = [
            flag_set(
                actions = all_link_actions,
                flag_groups = [
                    flag_group(
                        flags = ["-Wl,@%{linker_param_file}"],
                        expand_if_available = "linker_param_file",
                    ),
                ],
            ),
            flag_set(
                actions = [ACTION_NAMES.cpp_link_static_library],
                flag_groups = [
                    flag_group(
                        flags = ["@%{linker_param_file}"],
                        expand_if_available = "linker_param_file",
                    ),
                ],
            ),
        ],
    )

    symbol_counts_feature = feature(
        name = "symbol_counts",
        flag_sets = [
            flag_set(
                actions = all_link_actions,
                flag_groups = [
                    flag_group(
                        flags = ["-Wl,--print-symbol-counts=%{symbol_counts_output}"],
                        expand_if_available = "symbol_counts_output",
                    ),
                ],
            ),
        ],
    )

    preprocessor_defines_feature = feature(
        name = "preprocessor_defines",
        enabled = True,
        flag_sets = [
            flag_set(
                actions = [
                    ACTION_NAMES.preprocess_assemble,
                    ACTION_NAMES.c_compile,
                    ACTION_NAMES.cpp_compile,
                    ACTION_NAMES.cpp_header_parsing,
                    ACTION_NAMES.cpp_module_compile,
                    ACTION_NAMES.linkstamp_compile,
                ],
                flag_groups = [
                    flag_group(
                        flags = ["-D%{preprocessor_defines}"],
                        iterate_over = "preprocessor_defines",
                    ),
                ],
            ),
        ],
    )

    dependency_file_feature = feature(
        name = "dependency_file",
        enabled = True,
        flag_sets = [
            flag_set(
                actions = [
                    ACTION_NAMES.assemble,
                    ACTION_NAMES.preprocess_assemble,
                    ACTION_NAMES.c_compile,
                    ACTION_NAMES.cpp_compile,
                    ACTION_NAMES.cpp_module_compile,
                    ACTION_NAMES.cpp_header_parsing,
                ],
                flag_groups = [
                    flag_group(
                        flags = ["-MD", "-MF", "%{dependency_file}"],
                        expand_if_available = "dependency_file",
                    ),
                ],
            ),
        ],
    )

    compiler_output_flags_feature = feature(
        name = "compiler_output_flags",
        flag_sets = [
            flag_set(
                actions = [
                    ACTION_NAMES.assemble,
                    ACTION_NAMES.preprocess_assemble,
                    ACTION_NAMES.c_compile,
                    ACTION_NAMES.cpp_compile,
                    ACTION_NAMES.linkstamp_compile,
                    ACTION_NAMES.cpp_header_parsing,
                    ACTION_NAMES.cpp_module_compile,
                    ACTION_NAMES.cpp_module_codegen,
                ],
                flag_groups = [
                    flag_group(
                        flags = ["-S"],
                        expand_if_available = "output_assembly_file",
                    ),
                    flag_group(
                        flags = ["-E"],
                        expand_if_available = "output_preprocess_file",
                    ),
                    flag_group(
                        flags = ["-o", "%{output_file}"],
                        expand_if_available = "output_file",
                    ),
                ],
            ),
        ],
    )

    no_legacy_features_feature = feature(name = "no_legacy_features")

    user_link_flags_feature = feature(
        name = "user_link_flags",
        flag_sets = [
            flag_set(
                actions = all_link_actions,
                flag_groups = [
                    flag_group(
                        flags = ["%{user_link_flags}"],
                        iterate_over = "user_link_flags",
                        expand_if_available = "user_link_flags",
                    ),
                ],
            ),
        ],
    )

    library_search_directories_feature = feature(
        name = "library_search_directories",
        flag_sets = [
            flag_set(
                actions = all_link_actions +
                          [ACTION_NAMES.cpp_link_static_library],
                flag_groups = [
                    flag_group(
                        flags = ["-L%{library_search_directories}"],
                        iterate_over = "library_search_directories",
                        expand_if_available = "library_search_directories",
                    ),
                ],
            ),
        ],
    )

    random_seed_feature = feature(
        name = "random_seed",
        enabled = True,
        flag_sets = [
            flag_set(
                actions = [
                    ACTION_NAMES.cpp_compile,
                    ACTION_NAMES.cpp_module_codegen,
                    ACTION_NAMES.cpp_module_compile,
                ],
                flag_groups = [flag_group(flags = ["-frandom-seed=%{output_file}"])],
            ),
        ],
    )

    autofdo_feature = feature(
        name = "autofdo",
        flag_sets = [
            flag_set(
                actions = [ACTION_NAMES.c_compile, ACTION_NAMES.cpp_compile],
                flag_groups = [
                    flag_group(
                        flags = [
                            "-fauto-profile=%{fdo_profile_path}",
                            "-fprofile-correction",
                        ],
                        expand_if_available = "fdo_profile_path",
                    ),
                ],
            ),
        ],
        provides = ["profile"],
    )

    compiler_input_flags_feature = feature(
        name = "compiler_input_flags",
        flag_sets = [
            flag_set(
                actions = [
                    ACTION_NAMES.assemble,
                    ACTION_NAMES.preprocess_assemble,
                    ACTION_NAMES.c_compile,
                    ACTION_NAMES.cpp_compile,
                    ACTION_NAMES.linkstamp_compile,
                    ACTION_NAMES.cpp_header_parsing,
                    ACTION_NAMES.cpp_module_compile,
                    ACTION_NAMES.cpp_module_codegen,
                ],
                flag_groups = [
                    flag_group(
                        flags = ["-c", "%{source_file}"],
                        expand_if_available = "source_file",
                    ),
                ],
            ),
        ],
    )

    default_compile_flags_feature = feature(
        name = "default_compile_flags",
        enabled = True,
        flag_sets = [
            flag_set(
                actions = [
                    ACTION_NAMES.assemble,
                    ACTION_NAMES.preprocess_assemble,
                    ACTION_NAMES.linkstamp_compile,
                    ACTION_NAMES.c_compile,
                    ACTION_NAMES.cpp_compile,
                    ACTION_NAMES.cpp_header_parsing,
                    ACTION_NAMES.cpp_module_compile,
                    ACTION_NAMES.cpp_module_codegen,
                    ACTION_NAMES.lto_backend,
                    ACTION_NAMES.clif_match,
                ],
                flag_groups = [
                    flag_group(
                        flags = [
                            "-isystemasylo/platform/posix/include",
                            "-isystemasylo/platform/system/include",
                            "-isystemexternal/com_google_asylo/asylo/platform/posix/include",
                            "-isystemexternal/com_google_asylo/asylo/platform/system/include",
                            "-D__ASYLO__",
                            "-DCOMPILER_GCC3",
                            "-D__LINUX_ERRNO_EXTENSIONS__",
                        ],
                    ),
                ],
            ),
            flag_set(
                actions = [
                    ACTION_NAMES.assemble,
                    ACTION_NAMES.preprocess_assemble,
                    ACTION_NAMES.linkstamp_compile,
                    ACTION_NAMES.c_compile,
                    ACTION_NAMES.cpp_compile,
                    ACTION_NAMES.cpp_header_parsing,
                    ACTION_NAMES.cpp_module_compile,
                    ACTION_NAMES.cpp_module_codegen,
                    ACTION_NAMES.lto_backend,
                    ACTION_NAMES.clif_match,
                ],
                flag_groups = [flag_group(flags = ["-g", "-O0"])],
                with_features = [with_feature_set(features = ["dbg"])],
            ),
            flag_set(
                actions = [
                    ACTION_NAMES.assemble,
                    ACTION_NAMES.preprocess_assemble,
                    ACTION_NAMES.linkstamp_compile,
                    ACTION_NAMES.c_compile,
                    ACTION_NAMES.cpp_compile,
                    ACTION_NAMES.cpp_header_parsing,
                    ACTION_NAMES.cpp_module_compile,
                    ACTION_NAMES.cpp_module_codegen,
                    ACTION_NAMES.lto_backend,
                    ACTION_NAMES.clif_match,
                ],
                flag_groups = [
                    flag_group(
                        flags = [
                            "-g0",
                            "-O2",
                            "-DNDEBUG",
                            "-ffunction-sections",
                            "-fdata-sections",
                            "-fPIE",
                        ],
                    ),
                ],
                with_features = [with_feature_set(features = ["opt"])],
            ),
            flag_set(
                actions = [
                    ACTION_NAMES.linkstamp_compile,
                    ACTION_NAMES.cpp_compile,
                    ACTION_NAMES.cpp_header_parsing,
                    ACTION_NAMES.cpp_module_compile,
                    ACTION_NAMES.cpp_module_codegen,
                    ACTION_NAMES.lto_backend,
                    ACTION_NAMES.clif_match,
                ],
                flag_groups = [flag_group(flags = ["-std=gnu++17"])],
            ),
        ],
    )

    output_execpath_flags_executable_feature = feature(
        name = "output_execpath_flags_executable",
        flag_sets = [
            flag_set(
                actions = [ACTION_NAMES.cpp_link_executable],
                flag_groups = [
                    flag_group(
                        flags = ["-o"],
                        expand_if_available = "output_execpath",
                    ),
                ],
            ),
            flag_set(
                actions = [ACTION_NAMES.cpp_link_executable],
                flag_groups = [
                    flag_group(
                        flag_groups = [
                            flag_group(
                                flags = ["/dev/null", "-MMD", "-MF"],
                                expand_if_available = "output_execpath",
                            ),
                        ],
                        expand_if_available = "skip_mostly_static",
                    ),
                ],
            ),
            flag_set(
                actions = [ACTION_NAMES.cpp_link_executable],
                flag_groups = [
                    flag_group(
                        flags = ["%{output_execpath}"],
                        expand_if_available = "output_execpath",
                    ),
                ],
            ),
        ],
    )

    dbg_feature = feature(name = "dbg")

    strip_debug_symbols_feature = feature(
        name = "strip_debug_symbols",
        flag_sets = [
            flag_set(
                actions = all_link_actions +
                          ["c++-link-interface-dynamic-library"],
                flag_groups = [
                    flag_group(
                        flags = ["-Wl,-S"],
                        expand_if_available = "strip_debug_symbols",
                    ),
                ],
            ),
        ],
    )

    force_pic_flags_feature = feature(
        name = "force_pic_flags",
        flag_sets = [
            flag_set(
                actions = [ACTION_NAMES.cpp_link_executable],
                flag_groups = [
                    flag_group(
                        flags = ["-pie"],
                        expand_if_available = "force_pic",
                    ),
                ],
            ),
        ],
    )

    fdo_instrument_feature = feature(
        name = "fdo_instrument",
        flag_sets = [
            flag_set(
                actions = [
                    ACTION_NAMES.c_compile,
                    ACTION_NAMES.cpp_compile,
                    "c++-link-interface-dynamic-library",
                    ACTION_NAMES.cpp_link_dynamic_library,
                    ACTION_NAMES.cpp_link_nodeps_dynamic_library,
                    ACTION_NAMES.cpp_link_executable,
                ],
                flag_groups = [
                    flag_group(
                        flags = [
                            "-fprofile-generate=%{fdo_instrument_path}",
                            "-fno-data-sections",
                        ],
                        expand_if_available = "fdo_instrument_path",
                    ),
                ],
            ),
        ],
        provides = ["profile"],
    )

    user_compile_flags_feature = feature(
        name = "user_compile_flags",
        flag_sets = [
            flag_set(
                actions = [
                    ACTION_NAMES.assemble,
                    ACTION_NAMES.preprocess_assemble,
                    ACTION_NAMES.c_compile,
                    ACTION_NAMES.cpp_compile,
                    ACTION_NAMES.cpp_header_parsing,
                    ACTION_NAMES.cpp_module_compile,
                    ACTION_NAMES.cpp_module_codegen,
                    ACTION_NAMES.linkstamp_compile,
                    ACTION_NAMES.lto_backend,
                ],
                flag_groups = [
                    flag_group(
                        flags = ["%{user_compile_flags}"],
                        iterate_over = "user_compile_flags",
                        expand_if_available = "user_compile_flags",
                    ),
                ],
            ),
        ],
    )

    supports_dynamic_linker_feature = feature(name = "supports_dynamic_linker", enabled = True)

    supports_pic_feature = feature(name = "supports_pic", enabled = True)

    static_linking_mode_feature = feature(name = "static_linking_mode")

    has_configured_linker_path_feature = feature(name = "has_configured_linker_path")

    output_execpath_flags_feature = feature(
        name = "output_execpath_flags",
        flag_sets = [
            flag_set(
                actions = [
                    ACTION_NAMES.cpp_link_dynamic_library,
                    ACTION_NAMES.cpp_link_nodeps_dynamic_library,
                ],
                flag_groups = [
                    flag_group(
                        flags = ["-o", "%{output_execpath}"],
                        expand_if_available = "output_execpath",
                    ),
                ],
            ),
        ],
    )

    pic_feature = feature(
        name = "pic",
        enabled = True,
        flag_sets = [
            flag_set(
                actions = [
                    ACTION_NAMES.c_compile,
                    ACTION_NAMES.cpp_compile,
                    ACTION_NAMES.cpp_module_codegen,
                    ACTION_NAMES.cpp_module_compile,
                    ACTION_NAMES.preprocess_assemble,
                    ACTION_NAMES.linkstamp_compile,
                ],
                flag_groups = [
                    flag_group(flags = ["-fPIC"], expand_if_available = "pic"),
                ],
            ),
        ],
    )

    per_object_debug_info_feature = None
    if (ctx.attr.cpu == "sgx_x86_64"):
        per_object_debug_info_feature = feature(
            name = "per_object_debug_info",
            enabled = True,
            flag_sets = [
                flag_set(
                    actions = [
                        ACTION_NAMES.c_compile,
                        ACTION_NAMES.cpp_compile,
                        ACTION_NAMES.cpp_module_codegen,
                        ACTION_NAMES.assemble,
                        ACTION_NAMES.preprocess_assemble,
                        ACTION_NAMES.lto_backend,
                    ],
                    flag_groups = [
                        flag_group(
                            flags = ["-gsplit-dwarf", "-g"],
                            expand_if_available = "per_object_debug_info_file",
                        ),
                    ],
                ),
            ],
        )
    elif (ctx.attr.cpu == "k8"):
        per_object_debug_info_feature = feature(
            name = "per_object_debug_info",
            enabled = True,
            flag_sets = [
                flag_set(
                    actions = [
                        ACTION_NAMES.c_compile,
                        ACTION_NAMES.cpp_compile,
                        ACTION_NAMES.cpp_module_codegen,
                        ACTION_NAMES.assemble,
                        ACTION_NAMES.preprocess_assemble,
                        ACTION_NAMES.lto_backend,
                    ],
                    flag_groups = [
                        flag_group(
                            flags = ["-gsplit-dwarf"],
                            expand_if_available = "per_object_debug_info_file",
                        ),
                    ],
                ),
            ],
        )

    fdo_optimize_feature = feature(
        name = "fdo_optimize",
        flag_sets = [
            flag_set(
                actions = [ACTION_NAMES.c_compile, ACTION_NAMES.cpp_compile],
                flag_groups = [
                    flag_group(
                        flags = [
                            "-fprofile-use=%{fdo_profile_path}",
                            "-fprofile-correction",
                        ],
                        expand_if_available = "fdo_profile_path",
                    ),
                ],
            ),
        ],
        provides = ["profile"],
    )

    unfiltered_compile_flags_feature = feature(
        name = "unfiltered_compile_flags",
        flag_sets = [
            flag_set(
                actions = [
                    ACTION_NAMES.assemble,
                    ACTION_NAMES.preprocess_assemble,
                    ACTION_NAMES.c_compile,
                    ACTION_NAMES.cpp_compile,
                    ACTION_NAMES.cpp_header_parsing,
                    ACTION_NAMES.cpp_module_compile,
                    ACTION_NAMES.cpp_module_codegen,
                    ACTION_NAMES.linkstamp_compile,
                    ACTION_NAMES.lto_backend,
                ],
                flag_groups = [
                    flag_group(
                        flags = [
                            "-no-canonical-prefixes",
                            "-fno-canonical-system-headers",
                        ],
                    ),
                ],
            ),
        ],
    )

    opt_feature = feature(name = "opt")

    linkstamps_feature = feature(
        name = "linkstamps",
        flag_sets = [
            flag_set(
                actions = all_link_actions,
                flag_groups = [
                    flag_group(
                        flags = ["%{linkstamp_paths}"],
                        iterate_over = "linkstamp_paths",
                        expand_if_available = "linkstamp_paths",
                    ),
                ],
            ),
        ],
    )

    libraries_to_link_feature = feature(
        name = "libraries_to_link",
        flag_sets = [
            flag_set(
                actions = all_link_actions +
                          [ACTION_NAMES.cpp_link_static_library],
                flag_groups = [
                    flag_group(
                        iterate_over = "libraries_to_link",
                        flag_groups = [
                            flag_group(
                                flags = ["-Wl,-whole-archive"],
                                expand_if_equal = variable_with_value(
                                    name = "libraries_to_link.type",
                                    value = "static_library",
                                ),
                                expand_if_true = "libraries_to_link.is_whole_archive",
                            ),
                            flag_group(
                                flags = ["-Wl,--start-lib"],
                                expand_if_equal = variable_with_value(
                                    name = "libraries_to_link.type",
                                    value = "object_file_group",
                                ),
                                expand_if_false = "libraries_to_link.is_whole_archive",
                            ),
                            flag_group(
                                flags = ["%{libraries_to_link.object_files}"],
                                iterate_over = "libraries_to_link.object_files",
                                expand_if_equal = variable_with_value(
                                    name = "libraries_to_link.type",
                                    value = "object_file_group",
                                ),
                            ),
                            flag_group(
                                flags = ["-Wl,--end-lib"],
                                expand_if_equal = variable_with_value(
                                    name = "libraries_to_link.type",
                                    value = "object_file_group",
                                ),
                                expand_if_false = "libraries_to_link.is_whole_archive",
                            ),
                            flag_group(
                                flags = ["%{libraries_to_link.name}"],
                                expand_if_equal = variable_with_value(
                                    name = "libraries_to_link.type",
                                    value = "object_file",
                                ),
                            ),
                            flag_group(
                                flags = ["%{libraries_to_link.name}"],
                                expand_if_equal = variable_with_value(
                                    name = "libraries_to_link.type",
                                    value = "interface_library",
                                ),
                            ),
                            flag_group(
                                flags = ["%{libraries_to_link.name}"],
                                expand_if_equal = variable_with_value(
                                    name = "libraries_to_link.type",
                                    value = "static_library",
                                ),
                            ),
                            flag_group(
                                flags = ["-l%{libraries_to_link.name}"],
                                expand_if_equal = variable_with_value(
                                    name = "libraries_to_link.type",
                                    value = "dynamic_library",
                                ),
                            ),
                            flag_group(
                                flags = ["-l:%{libraries_to_link.name}"],
                                expand_if_equal = variable_with_value(
                                    name = "libraries_to_link.type",
                                    value = "versioned_dynamic_library",
                                ),
                            ),
                            flag_group(
                                flags = ["-Wl,-no-whole-archive"],
                                expand_if_equal = variable_with_value(
                                    name = "libraries_to_link.type",
                                    value = "static_library",
                                ),
                                expand_if_true = "libraries_to_link.is_whole_archive",
                            ),
                        ],
                        expand_if_available = "libraries_to_link",
                    ),
                ],
            ),
        ],
    )

    archiver_flags_feature = feature(
        name = "archiver_flags",
        flag_sets = [
            flag_set(
                actions = [ACTION_NAMES.cpp_link_static_library],
                flag_groups = [
                    flag_group(
                        flags = ["rcsD", "%{output_execpath}"],
                        expand_if_available = "output_execpath",
                    ),
                ],
            ),
        ],
    )

    default_link_flags_feature = None
    if (ctx.attr.cpu == "k8"):
        default_link_flags_feature = feature(
            name = "default_link_flags",
            enabled = True,
            flag_sets = [
                flag_set(
                    actions = all_link_actions,
                    flag_groups = [flag_group(flags = ["-no-canonical-prefixes"])],
                ),
                flag_set(
                    actions = all_link_actions,
                    flag_groups = [flag_group(flags = ["-O0"])],
                    with_features = [with_feature_set(features = ["dbg"])],
                ),
                flag_set(
                    actions = all_link_actions,
                    flag_groups = [
                        flag_group(
                            flags = ["-Wl,--gc-sections", "-Wl,-z,relro,-z,now"],
                        ),
                    ],
                    with_features = [with_feature_set(features = ["opt"])],
                ),
                flag_set(
                    actions = [ACTION_NAMES.cpp_link_executable],
                    flag_groups = [flag_group(flags = ["-pie"])],
                    with_features = [with_feature_set(features = ["opt"])],
                ),
                flag_set(
                    actions = [ACTION_NAMES.cpp_link_executable],
                    flag_groups = [
                        flag_group(
                            flags = [
                                "-lstdc++",
                                "-lc",
                                "-lgcc",
                                "-lm",
                                "-lenclave",
                                "-Wl,-shared",
                                "-Wl,-no-undefined",
                            ],
                        ),
                    ],
                    with_features = [with_feature_set(features = ["static_linking_mode"])],
                ),
                flag_set(
                    actions = [
                        ACTION_NAMES.cpp_link_executable,
                        ACTION_NAMES.cpp_link_dynamic_library,
                    ],
                    flag_groups = [
                        flag_group(
                            flags = [
                                "-lstdc++",
                                "-lc",
                                "-lgcc",
                                "-lm",
                                "-lenclave",
                                "-Wl,-shared",
                            ],
                        ),
                    ],
                    with_features = [with_feature_set(features = ["dynamic_linking_mode"])],
                ),
                flag_set(
                    actions = [
                        ACTION_NAMES.cpp_link_nodeps_dynamic_library,
                        ACTION_NAMES.cpp_link_dynamic_library,
                    ],
                    flag_groups = [
                        flag_group(
                            flags = [
                                "-static",
                                "-lstdc++",
                                "-lc",
                                "-lgcc",
                                "-lm",
                                "-lenclave",
                                "-Wl,-shared",
                            ],
                        ),
                    ],
                    with_features = [with_feature_set(features = ["mostly_static_linking_mode"])],
                ),
                flag_set(
                    actions = [
                        ACTION_NAMES.cpp_link_nodeps_dynamic_library,
                        ACTION_NAMES.cpp_link_dynamic_library,
                    ],
                    flag_groups = [
                        flag_group(
                            flags = [
                                "-lstdc++",
                                "-lc",
                                "-lgcc",
                                "-lm",
                                "-lenclave",
                                "-Wl,-shared",
                            ],
                        ),
                    ],
                ),
            ],
        )
    elif (ctx.attr.cpu == "sgx_x86_64"):
        default_link_flags_feature = feature(
            name = "default_link_flags",
            enabled = True,
            flag_sets = [
                flag_set(
                    actions = all_link_actions,
                    flag_groups = [flag_group(flags = ["-no-canonical-prefixes"])],
                ),
                flag_set(
                    actions = all_link_actions,
                    flag_groups = [flag_group(flags = ["-O0"])],
                    with_features = [with_feature_set(features = ["dbg"])],
                ),
                flag_set(
                    actions = all_link_actions,
                    flag_groups = [
                        flag_group(
                            flags = ["-Wl,--gc-sections", "-Wl,-z,relro,-z,now"],
                        ),
                    ],
                    with_features = [with_feature_set(features = ["opt"])],
                ),
                flag_set(
                    actions = [ACTION_NAMES.cpp_link_executable],
                    flag_groups = [flag_group(flags = ["-pie"])],
                    with_features = [with_feature_set(features = ["opt"])],
                ),
                flag_set(
                    actions = [ACTION_NAMES.cpp_link_executable],
                    flag_groups = [
                        flag_group(
                            flags = [
                                "-lstdc++",
                                "-lc",
                                "-lgcc",
                                "-lm",
                                "-lenclave",
                                "-Wl,-shared",
                                "-Wl,-no-undefined",
                            ],
                        ),
                    ],
                    with_features = [with_feature_set(features = ["static_linking_mode"])],
                ),
                flag_set(
                    actions = [ACTION_NAMES.cpp_link_executable],
                    flag_groups = [
                        flag_group(
                            flags = [
                                "-lstdc++",
                                "-lc",
                                "-lgcc",
                                "-lm",
                                "-lenclave",
                                "-Wl,-shared",
                            ],
                        ),
                    ],
                    with_features = [with_feature_set(features = ["dynamic_linking_mode"])],
                ),
                flag_set(
                    actions = [
                        ACTION_NAMES.cpp_link_nodeps_dynamic_library,
                        ACTION_NAMES.cpp_link_dynamic_library,
                    ],
                    flag_groups = [
                        flag_group(
                            flags = [
                                "-lstdc++",
                                "-lc",
                                "-lgcc",
                                "-lm",
                                "-lenclave",
                                "-Wl,-shared",
                            ],
                        ),
                    ],
                ),
            ],
        )

    includes_feature = feature(
        name = "includes",
        enabled = True,
        flag_sets = [
            flag_set(
                actions = [
                    ACTION_NAMES.preprocess_assemble,
                    ACTION_NAMES.linkstamp_compile,
                    ACTION_NAMES.c_compile,
                    ACTION_NAMES.cpp_compile,
                    ACTION_NAMES.cpp_header_parsing,
                    ACTION_NAMES.cpp_module_compile,
                    ACTION_NAMES.clif_match,
                ],
                flag_groups = [
                    flag_group(
                        flags = ["-include", "%{includes}"],
                        iterate_over = "includes",
                        expand_if_available = "includes",
                    ),
                ],
            ),
        ],
    )

    include_paths_feature = feature(
        name = "include_paths",
        enabled = True,
        flag_sets = [
            flag_set(
                actions = [
                    ACTION_NAMES.preprocess_assemble,
                    ACTION_NAMES.c_compile,
                    ACTION_NAMES.cpp_compile,
                    ACTION_NAMES.cpp_header_parsing,
                    ACTION_NAMES.cpp_module_compile,
                    ACTION_NAMES.linkstamp_compile,
                    ACTION_NAMES.clif_match,
                ],
                flag_groups = [
                    flag_group(
                        flags = ["-iquote", "%{quote_include_paths}"],
                        iterate_over = "quote_include_paths",
                    ),
                    flag_group(
                        flags = ["-I%{include_paths}"],
                        iterate_over = "include_paths",
                    ),
                    flag_group(
                        flags = ["-isystem", "%{system_include_paths}"],
                        iterate_over = "system_include_paths",
                    ),
                ],
            ),
        ],
    )

    sysroot_feature = feature(
        name = "sysroot",
        flag_sets = [
            flag_set(
                actions = [
                    ACTION_NAMES.assemble,
                    ACTION_NAMES.preprocess_assemble,
                    ACTION_NAMES.c_compile,
                    ACTION_NAMES.cpp_compile,
                    ACTION_NAMES.cpp_header_parsing,
                    ACTION_NAMES.cpp_module_compile,
                    ACTION_NAMES.cpp_module_codegen,
                    ACTION_NAMES.linkstamp_compile,
                    ACTION_NAMES.lto_backend,
                    ACTION_NAMES.cpp_link_executable,
                    ACTION_NAMES.cpp_link_dynamic_library,
                    ACTION_NAMES.cpp_link_nodeps_dynamic_library,
                    ACTION_NAMES.lto_backend,
                ],
                flag_groups = [
                    flag_group(
                        flags = ["--sysroot=%{sysroot}"],
                        iterate_over = "sysroot",
                        expand_if_available = "sysroot",
                    ),
                ],
            ),
        ],
    )

    fully_static_link_feature = feature(
        name = "fully_static_link",
        flag_sets = [
            flag_set(
                actions = [
                    ACTION_NAMES.cpp_link_executable,
                    ACTION_NAMES.cpp_link_dynamic_library,
                ],
                flag_groups = [
                    flag_group(
                        flags = [
                            "-static",
                            "-lstdc++",
                            "-lc",
                            "-lgcc",
                            "-lm",
                            "-lenclave",
                            "-Wl,-shared",
                            "-Wl,-no-undefined",
                        ],
                    ),
                    flag_group(flags = ["-static"]),
                ],
            ),
        ],
    )

    shared_flag_feature = feature(
        name = "shared_flag",
        flag_sets = [
            flag_set(
                actions = [
                    ACTION_NAMES.cpp_link_dynamic_library,
                    ACTION_NAMES.cpp_link_nodeps_dynamic_library,
                ],
                flag_groups = [flag_group(flags = ["-shared"])],
            ),
        ],
    )

    runtime_library_search_directories_feature = feature(
        name = "runtime_library_search_directories",
        flag_sets = [
            flag_set(
                actions = all_link_actions +
                          [ACTION_NAMES.cpp_link_static_library],
                flag_groups = [
                    flag_group(
                        flags = [
                            "-Wl,-rpath,$ORIGIN/%{runtime_library_search_directories}",
                        ],
                        iterate_over = "runtime_library_search_directories",
                        expand_if_available = "runtime_library_search_directories",
                    ),
                ],
            ),
        ],
    )

    dynamic_linking_mode_feature = feature(name = "dynamic_linking_mode")
    mostly_static_linking_mode_feature = feature(name = "mostly_static_linking_mode")

    # Features to specify various levels of LVI mitgation, as provided by Intel.
    # https://software.intel.com/security-software-guidance/insights/deep-dive-load-value-injection#applysgxmitigation
    lvi_all_loads_mitigation_feature = feature(
        name = "lvi_all_loads_mitigation",
        flag_sets = [
            flag_set(
                actions = [
                    ACTION_NAMES.assemble,
                    ACTION_NAMES.preprocess_assemble,
                    ACTION_NAMES.c_compile,
                    ACTION_NAMES.cpp_compile,
                    ACTION_NAMES.cpp_header_parsing,
                    ACTION_NAMES.cpp_module_compile,
                    ACTION_NAMES.cpp_module_codegen,
                ],
                flag_groups = [
                    flag_group(
                        flags = [
                            "-mindirect-branch-register",
                            "-mfunction-return=thunk-inline",
                            "-Wa,-mlfence-before-ret=not",
                            "-Wa,-mlfence-after-load=yes",
                            "-fno-plt",
                        ],
                    ),
                ],
            ),
        ],
        provides = ["lvi_mitigation"],
    )

    lvi_control_flow_mitigation_feature = feature(
        name = "lvi_control_flow_mitigation",
        flag_sets = [
            flag_set(
                actions = [
                    ACTION_NAMES.assemble,
                    ACTION_NAMES.preprocess_assemble,
                    ACTION_NAMES.c_compile,
                    ACTION_NAMES.cpp_compile,
                    ACTION_NAMES.cpp_header_parsing,
                    ACTION_NAMES.cpp_module_compile,
                    ACTION_NAMES.cpp_module_codegen,
                ],
                flag_groups = [
                    flag_group(
                        flags = [
                            "-mindirect-branch-register",
                            "-mfunction-return=thunk-inline",
                            "-Wa,-mlfence-before-ret=not",
                            "-Wa,-mlfence-before-indirect-branch=register",
                            "-fno-plt",
                        ],
                    ),
                ],
            ),
        ],
        provides = ["lvi_mitigation"],
    )

    lvi_no_auto_mitigation_feature = feature(
        name = "lvi_no_auto_mitigation",
        provides = ["lvi_mitigation"],
    )

    features = [
        no_legacy_features_feature,
        has_configured_linker_path_feature,
        default_compile_flags_feature,
        symbol_counts_feature,
        shared_flag_feature,
        strip_debug_symbols_feature,
        linkstamps_feature,
        output_execpath_flags_feature,
        output_execpath_flags_executable_feature,
        runtime_library_search_directories_feature,
        library_search_directories_feature,
        archiver_flags_feature,
        libraries_to_link_feature,
        force_pic_flags_feature,
        user_link_flags_feature,
        default_link_flags_feature,
        dependency_file_feature,
        random_seed_feature,
        pic_feature,
        per_object_debug_info_feature,
        includes_feature,
        include_paths_feature,
        preprocessor_defines_feature,
        fdo_instrument_feature,
        fdo_optimize_feature,
        autofdo_feature,
        lipo_feature,
        user_compile_flags_feature,
        sysroot_feature,
        unfiltered_compile_flags_feature,
        compiler_input_flags_feature,
        compiler_output_flags_feature,
        linker_param_file_feature,
        fully_static_link_feature,
        supports_dynamic_linker_feature,
        supports_pic_feature,
        dbg_feature,
        opt_feature,
        static_linking_mode_feature,
        dynamic_linking_mode_feature,
        mostly_static_linking_mode_feature,
        lvi_all_loads_mitigation_feature,
        lvi_control_flow_mitigation_feature,
        lvi_no_auto_mitigation_feature,
    ]

    cxx_builtin_include_directories = _get_include_directories(compiler)

    artifact_name_patterns = []

    make_variables = []

    tool_paths = [
        tools.ar,
        tools.cpp,
        tools.gcc,
        tools.gpp,
        tools.gcov,
        tools.ld,
        tools.nm,
        tools.objcopy,
        tools.objdump,
        tools.strip,
    ]

    out = ctx.actions.declare_file(ctx.label.name)
    ctx.actions.write(out, "Fake executable")
    return [
        cc_common.create_cc_toolchain_config_info(
            ctx = ctx,
            features = features,
            action_configs = action_configs,
            artifact_name_patterns = artifact_name_patterns,
            cxx_builtin_include_directories = cxx_builtin_include_directories,
            toolchain_identifier = toolchain_identifier,
            host_system_name = host_system_name,
            target_system_name = target_system_name,
            target_cpu = target_cpu,
            target_libc = target_libc,
            compiler = compiler,
            abi_version = abi_version,
            abi_libc_version = abi_libc_version,
            tool_paths = tool_paths,
            make_variables = make_variables,
            builtin_sysroot = builtin_sysroot,
            cc_target_os = cc_target_os,
        ),
        DefaultInfo(
            executable = out,
        ),
    ]

cc_toolchain_config_rule = rule(
    implementation = _impl,
    attrs = {
        "cpu": attr.string(mandatory = True, values = ["k8", "sgx_x86_64"]),
        "compiler": attr.string(mandatory = True, values = ["gcc", "llvm"]),
    },
    provides = [CcToolchainConfigInfo],
    executable = True,
)

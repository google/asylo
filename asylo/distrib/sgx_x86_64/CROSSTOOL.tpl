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

# -*- protobuffer -*-

major_version: "1"
minor_version: "1"

# Remove after Bazel 0.19 release:
default_target_cpu: "sgx_x86_64"

toolchain {
  abi_version: "sgx_x86_64"
  abi_libc_version: "sgx_x86_64"
  compiler: "compiler"
  host_system_name: "x86_64-grtev4-linux-gnu"
  target_libc: "sgx-sdk"
  target_cpu: "sgx_x86_64"
  target_system_name: "x86_64-newlib-asylo"
  toolchain_identifier: "asylo_sgx_x86_64"
  cc_target_os: "asylo"

  tool_path { name: "ar" path: "bin/x86_64-elf-ar" }
  tool_path { name: "cpp" path: "bin/x86_64-elf-cpp" }
  tool_path { name: "gcc" path: "bin/x86_64-elf-gcc" }
  tool_path { name: "g++" path: "bin/x86_64-elf-g++" }
  tool_path { name: "gcov" path: "bin/x86_64-elf-gcov" }
  tool_path { name: "ld" path: "bin/x86_64-elf-ld" }
  tool_path { name: "nm" path: "bin/x86_64-elf-nm" }
  tool_path { name: "objcopy" path: "bin/x86_64-elf-objcopy" }
  tool_path { name: "objdump" path: "bin/x86_64-elf-objdump" }
  tool_path { name: "strip" path: "bin/x86_64-elf-strip" }

  cxx_builtin_include_directory: "asylo/platform/posix/include"
  cxx_builtin_include_directory: "asylo/platform/system/include"
  cxx_builtin_include_directory: "external/com_google_asylo/asylo/platform/posix/include"
  cxx_builtin_include_directory: "external/com_google_asylo/asylo/platform/system/include"
  cxx_builtin_include_directory: "x86_64-elf/include"
  cxx_builtin_include_directory: "x86_64-elf/include/c++/7.3.0"
  cxx_builtin_include_directory: "x86_64-elf/include/c++/7.3.0/x86_64-elf"
  cxx_builtin_include_directory: "x86_64-elf/include/c++/7.3.0/backward"
  cxx_builtin_include_directory: "lib/gcc/x86_64-elf/7.3.0/include"
  cxx_builtin_include_directory: "lib/gcc/x86_64-elf/7.3.0/include-fixed"

  # Required to enable optional newlib features.

  feature {
    name: "no_legacy_features"
  }

  action_config {
    config_name: 'strip'
    action_name: 'strip'
    tool {
      tool_path: 'bin/x86_64-elf-strip'
    }
    flag_set {
      flag_group {
        flag: '-S'
        flag: '-p'
        flag: '-o'
        flag: '%{output_file}'
        flag: '-R'
        flag: '.gnu.switches.text.quote_paths'
        flag: '-R'
        flag: '.gnu.switches.text.bracket_paths'
        flag: '-R'
        flag: '.gnu.switches.text.system_paths'
        flag: '-R'
        flag: '.gnu.switches.text.cpp_defines'
        flag: '-R'
        flag: '.gnu.switches.text.cpp_includes'
        flag: '-R'
        flag: '.gnu.switches.text.cl_args'
        flag: '-R'
        flag: '.gnu.switches.text.lipo_info'
        flag: '-R'
        flag: '.gnu.switches.text.annotation'
      }
      flag_group {
        iterate_over: 'stripopts'
        flag: '%{stripopts}'
      }
      flag_group {
        flag: '%{input_file}'
      }
    }
  }

  action_config {
    config_name: 'c-compile'
    action_name: 'c-compile'
    tool { tool_path: "bin/x86_64-elf-gcc" }
    implies: 'user_compile_flags'
    implies: "sysroot"
    implies: 'unfiltered_compile_flags'
    implies: 'compiler_input_flags'
    implies: 'compiler_output_flags'
  }
  action_config {
    config_name: 'c++-compile'
    action_name: 'c++-compile'
    tool { tool_path: "bin/x86_64-elf-g++" }
    implies: 'user_compile_flags'
    implies: "sysroot"
    implies: 'unfiltered_compile_flags'
    implies: 'compiler_input_flags'
    implies: 'compiler_output_flags'
  }
  action_config {
    config_name: 'preprocess-assemble'
    action_name: 'preprocess-assemble'
    tool {
      tool_path: 'bin/x86_64-elf-gcc'
    }
    implies: 'user_compile_flags'
    implies: "sysroot"
    implies: 'unfiltered_compile_flags'
    implies: 'compiler_input_flags'
    implies: 'compiler_output_flags'
  }
  action_config {
     config_name: 'c++-link-executable'
     action_name: 'c++-link-executable'
     tool {
       tool_path: "bin/x86_64-elf-gcc"
     }
     implies: 'runtime_library_search_directories'
     implies: 'library_search_directories'
     implies: 'libraries_to_link'
     implies: 'force_pic_flags'
     implies: 'user_link_flags'
     implies: 'linker_param_file'
     implies: 'sysroot'
  }
  action_config {
     config_name: 'c++-link-dynamic-library'
     action_name: 'c++-link-dynamic-library'
     tool {
       tool_path: "bin/x86_64-elf-gcc"
     }
     implies: "has_configured_linker_path"
     implies: 'output_execpath_flags'
     implies: 'runtime_library_search_directories'
     implies: 'library_search_directories'
     implies: 'libraries_to_link'
     implies: 'user_link_flags'
     implies: 'linker_param_file'
     implies: 'sysroot'
  }
  action_config {
     config_name: 'c++-link-static-library'
     action_name: 'c++-link-static-library'
     tool {
       tool_path: "bin/x86_64-elf-ar"
     }
     implies: 'archiver_flags'
     implies: 'libraries_to_link'
     implies: 'linker_param_file'
  }
  action_config {
     config_name: 'c++-link-nodeps-dynamic-library'
     action_name: 'c++-link-nodeps-dynamic-library'
     tool {
       tool_path: "bin/x86_64-elf-gcc"
     }
     implies: "has_configured_linker_path"
     implies: 'output_execpath_flags'
     implies: 'runtime_library_search_directories'
     implies: 'library_search_directories'
     implies: 'libraries_to_link'
     implies: 'user_link_flags'
     implies: 'linker_param_file'
     implies: 'sysroot'
  }
  action_config {
     config_name: 'c++-link-interface-dynamic-library'
     action_name: 'c++-link-interface-dynamic-library'
     tool {
       tool_path: "bin/x86_64-elf-ld"
     }
     implies: 'runtime_library_search_directories'
     implies: 'library_search_directories'
     implies: 'libraries_to_link'
     implies: 'linker_param_file'
  }

  feature {
    name: "has_configured_linker_path"
  }

  # This differs from default behavior because it doesn't include
  # c++-link-executable
  feature {
     name: 'output_execpath_flags'
     flag_set {
         action: 'c++-link-dynamic-library'
         action: 'c++-link-nodeps-dynamic-library'
         flag_group {
             expand_if_all_available: 'output_execpath'
             flag: '-o'
             flag: '%{output_execpath}'
         }
     }
  }

  # This is different from default because it includes alwayslink, static,
  # and pic actions.
  feature {
     name: 'runtime_library_search_directories'
     flag_set {
       action: 'c++-link-executable'
       action: 'c++-link-dynamic-library'
       action: 'c++-link-nodeps-dynamic-library'
       action: 'c++-link-static-library'
       flag_group {
         expand_if_all_available: 'runtime_library_search_directories'
         iterate_over: 'runtime_library_search_directories'
         flag: '-Wl,-rpath,$ORIGIN/%{runtime_library_search_directories}'
       }
     }
  }

  # This is different from default because it includes alwayslink, static,
  # and pic actions.
  feature {
     name: 'library_search_directories'
     flag_set {
         action: 'c++-link-executable'
         action: 'c++-link-dynamic-library'
         action: 'c++-link-nodeps-dynamic-library'
         action: 'c++-link-static-library'
         flag_group {
             expand_if_all_available: 'library_search_directories'
             iterate_over: 'library_search_directories'
             flag: "-L%{library_search_directories}"
         }
     }
  }

  feature {
    name: 'supports_pic'
    enabled: true
  }

  feature {
    name: "supports_dynamic_linker"
    enabled: true
  }

  feature {
      name: 'archiver_flags'
      flag_set {
          action: 'c++-link-static-library'
          flag_group {
            expand_if_all_available: 'output_execpath'
              flag: 'rcsD'
              flag: '%{output_execpath}'
          }
      }
  }

  # This is different from default because it includes alwayslink, static,
  # and pic actions.
  feature {
     name: 'libraries_to_link'
     flag_set {
         action: 'c++-link-executable'
         action: 'c++-link-dynamic-library'
         action: 'c++-link-nodeps-dynamic-library'
         action: 'c++-link-static-library'
         flag_group {
             expand_if_all_available: 'libraries_to_link'
             iterate_over: 'libraries_to_link'
             flag_group {
                 expand_if_true: 'libraries_to_link.is_whole_archive'
                 flag: '-Wl,-whole-archive'
             }
             flag_group {
                 expand_if_equal: {
                     variable: 'libraries_to_link.type'
                     value: 'object_file_group'
                 }
                 flag: '-Wl,--start-lib'
             }
             flag_group {
                 expand_if_equal: {
                     variable: 'libraries_to_link.type'
                     value: 'object_file_group'
                 }
                 iterate_over: 'libraries_to_link.object_files'
                 flag: '%{libraries_to_link.object_files}'
             }
             flag_group {
                 expand_if_equal: {
                     variable: 'libraries_to_link.type'
                     value: 'object_file_group'
                 }
                 flag: '-Wl,--end-lib'
             }
             flag_group {
                 expand_if_equal: {
                     variable: 'libraries_to_link.type'
                     value: 'object_file'
                 }
                 flag: '%{libraries_to_link.name}'
             }
             flag_group {
                 expand_if_equal: {
                     variable: 'libraries_to_link.type'
                     value: 'interface_library'
                 }
                 flag: '%{libraries_to_link.name}'
             }
             flag_group {
                 expand_if_equal: {
                     variable: 'libraries_to_link.type'
                     value: 'static_library'
                 }
                 flag: '%{libraries_to_link.name}'
             }
             flag_group {
                 expand_if_equal: {
                     variable: 'libraries_to_link.type'
                     value: 'dynamic_library'
                 }
                 flag: '-l%{libraries_to_link.name}'
             }
             flag_group {
                 expand_if_equal: {
                     variable: 'libraries_to_link.type'
                     value: 'versioned_dynamic_library'
                 }
                 flag: '-l:%{libraries_to_link.name}'
             }
             flag_group {
                 expand_if_true: 'libraries_to_link.is_whole_archive'
                 flag: '-Wl,-no-whole-archive'
             }
         }
     }
  }

  feature {
     name: 'force_pic_flags'
     flag_set {
         action: 'c++-link-executable'
         flag_group {
             expand_if_all_available: 'force_pic'
             flag: '-pie'
         }
     }
  }

  feature {
      name: 'user_link_flags'
      flag_set {
          action: 'c++-link-executable'
          action: 'c++-link-dynamic-library'
          action: 'c++-link-nodeps-dynamic-library'
          flag_group {
              expand_if_all_available: 'user_link_flags'
              iterate_over: 'user_link_flags'
              flag: '%{user_link_flags}'
          }
      }
  }

  # This differs from default behavior because it doesn't include objc or
  # clif-match.
  feature {
    name: "dependency_file"
    flag_set {
      action: "assemble"
      action: "preprocess-assemble"
      action: "c-compile"
      action: "c++-compile"
      action: "c++-module-compile"
      action: "c++-header-parsing"
      flag_group {
        expand_if_all_available: "dependency_file"
        flag: "-MD"
        flag: "-MF"
        flag: "%{dependency_file}"
      }
    }
    enabled: true
  }

  feature {
    name: "random_seed"
    flag_set {
      action: "c++-compile"
      action: "c++-module-codegen"
      action: "c++-module-compile"
      flag_group {
        flag: "-frandom-seed=%{output_file}"
      }
    }
    enabled: true
  }

  # This differs from default behavior because it doesn't include 'assemble'.
  feature {
    name: "pic"
    flag_set {
      action: "c-compile"
      action: "c++-compile"
      action: "c++-module-codegen"
      action: "c++-module-compile"
      action: "preprocess-assemble"
      flag_group {
        expand_if_all_available: "pic"
        flag: "-fPIC"
      }
    }
    enabled: true
  }

  # This is different from default because it doesn't include objc.
  feature {
    name: "include_paths"
    flag_set {
      action: "preprocess-assemble"
      action: "c-compile"
      action: "c++-compile"
      action: "c++-header-parsing"
      action: "c++-module-compile"
      action: "clif-match"
      flag_group {
        iterate_over: "quote_include_paths"
        flag: "-iquote"
        flag: "%{quote_include_paths}"
      }
      flag_group {
        iterate_over: "include_paths"
        flag: "-I%{include_paths}"
      }
      flag_group {
        iterate_over: "system_include_paths"
        flag: "-isystem"
        flag: "%{system_include_paths}"
      }
    }
  }

  feature {
    name: "preprocessor_defines"
    flag_set {
      action: "preprocess-assemble"
      action: "c-compile"
      action: "c++-compile"
      action: "c++-header-parsing"
      action: "c++-module-compile"
      flag_group {
        iterate_over: 'preprocessor_defines'
        flag: "-D%{preprocessor_defines}"
      }
    }
    enabled: true
  }

  # This differs from default behavior because the flags groups are merged.
  feature {
    name: "fdo_instrument"
    provides: "profile"
    flag_set {
      action: "c-compile"
      action: "c++-compile"
      action: "c++-link-interface-dynamic-library"
      action: "c++-link-dynamic-library"
      action: 'c++-link-nodeps-dynamic-library'
      action: "c++-link-executable"
      flag_group {
        expand_if_all_available: "fdo_instrument_path"
        flag: "-fprofile-generate=%{fdo_instrument_path}"
        flag: "-fno-data-sections"
      }
    }
  }

  feature {
    name: "fdo_optimize"
    provides: "profile"
    flag_set {
      action: "c-compile"
      action: "c++-compile"
      flag_group {
        expand_if_all_available: "fdo_profile_path"
        flag: "-fprofile-use=%{fdo_profile_path}"
        flag: "-fprofile-correction"
      }
    }
  }

  feature {
    name: "autofdo"
    provides: "profile"
    flag_set {
      action: "c-compile"
      action: "c++-compile"
      flag_group {
        expand_if_all_available: "fdo_profile_path"
        flag: "-fauto-profile=%{fdo_profile_path}"
        flag: "-fprofile-correction"
      }
    }
  }

  # Differs from default behavior due to requires.
  feature {
    name: "lipo"
    requires { feature: "autofdo" }
    requires { feature: "fdo_optimize" }
    requires { feature: "fdo_instrument" }
    flag_set {
      action: "c-compile"
      action: "c++-compile"
      flag_group {
        flag: "-fripa"
      }
    }
  }

  # This is different from default behavior because it doesn't include
  # clif-match.
  feature {
    name: 'user_compile_flags'
    flag_set {
      action: 'assemble'
      action: 'preprocess-assemble'
      action: 'c-compile'
      action: 'c++-compile'
      action: 'c++-header-parsing'
      action: 'c++-module-compile'
      action: 'c++-module-codegen'
      action: 'lto-backend'
      flag_group {
        expand_if_all_available: 'user_compile_flags'
        iterate_over: 'user_compile_flags'
        flag: '%{user_compile_flags}'
      }
    }
  }

  # This is different from default behavior because it doesn't include
  # clif-match.
  feature {
    name: 'sysroot'
    flag_set {
      action: 'assemble'
      action: 'preprocess-assemble'
      action: 'c-compile'
      action: 'c++-compile'
      action: 'c++-header-parsing'
      action: 'c++-module-compile'
      action: 'c++-module-codegen'
      action: 'lto-backend'
      action: 'c++-link-executable'
      action: 'c++-link-dynamic-library'
      action: 'c++-link-nodeps-dynamic-library'
      action: 'lto-backend'
      flag_group {
        expand_if_all_available: 'sysroot'
        iterate_over: 'sysroot'
        flag: '--sysroot=%{sysroot}'
      }
    }
  }

  feature {
    name: 'unfiltered_compile_flags'
    flag_set {
      action: 'assemble'
      action: 'preprocess-assemble'
      action: 'c-compile'
      action: 'c++-compile'
      action: 'c++-header-parsing'
      action: 'c++-module-compile'
      action: 'c++-module-codegen'
      action: 'lto-backend'
      flag_group {
        expand_if_all_available: 'unfiltered_compile_flags'
        flag: '-no-canonical-prefixes'
        flag: '-fno-canonical-system-headers'
        flag: "-Wno-builtin-macro-redefined"
        flag: "-D__DATE__=\"redacted\""
        flag: "-D__TIMESTAMP__=\"redacted\""
        flag: "-D__TIME__=\"redacted\""
      }
    }
  }

  feature {
    name: "default_compile_flags"
    enabled: true
    flag_set {
      action: 'assemble'
      action: 'preprocess-assemble'
      action: 'c-compile'
      action: 'c++-compile'
      action: 'c++-header-parsing'
      action: 'c++-module-compile'
      action: 'c++-module-codegen'
      flag_group {
        flag: "-isystemasylo/platform/posix/include"
        flag: "-isystemasylo/platform/system/include"
        flag: "-isystemexternal/com_google_asylo/asylo/platform/posix/include"
        flag: "-isystemexternal/com_google_asylo/asylo/platform/system/include"
        flag: "-D__LITTLE_ENDIAN"
        flag: "-D__ASYLO__"
        flag: "-D__LITTLE_ENDIAN__"
        flag: "-DCOMPILER_GCC3"
        flag: "-D__LINUX_ERRNO_EXTENSIONS__"
        flag: "-D_GLIBCXX_USE_C99"        flag: "-D_GNU_SOURCE"
      }
    }
    flag_set {
      action: 'assemble'
      action: 'preprocess-assemble'
      action: 'c-compile'
      action: 'c++-compile'
      action: 'c++-header-parsing'
      action: 'c++-module-compile'
      action: 'c++-module-codegen'
      flag_group {
        flag: '-g'
        flag: '-O0'
      }
      with_feature {
        feature: 'dbg'
      }
    }
    flag_set {
      action: 'assemble'
      action: 'preprocess-assemble'
      action: 'c-compile'
      action: 'c++-compile'
      action: 'c++-header-parsing'
      action: 'c++-module-compile'
      action: 'c++-module-codegen'
      flag_group {
        flag: "-g0"
        flag: "-fdebug-types-section"
        flag: "-O2"
        flag: "-DNDEBUG"
        flag: "-ffunction-sections"
        flag: "-fdata-sections"
        flag: "-fPIE"
        # The following are needed to compile Intel's SGX SDK in opt mode
        flag: "-Wno-array-bounds"
        flag: "-Wno-strict-aliasing"
        flag: "-Wno-maybe-uninitialized"
      }
      with_feature {
        feature: 'opt'
      }
    }
    flag_set {
      action: 'c++-compile'
      action: 'c++-header-parsing'
      action: 'c++-module-compile'
      action: 'c++-module-codegen'
      flag_group {
        flag: '-std=gnu++11'
      }
    }
  }

  feature {
    name: "default_link_flags"
    enabled: true
    flag_set {
      action: 'c++-link-executable'
      action: 'c++-link-nodeps-dynamic-library'
      action: 'c++-link-dynamic-library'
      flag_group {
        flag: "-no-canonical-prefixes"
      }
    }
    flag_set {
      action: 'c++-link-executable'
      action: 'c++-link-nodeps-dynamic-library'
      action: 'c++-link-dynamic-library'
      flag_group {
        flag: "-O0"
      }
      with_feature {
        feature: 'dbg'
      }
    }
    flag_set {
      action: 'c++-link-executable'
      action: 'c++-link-nodeps-dynamic-library'
      action: 'c++-link-dynamic-library'
      flag_group {
        flag: "-Wl,--gc-sections"
        flag: "-Wl,-z,relro,-z,now"
      }
      with_feature {
        feature: 'opt'
      }
    }
    flag_set {
      action: 'c++-link-executable'
      flag_group {
        flag: "-pie"
      }
      with_feature {
        feature: 'opt'
      }
    }
    flag_set {
      action: 'c++-link-executable'
      flag_group {
        flag: "-lstdc++"
        flag: "-lc"
        flag: "-lgcc"
        flag: "-lm"
        flag: "-lenclave"
        flag: "-Wl,-shared"
        flag: "-Wl,-no-undefined"
      }
      with_feature {
        feature: 'static_linking_mode'
      }
    }
    flag_set {
      action: 'c++-link-executable'
      action: 'c++-link-dynamic-library'
      flag_group {
        flag: "-lstdc++"
        flag: "-lc"
        flag: "-lgcc"
        flag: "-lm"
        flag: "-lenclave"
        flag: "-Wl,-shared"
      }
      with_feature {
        feature: 'dynamic_linking_mode'
      }
    }
    flag_set {
      action: 'c++-link-nodeps-dynamic-library'
      action: 'c++-link-dynamic-library'
      flag_group {
        flag: "-lstdc++"
        flag: "-lc"
        flag: "-lgcc"
        flag: "-lm"
        flag: "-lenclave"
        flag: "-Wl,-shared"
      }
      with_feature {
        feature: 'dynamic_linking_mode'
      }
    }
    flag_set {
      action: 'c++-link-nodeps-dynamic-library'
      action: 'c++-link-dynamic-library'
      flag_group {
        flag: "-static"
        flag: "-lstdc++"
        flag: "-lc"
        flag: "-lgcc"
        flag: "-lm"
        flag: "-lenclave"
        flag: "-Wl,-shared"
      }
      with_feature {
        feature: 'mostly_static_linking_mode'
      }
    }
  }

  feature { name: "dynamic_linking_mode" }
  feature { name: "static_linking_mode" }
  feature { name: "mostly_static_linking_mode" }


  feature {
    name: "includes"
    enabled: true
    flag_set {
      action: 'preprocess-assemble'
      action: 'c-compile'
      action: 'c++-compile'
      action: 'c++-header-parsing'
      action: 'c++-module-compile'
      flag_group {
        expand_if_all_available: "includes"
        iterate_over: 'includes'
        flag: '-include=%{includes}'
      }
    }
  }

  feature {
    name: "include_paths"
    enabled: true
    flag_set {
      action: 'preprocess-assemble'
      action: 'c-compile'
      action: 'c++-compile'
      action: 'c++-header-parsing'
      action: 'c++-module-compile'
      flag_group {
        iterate_over: 'quote_include_paths'
        flag: '-iquote=%{quote_include_paths}'
      }
      flag_group {
       iterate_over: 'include_paths'
        flag: '-I=%{include_paths}'
      }
      flag_group {
        iterate_over: 'system_include_paths'
        flag: '-isystem=%{system_include_paths}'
      }
    }
  }

  # This is different from default because it doesn't include lto-backend, or
  # objc.
  feature {
    name: 'compiler_input_flags'
    flag_set {
      action: 'assemble'
      action: 'preprocess-assemble'
      action: 'c-compile'
      action: 'c++-compile'
      action: 'c++-header-parsing'
      action: 'c++-module-compile'
      action: 'c++-module-codegen'
      flag_group {
        expand_if_all_available: 'source_file'
        flag: '-c'
        flag: '%{source_file}'
      }
    }
  }

  # This is different from default because it doesn't include lto-backend, or
  # objc.
  feature {
    name: 'compiler_output_flags'
    flag_set {
      action: 'assemble'
      action: 'preprocess-assemble'
      action: 'c-compile'
      action: 'c++-compile'
      action: 'c++-header-parsing'
      action: 'c++-module-compile'
      action: 'c++-module-codegen'
      flag_group {
        expand_if_all_available: 'output_assembly_file'
        flag: '-S'
      }
      flag_group {
        expand_if_all_available: 'output_preprocess_file'
        flag: '-E'
      }
      flag_group {
        expand_if_all_available: 'output_file'
        flag: '-o'
        flag: '%{output_file}'
      }
    }
  }

  # This is different from default behavior because it includes alwayslink,
  # static, and pic actions in the second flag_set.
  feature {
      name: "linker_param_file"
      flag_set {
          action: "c++-link-executable"
          action: "c++-link-dynamic-library"
          action: 'c++-link-nodeps-dynamic-library'
          flag_group {
              expand_if_all_available: "linker_param_file"
              flag: "-Wl,@%{linker_param_file}"
          }
      }
      flag_set {
          action: "c++-link-static-library"
          flag_group {
              expand_if_all_available: "linker_param_file"
              flag: "@%{linker_param_file}"
          }
      }
  }

  feature {
    name: "fully_static_link"
    flag_set {
      action: "c++-link-executable"
      flag_group {
        flag: "-static"
        flag: "-lstdc++"
        flag: "-lc"
        flag: "-lgcc"
        flag: "-lm"
        flag: "-lenclave"
        flag: "-Wl,-shared"
        flag: "-Wl,-no-undefined"
      }
      action: "c++-link-dynamic-library"
      flag_group {
        flag: "-static"
      }
    }
  }
}

# Fallback toolchain for non-sgx k8 cpus
toolchain {
  abi_version: "sgx_x86_64"
  abi_libc_version: "sgx_x86_64"
  compiler: "compiler"
  host_system_name: "x86_64-grtev4-linux-gnu"
  target_libc: "sgx-sdk"
  target_cpu: "k8"
  target_system_name: "x86_64-newlib-asylo"
  toolchain_identifier: "asylo_k8"
  cc_target_os: "asylo"

  tool_path { name: "ar" path: "bin/x86_64-elf-ar" }
  tool_path { name: "cpp" path: "bin/x86_64-elf-cpp" }
  tool_path { name: "gcc" path: "bin/x86_64-elf-gcc" }
  tool_path { name: "g++" path: "bin/x86_64-elf-g++" }
  tool_path { name: "gcov" path: "bin/x86_64-elf-gcov" }
  tool_path { name: "ld" path: "bin/x86_64-elf-ld" }
  tool_path { name: "nm" path: "bin/x86_64-elf-nm" }
  tool_path { name: "objcopy" path: "bin/x86_64-elf-objcopy" }
  tool_path { name: "objdump" path: "bin/x86_64-elf-objdump" }
  tool_path { name: "strip" path: "bin/x86_64-elf-strip" }

  cxx_builtin_include_directory: "asylo/platform/posix/include"
  cxx_builtin_include_directory: "asylo/platform/system/include"
  cxx_builtin_include_directory: "external/com_google_asylo/asylo/platform/posix/include"
  cxx_builtin_include_directory: "external/com_google_asylo/asylo/platform/system/include"
  cxx_builtin_include_directory: "x86_64-elf/include"
  cxx_builtin_include_directory: "x86_64-elf/include/c++/7.3.0"
  cxx_builtin_include_directory: "x86_64-elf/include/c++/7.3.0/x86_64-elf"
  cxx_builtin_include_directory: "x86_64-elf/include/c++/7.3.0/backward"
  cxx_builtin_include_directory: "lib/gcc/x86_64-elf/7.3.0/include"
  cxx_builtin_include_directory: "lib/gcc/x86_64-elf/7.3.0/include-fixed"

  # Required to enable optional newlib features.

  feature {
    name: "no_legacy_features"
  }

  action_config {
    config_name: 'strip'
    action_name: 'strip'
    tool {
      tool_path: 'bin/x86_64-elf-strip'
    }
    flag_set {
      flag_group {
        flag: '-S'
        flag: '-p'
        flag: '-o'
        flag: '%{output_file}'
        flag: '-R'
        flag: '.gnu.switches.text.quote_paths'
        flag: '-R'
        flag: '.gnu.switches.text.bracket_paths'
        flag: '-R'
        flag: '.gnu.switches.text.system_paths'
        flag: '-R'
        flag: '.gnu.switches.text.cpp_defines'
        flag: '-R'
        flag: '.gnu.switches.text.cpp_includes'
        flag: '-R'
        flag: '.gnu.switches.text.cl_args'
        flag: '-R'
        flag: '.gnu.switches.text.lipo_info'
        flag: '-R'
        flag: '.gnu.switches.text.annotation'
      }
      flag_group {
        iterate_over: 'stripopts'
        flag: '%{stripopts}'
      }
      flag_group {
        flag: '%{input_file}'
      }
    }
  }

  action_config {
    config_name: 'c-compile'
    action_name: 'c-compile'
    tool { tool_path: "bin/x86_64-elf-gcc" }
    implies: 'user_compile_flags'
    implies: "sysroot"
    implies: 'unfiltered_compile_flags'
    implies: 'compiler_input_flags'
    implies: 'compiler_output_flags'
  }
  action_config {
    config_name: 'c++-compile'
    action_name: 'c++-compile'
    tool { tool_path: "bin/x86_64-elf-g++" }
    implies: 'user_compile_flags'
    implies: "sysroot"
    implies: 'unfiltered_compile_flags'
    implies: 'compiler_input_flags'
    implies: 'compiler_output_flags'
  }
  action_config {
    config_name: 'preprocess-assemble'
    action_name: 'preprocess-assemble'
    tool {
      tool_path: 'bin/x86_64-elf-gcc'
    }
    implies: 'user_compile_flags'
    implies: "sysroot"
    implies: 'unfiltered_compile_flags'
    implies: 'compiler_input_flags'
    implies: 'compiler_output_flags'
  }
  action_config {
     config_name: 'c++-link-executable'
     action_name: 'c++-link-executable'
     tool {
       tool_path: "bin/x86_64-elf-gcc"
     }
     implies: 'runtime_library_search_directories'
     implies: 'library_search_directories'
     implies: 'libraries_to_link'
     implies: 'force_pic_flags'
     implies: 'user_link_flags'
     implies: 'linker_param_file'
     implies: 'sysroot'
  }
  action_config {
     config_name: 'c++-link-dynamic-library'
     action_name: 'c++-link-dynamic-library'
     tool {
       tool_path: "bin/x86_64-elf-gcc"
     }
     implies: "has_configured_linker_path"
     implies: 'output_execpath_flags'
     implies: 'runtime_library_search_directories'
     implies: 'library_search_directories'
     implies: 'libraries_to_link'
     implies: 'user_link_flags'
     implies: 'linker_param_file'
     implies: 'sysroot'
  }
  action_config {
     config_name: 'c++-link-static-library'
     action_name: 'c++-link-static-library'
     tool {
       tool_path: "bin/x86_64-elf-ar"
     }
     implies: 'archiver_flags'
     implies: 'libraries_to_link'
     implies: 'linker_param_file'
  }
  action_config {
     config_name: 'c++-link-nodeps-dynamic-library'
     action_name: 'c++-link-nodeps-dynamic-library'
     tool {
       tool_path: "bin/x86_64-elf-gcc"
     }
     implies: "has_configured_linker_path"
     implies: 'output_execpath_flags'
     implies: 'runtime_library_search_directories'
     implies: 'library_search_directories'
     implies: 'libraries_to_link'
     implies: 'user_link_flags'
     implies: 'linker_param_file'
     implies: 'sysroot'
  }
  action_config {
     config_name: 'c++-link-interface-dynamic-library'
     action_name: 'c++-link-interface-dynamic-library'
     tool {
       tool_path: "bin/x86_64-elf-ld"
     }
     implies: 'runtime_library_search_directories'
     implies: 'library_search_directories'
     implies: 'libraries_to_link'
     implies: 'linker_param_file'
  }

  feature {
    name: "has_configured_linker_path"
  }

  # This differs from default behavior because it doesn't include
  # c++-link-executable
  feature {
     name: 'output_execpath_flags'
     flag_set {
         action: 'c++-link-dynamic-library'
         action: 'c++-link-nodeps-dynamic-library'
         flag_group {
             expand_if_all_available: 'output_execpath'
             flag: '-o'
             flag: '%{output_execpath}'
         }
     }
  }

  # This is different from default because it includes alwayslink, static,
  # and pic actions.
  feature {
     name: 'runtime_library_search_directories'
     flag_set {
       action: 'c++-link-executable'
       action: 'c++-link-dynamic-library'
       action: 'c++-link-nodeps-dynamic-library'
       action: 'c++-link-static-library'
       flag_group {
         expand_if_all_available: 'runtime_library_search_directories'
         iterate_over: 'runtime_library_search_directories'
         flag: '-Wl,-rpath,$ORIGIN/%{runtime_library_search_directories}'
       }
     }
  }

  # This is different from default because it includes alwayslink, static,
  # and pic actions.
  feature {
     name: 'library_search_directories'
     flag_set {
       action: 'c++-link-executable'
       action: 'c++-link-dynamic-library'
       action: 'c++-link-nodeps-dynamic-library'
       action: 'c++-link-static-library'
       flag_group {
         expand_if_all_available: 'library_search_directories'
         iterate_over: 'library_search_directories'
         flag: "-L%{library_search_directories}"
       }
     }
  }

  feature {
    name: 'supports_pic'
    enabled: true
  }

  feature {
    name: "supports_dynamic_linker"
    enabled: true
  }

  # This is different from default because it includes alwayslink and pic.
  feature {
    name: 'archiver_flags'
    flag_set {
      action: 'c++-link-static-library'
      flag_group {
          expand_if_all_available: 'output_execpath'
          flag: 'rcsD'
          flag: '%{output_execpath}'
      }
    }
}

  # This is different from default because it includes alwayslink, static,
  # and pic actions.
  feature {
     name: 'libraries_to_link'
     flag_set {
         action: 'c++-link-executable'
         action: 'c++-link-dynamic-library'
         action: 'c++-link-nodeps-dynamic-library'
         action: 'c++-link-static-library'
         flag_group {
             expand_if_all_available: 'libraries_to_link'
             iterate_over: 'libraries_to_link'
             flag_group {
                 expand_if_true: 'libraries_to_link.is_whole_archive'
                 flag: '-Wl,-whole-archive'
             }
             flag_group {
                 expand_if_equal: {
                     variable: 'libraries_to_link.type'
                     value: 'object_file_group'
                 }
                 flag: '-Wl,--start-lib'
             }
             flag_group {
                 expand_if_equal: {
                     variable: 'libraries_to_link.type'
                     value: 'object_file_group'
                 }
                 iterate_over: 'libraries_to_link.object_files'
                 flag: '%{libraries_to_link.object_files}'
             }
             flag_group {
                 expand_if_equal: {
                     variable: 'libraries_to_link.type'
                     value: 'object_file_group'
                 }
                 flag: '-Wl,--end-lib'
             }
             flag_group {
                 expand_if_equal: {
                     variable: 'libraries_to_link.type'
                     value: 'object_file'
                 }
                 flag: '%{libraries_to_link.name}'
             }
             flag_group {
                 expand_if_equal: {
                     variable: 'libraries_to_link.type'
                     value: 'interface_library'
                 }
                 flag: '%{libraries_to_link.name}'
             }
             flag_group {
                 expand_if_equal: {
                     variable: 'libraries_to_link.type'
                     value: 'static_library'
                 }
                 flag: '%{libraries_to_link.name}'
             }
             flag_group {
                 expand_if_equal: {
                     variable: 'libraries_to_link.type'
                     value: 'dynamic_library'
                 }
                 flag: '-l%{libraries_to_link.name}'
             }
             flag_group {
                 expand_if_equal: {
                     variable: 'libraries_to_link.type'
                     value: 'versioned_dynamic_library'
                 }
                 flag: '-l:%{libraries_to_link.name}'
             }
             flag_group {
                 expand_if_true: 'libraries_to_link.is_whole_archive'
                 flag: '-Wl,-no-whole-archive'
             }
         }
     }
  }

  feature {
     name: 'force_pic_flags'
     flag_set {
         action: 'c++-link-executable'
         flag_group {
             expand_if_all_available: 'force_pic'
             flag: '-pie'
         }
     }
  }

  feature {
      name: 'user_link_flags'
      flag_set {
          action: 'c++-link-executable'
          action: 'c++-link-dynamic-library'
          action: 'c++-link-nodeps-dynamic-library'
          flag_group {
              expand_if_all_available: 'user_link_flags'
              iterate_over: 'user_link_flags'
              flag: '%{user_link_flags}'
          }
      }
  }

  # This differs from default behavior because it doesn't include objc or
  # clif-match.
  feature {
    name: "dependency_file"
    flag_set {
      action: "assemble"
      action: "preprocess-assemble"
      action: "c-compile"
      action: "c++-compile"
      action: "c++-module-compile"
      action: "c++-header-parsing"
      flag_group {
        expand_if_all_available: "dependency_file"
        flag: "-MD"
        flag: "-MF"
        flag: "%{dependency_file}"
      }
    }
    enabled: true
  }

  feature {
    name: "random_seed"
    flag_set {
      action: "c++-compile"
      action: "c++-module-codegen"
      action: "c++-module-compile"
      flag_group {
        flag: "-frandom-seed=%{output_file}"
      }
    }
    enabled: true
  }

  # This differs from default behavior because it doesn't include 'assemble'.
  feature {
    name: "pic"
    flag_set {
      action: "c-compile"
      action: "c++-compile"
      action: "c++-module-codegen"
      action: "c++-module-compile"
      action: "preprocess-assemble"
      flag_group {
        expand_if_all_available: "pic"
        flag: "-fPIC"
      }
    }
    enabled: true
  }


  # This is different from default because it doesn't include objc.
  feature {
    name: "include_paths"
    flag_set {
      action: "preprocess-assemble"
      action: "c-compile"
      action: "c++-compile"
      action: "c++-header-parsing"
      action: "c++-module-compile"
      action: "clif-match"
      flag_group {
        iterate_over: "quote_include_paths"
        flag: "-iquote"
        flag: "%{quote_include_paths}"
      }
      flag_group {
        iterate_over: "include_paths"
        flag: "-I%{include_paths}"
      }
      flag_group {
        iterate_over: "system_include_paths"
        flag: "-isystem"
        flag: "%{system_include_paths}"
      }
    }
    enabled: true
  }

  feature {
    name: "preprocessor_defines"
    enabled: true
    flag_set {
      action: "preprocess-assemble"
      action: "c-compile"
      action: "c++-compile"
      action: "c++-header-parsing"
      action: "c++-module-compile"
      flag_group {
        iterate_over: 'preprocessor_defines'
        flag: "-D%{preprocessor_defines}"
      }
    }
  }

  # This differs from default behavior because the flags groups are merged.
  feature {
    name: "fdo_instrument"
    provides: "profile"
    flag_set {
      action: "c-compile"
      action: "c++-compile"
      action: "c++-link-interface-dynamic-library"
      action: "c++-link-dynamic-library"
      action: 'c++-link-nodeps-dynamic-library'
      action: "c++-link-executable"
      flag_group {
        expand_if_all_available: "fdo_instrument_path"
        flag: "-fprofile-generate=%{fdo_instrument_path}"
        flag: "-fno-data-sections"
      }
    }
  }

  feature {
    name: "fdo_optimize"
    provides: "profile"
    flag_set {
      action: "c-compile"
      action: "c++-compile"
      flag_group {
        expand_if_all_available: "fdo_profile_path"
        flag: "-fprofile-use=%{fdo_profile_path}"
        flag: "-fprofile-correction"
      }
    }
  }

  feature {
    name: "autofdo"
    provides: "profile"
    flag_set {
      action: "c-compile"
      action: "c++-compile"
      flag_group {
        expand_if_all_available: "fdo_profile_path"
        flag: "-fauto-profile=%{fdo_profile_path}"
        flag: "-fprofile-correction"
      }
    }
  }

  # Differs from default behavior due to requires.
  feature {
    name: "lipo"
    requires { feature: "autofdo" }
    requires { feature: "fdo_optimize" }
    requires { feature: "fdo_instrument" }
    flag_set {
      action: "c-compile"
      action: "c++-compile"
      flag_group {
        flag: "-fripa"
      }
    }
  }

  # This is different from default behavior because it doesn't include
  # clif-match.
  feature {
    name: 'user_compile_flags'
    flag_set {
      action: 'assemble'
      action: 'preprocess-assemble'
      action: 'c-compile'
      action: 'c++-compile'
      action: 'c++-header-parsing'
      action: 'c++-module-compile'
      action: 'c++-module-codegen'
      action: 'lto-backend'
      flag_group {
        expand_if_all_available: 'user_compile_flags'
        iterate_over: 'user_compile_flags'
        flag: '%{user_compile_flags}'
      }
    }
  }

  # This is different from default behavior because it doesn't include
  # clif-match.
  feature {
    name: 'sysroot'
    flag_set {
      action: 'assemble'
      action: 'preprocess-assemble'
      action: 'c-compile'
      action: 'c++-compile'
      action: 'c++-header-parsing'
      action: 'c++-module-compile'
      action: 'c++-module-codegen'
      action: 'lto-backend'
      action: 'c++-link-executable'
      action: 'c++-link-dynamic-library'
      action: 'c++-link-nodeps-dynamic-library'
      action: 'lto-backend'
      flag_group {
        expand_if_all_available: 'sysroot'
        iterate_over: 'sysroot'
        flag: '--sysroot=%{sysroot}'
      }
    }
  }

  feature {
    name: 'unfiltered_compile_flags'
    flag_set {
      action: 'assemble'
      action: 'preprocess-assemble'
      action: 'c-compile'
      action: 'c++-compile'
      action: 'c++-header-parsing'
      action: 'c++-module-compile'
      action: 'c++-module-codegen'
      action: 'lto-backend'
      flag_group {
        expand_if_all_available: 'unfiltered_compile_flags'
        flag: '-no-canonical-prefixes'
        flag: '-fno-canonical-system-headers'
        flag: "-Wno-builtin-macro-redefined"
        flag: "-D__DATE__=\"redacted\""
        flag: "-D__TIMESTAMP__=\"redacted\""
        flag: "-D__TIME__=\"redacted\""
      }
    }
  }

  feature {
    name: "default_compile_flags"
    enabled: true
    flag_set {
      action: 'assemble'
      action: 'preprocess-assemble'
      action: 'c-compile'
      action: 'c++-compile'
      action: 'c++-header-parsing'
      action: 'c++-module-compile'
      action: 'c++-module-codegen'
      flag_group {
        flag: "-isystemasylo/platform/posix/include"
        flag: "-isystemasylo/platform/system/include"
        flag: "-isystemexternal/com_google_asylo/asylo/platform/posix/include"
        flag: "-isystemexternal/com_google_asylo/asylo/platform/system/include"
        flag: "-D__LITTLE_ENDIAN"
        flag: "-D__ASYLO__"
        flag: "-D__LITTLE_ENDIAN__"
        flag: "-DCOMPILER_GCC3"
        flag: "-D__LINUX_ERRNO_EXTENSIONS__"
        flag: "-D_GLIBCXX_USE_C99"
        flag: "-D_GNU_SOURCE"
      }
    }
    flag_set {
      action: 'assemble'
      action: 'preprocess-assemble'
      action: 'c-compile'
      action: 'c++-compile'
      action: 'c++-header-parsing'
      action: 'c++-module-compile'
      action: 'c++-module-codegen'
      flag_group {
        flag: '-g'
        flag: '-O0'
      }
      with_feature {
        feature: 'dbg'
      }
    }
    flag_set {
      action: 'assemble'
      action: 'preprocess-assemble'
      action: 'c-compile'
      action: 'c++-compile'
      action: 'c++-header-parsing'
      action: 'c++-module-compile'
      action: 'c++-module-codegen'
      flag_group {
        flag: "-g0"
        flag: "-fdebug-types-section"
        flag: "-O2"
        flag: "-DNDEBUG"
        flag: "-ffunction-sections"
        flag: "-fdata-sections"
        flag: "-fPIE"
        # The following are needed to compile Intel's SGX SDK in opt mode
        flag: "-Wno-array-bounds"
        flag: "-Wno-strict-aliasing"
        flag: "-Wno-maybe-uninitialized"
      }
      with_feature {
        feature: 'opt'
      }
    }
    flag_set {
      action: 'c++-compile'
      action: 'c++-header-parsing'
      action: 'c++-module-compile'
      action: 'c++-module-codegen'
      flag_group {
        flag: '-std=gnu++11'
      }
    }
  }

  feature {
    name: "default_link_flags"
    enabled: true
    flag_set {
      action: 'c++-link-executable'
      action: 'c++-link-nodeps-dynamic-library'
      action: 'c++-link-dynamic-library'
      flag_group {
        flag: "-no-canonical-prefixes"
      }
    }
    flag_set {
      action: 'c++-link-executable'
      action: 'c++-link-nodeps-dynamic-library'
      action: 'c++-link-dynamic-library'
      flag_group {
        flag: "-O0"
      }
      with_feature {
        feature: 'dbg'
      }
    }
    flag_set {
      action: 'c++-link-executable'
      action: 'c++-link-nodeps-dynamic-library'
      action: 'c++-link-dynamic-library'
      flag_group {
        flag: "-Wl,--gc-sections"
        flag: "-Wl,-z,relro,-z,now"
      }
      with_feature {
        feature: 'opt'
      }
    }
    flag_set {
      action: 'c++-link-executable'
      flag_group {
        flag: "-pie"
      }
      with_feature {
        feature: 'opt'
      }
    }
    flag_set {
      action: 'c++-link-executable'
      flag_group {
        flag: "-lstdc++"
        flag: "-lc"
        flag: "-lgcc"
        flag: "-lm"
        flag: "-lenclave"
        flag: "-Wl,-shared"
        flag: "-Wl,-no-undefined"
      }
      with_feature {
        feature: 'static_linking_mode'
      }
    }
    flag_set {
      action: 'c++-link-executable'
      action: 'c++-link-dynamic-library'
      flag_group {
        flag: "-lstdc++"
        flag: "-lc"
        flag: "-lgcc"
        flag: "-lm"
        flag: "-lenclave"
        flag: "-Wl,-shared"
      }
      with_feature {
        feature: 'dynamic_linking_mode'
      }
    }
    flag_set {
      action: 'c++-link-nodeps-dynamic-library'
      action: 'c++-link-dynamic-library'
      flag_group {
        flag: "-lstdc++"
        flag: "-lc"
        flag: "-lgcc"
        flag: "-lm"
        flag: "-lenclave"
        flag: "-Wl,-shared"
      }
      with_feature {
        feature: 'dynamic_linking_mode'
      }
    }
    flag_set {
      action: 'c++-link-nodeps-dynamic-library'
      action: 'c++-link-dynamic-library'
      flag_group {
        flag: "-static"
        flag: "-lstdc++"
        flag: "-lc"
        flag: "-lgcc"
        flag: "-lm"
        flag: "-lenclave"
        flag: "-Wl,-shared"
      }
      with_feature {
        feature: 'mostly_static_linking_mode'
      }
    }
  }

  feature { name: "dynamic_linking_mode" }
  feature { name: "static_linking_mode" }
  feature { name: "mostly_static_linking_mode" }

  feature {
    name: "includes"
    enabled: true
    flag_set {
      action: 'preprocess-assemble'
      action: 'c-compile'
      action: 'c++-compile'
      action: 'c++-header-parsing'
      action: 'c++-module-compile'
      flag_group {
        expand_if_all_available: "includes"
        iterate_over: 'includes'
        flag: '-include=%{includes}'
      }
    }
  }

  # This is different from default because it doesn't include lto-backend, or
  # objc.
  feature {
    name: 'compiler_input_flags'
    flag_set {
      action: 'assemble'
      action: 'preprocess-assemble'
      action: 'c-compile'
      action: 'c++-compile'
      action: 'c++-header-parsing'
      action: 'c++-module-compile'
      action: 'c++-module-codegen'
      flag_group {
        expand_if_all_available: 'source_file'
        flag: '-c'
        flag: '%{source_file}'
      }
    }
  }

  # This is different from default because it doesn't include lto-backend, or
  # objc.
  feature {
    name: 'compiler_output_flags'
    flag_set {
      action: 'assemble'
      action: 'preprocess-assemble'
      action: 'c-compile'
      action: 'c++-compile'
      action: 'c++-header-parsing'
      action: 'c++-module-compile'
      action: 'c++-module-codegen'
      flag_group {
        expand_if_all_available: 'output_assembly_file'
        flag: '-S'
      }
      flag_group {
        expand_if_all_available: 'output_preprocess_file'
        flag: '-E'
      }
      flag_group {
        expand_if_all_available: 'output_file'
        flag: '-o'
        flag: '%{output_file}'
      }
    }
  }

  # This is different from default behavior because it includes alwayslink,
  # static, and pic actions in the second flag_set.
  feature {
      name: "linker_param_file"
      flag_set {
          action: "c++-link-executable"
          action: "c++-link-dynamic-library"
          action: 'c++-link-nodeps-dynamic-library'
          flag_group {
              expand_if_all_available: "linker_param_file"
              flag: "-Wl,@%{linker_param_file}"
          }
      }
      flag_set {
          action: "c++-link-static-library"
          flag_group {
              expand_if_all_available: "linker_param_file"
              flag: "@%{linker_param_file}"
          }
      }
  }

  feature {
    name: "fully_static_link"
    flag_set {
      action: "c++-link-executable"
      flag_group {
        flag: "-static"
        flag: "-lstdc++"
        flag: "-lc"
        flag: "-lgcc"
        flag: "-lm"
        flag: "-lenclave"
        flag: "-Wl,-shared"
        flag: "-Wl,-no-undefined"
      }
      action: "c++-link-dynamic-library"
      flag_group {
        flag: "-static"
      }
    }
  }
}

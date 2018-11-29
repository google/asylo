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
  needsPic: true
  target_libc: "sgx-sdk"
  target_cpu: "sgx_x86_64"
  target_system_name: "x86_64-newlib-asylo"
  toolchain_identifier: "asylo_sgx_x86_64"
  default_python_version: "python2.7"
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

  compiler_flag: "-isystemexternal/com_google_asylo/asylo/platform/posix/include"
  compiler_flag: "-isystemexternal/com_google_asylo/asylo/platform/system/include"
  compiler_flag: "-D__LITTLE_ENDIAN"
  cxx_flag: "-std=gnu++11"
  objcopy_embed_flag: "--input-target=binary"
  objcopy_embed_flag: "--output-target=elf64-x86-64"
  objcopy_embed_flag: "--binary-architecture=i386:x86-64"

  cxx_builtin_include_directory: "external/com_google_asylo/asylo/platform/posix/include"
  cxx_builtin_include_directory: "external/com_google_asylo/asylo/platform/system/include"
  cxx_builtin_include_directory: "x86_64-elf/include"
  cxx_builtin_include_directory: "x86_64-elf/include/c++/7.3.0"
  cxx_builtin_include_directory: "x86_64-elf/include/c++/7.3.0/x86_64-elf"
  cxx_builtin_include_directory: "x86_64-elf/include/c++/7.3.0/backward"
  cxx_builtin_include_directory: "lib/gcc/x86_64-elf/7.3.0/include"
  cxx_builtin_include_directory: "lib/gcc/x86_64-elf/7.3.0/include-fixed"

  compiler_flag: "-D__ASYLO__"
  compiler_flag: "-D__LITTLE_ENDIAN__"
  compiler_flag: "-DCOMPILER_GCC3"
  compiler_flag: "-D__LINUX_ERRNO_EXTENSIONS__"
  compiler_flag: "-D_GLIBCXX_USE_C99"
  unfiltered_cxx_flag: "-no-canonical-prefixes"
  unfiltered_cxx_flag: "-fno-canonical-system-headers"

  # Make C++ compilation deterministic. Use linkstamping instead of these
  # compiler symbols.
  unfiltered_cxx_flag: "-Wno-builtin-macro-redefined"
  unfiltered_cxx_flag: "-D__DATE__=\"redacted\""
  unfiltered_cxx_flag: "-D__TIMESTAMP__=\"redacted\""
  unfiltered_cxx_flag: "-D__TIME__=\"redacted\""
  linker_flag: "-no-canonical-prefixes"

  # Required to enable optional newlib features.
  compiler_flag: "-D__TM_GMTOFF=tm_gmtoff"
  compiler_flag: "-D__TM_ZONE=tm_zone"
  compiler_flag: "-D_POSIX_MONOTONIC_CLOCK"
  compiler_flag: "-D_POSIX_READER_WRITER_LOCKS"
  compiler_flag: "-D_POSIX_THREADS"
  compiler_flag: "-D_UNIX98_THREAD_MUTEX_ATTRIBUTES"
  compiler_flag: "-DHAVE_FCNTL"
  compiler_flag: "-D_GNU_SOURCE"

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
    implies: 'legacy_compile_flags'
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
    implies: 'legacy_compile_flags'
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
    implies: 'legacy_compile_flags'
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
     implies: 'legacy_link_flags'
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
     implies: 'legacy_link_flags'
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
     implies: 'legacy_link_flags'
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

  feature {
    name: 'legacy_compile_flags'
    flag_set {
      expand_if_all_available: 'legacy_compile_flags'
      action: 'assemble'
      action: 'preprocess-assemble'
      action: 'c-compile'
      action: 'c++-compile'
      action: 'c++-header-parsing'
      action: 'c++-module-compile'
      action: 'c++-module-codegen'
      action: 'lto-backend'
      flag_group {
        iterate_over: 'legacy_compile_flags'
        flag: '%{legacy_compile_flags}'
      }
    }
  }

  # This differs from default behavior because it doesn't include
  # c++-link-executable
  feature {
     name: 'output_execpath_flags'
     flag_set {
         expand_if_all_available: 'output_execpath'
         action: 'c++-link-dynamic-library'
         action: 'c++-link-nodeps-dynamic-library'
         flag_group {
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
       expand_if_all_available: 'runtime_library_search_directories'
       action: 'c++-link-executable'
       action: 'c++-link-dynamic-library'
       action: 'c++-link-nodeps-dynamic-library'
       action: 'c++-link-static-library'
       flag_group {
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
         expand_if_all_available: 'library_search_directories'
         action: 'c++-link-executable'
         action: 'c++-link-dynamic-library'
         action: 'c++-link-nodeps-dynamic-library'
         action: 'c++-link-static-library'
         flag_group {
             iterate_over: 'library_search_directories'
             flag: "-L%{library_search_directories}"
         }
     }
  }

  # This is different from default because it includes alwayslink and pic.
  feature {
      name: 'archiver_flags'
      flag_set {
          expand_if_all_available: 'output_execpath'
          action: 'c++-link-static-library'
          flag_group {
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
         expand_if_all_available: 'force_pic'
         action: 'c++-link-executable'
         flag_group {
             flag: '-pie'
         }
     }
  }

  feature {
      name: 'user_link_flags'
      flag_set {
          expand_if_all_available: 'user_link_flags'
          action: 'c++-link-executable'
          action: 'c++-link-dynamic-library'
          action: 'c++-link-nodeps-dynamic-library'
          flag_group {
              iterate_over: 'user_link_flags'
              flag: '%{user_link_flags}'
          }
      }
  }

  feature {
      name: 'legacy_link_flags'
      flag_set {
          expand_if_all_available: 'legacy_link_flags'
          action: 'c++-link-executable'
          action: 'c++-link-dynamic-library'
          action: 'c++-link-nodeps-dynamic-library'
          flag_group {
              iterate_over: 'legacy_link_flags'
              flag: '%{legacy_link_flags}'
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
      expand_if_all_available: "dependency_file"
      flag_group {
        flag: "-MD"
        flag: "-MF"
        flag: "%{dependency_file}"
      }
    }
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
      expand_if_all_available: "pic"
      flag_group {
        flag: "-fPIC"
      }
    }
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
      expand_if_all_available: "fdo_profile_path"
      flag_group {
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
      expand_if_all_available: 'user_compile_flags'
      action: 'assemble'
      action: 'preprocess-assemble'
      action: 'c-compile'
      action: 'c++-compile'
      action: 'c++-header-parsing'
      action: 'c++-module-compile'
      action: 'c++-module-codegen'
      action: 'lto-backend'
      flag_group {
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
      expand_if_all_available: 'sysroot'
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
        iterate_over: 'sysroot'
        flag: '--sysroot=%{sysroot}'
      }
    }
  }

  feature {
    name: 'unfiltered_compile_flags'
    flag_set {
      expand_if_all_available: 'unfiltered_compile_flags'
      action: 'assemble'
      action: 'preprocess-assemble'
      action: 'c-compile'
      action: 'c++-compile'
      action: 'c++-header-parsing'
      action: 'c++-module-compile'
      action: 'c++-module-codegen'
      action: 'lto-backend'
      flag_group {
        iterate_over: 'unfiltered_compile_flags'
        flag: '%{unfiltered_compile_flags}'
      }
    }
  }

  # Compel Bazel to use the compiler_X_flags features, otherwise it will
  # duplicate flags to the compiler and cause errors.
  # This is a migration feature for Bazel 0.11.1 to support both
  # compiler_input_flags and compiler_output_flags features. Later versions of
  # Bazel don't need this feature, but we'll keep it to support older versions
  # of Bazel.
  feature { name: "compile_action_flags_in_flag_set" }

  # This is different from default because it doesn't include lto-backend, or
  # objc.
  feature {
    name: 'compiler_input_flags'
    flag_set {
      expand_if_all_available: 'source_file'
      action: 'assemble'
      action: 'preprocess-assemble'
      action: 'c-compile'
      action: 'c++-compile'
      action: 'c++-header-parsing'
      action: 'c++-module-compile'
      action: 'c++-module-codegen'
      flag_group {
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
          expand_if_all_available: "linker_param_file"
          action: "c++-link-executable"
          action: "c++-link-dynamic-library"
          action: 'c++-link-nodeps-dynamic-library'
          flag_group {
              flag: "-Wl,@%{linker_param_file}"
          }
      }
      flag_set {
          expand_if_all_available: "linker_param_file"
          action: "c++-link-static-library"
          flag_group {
              flag: "@%{linker_param_file}"
          }
      }
  }

  compilation_mode_flags {
    mode: DBG
    compiler_flag: "-g"
    compiler_flag: "-O0"
    linker_flag: "-O0"
  }

  compilation_mode_flags {
    mode: OPT
    compiler_flag: "-g0"
    compiler_flag: "-fdebug-types-section"
    compiler_flag: "-O2"
    compiler_flag: "-DNDEBUG"
    compiler_flag: "-ffunction-sections"
    compiler_flag: "-fdata-sections"
    linker_flag: "-Wl,--gc-sections"
    compiler_flag: "-fPIE"
    linker_flag: "-pie"
    linker_flag: "-Wl,-z,relro,-z,now"
    # The following are needed to compile Intel's SGX SDK in opt mode
    compiler_flag: "-Wno-array-bounds"
    compiler_flag: "-Wno-strict-aliasing"
    compiler_flag: "-Wno-maybe-uninitialized"
  }

  linking_mode_flags {
    mode: MOSTLY_STATIC
    linker_flag: "-lstdc++"
    linker_flag: "-lc"
    linker_flag: "-lgcc"
    linker_flag: "-lm"
    linker_flag: "-lenclave"
    linker_flag: "-Wl,-shared"
    linker_flag: "-Wl,-no-undefined"
  }

  linking_mode_flags {
    mode: FULLY_STATIC
    linker_flag: "-lstdc++"
    linker_flag: "-lc"
    linker_flag: "-lgcc"
    linker_flag: "-lm"
    linker_flag: "-lenclave"
    linker_flag: "-Wl,-shared"
    linker_flag: "-Wl,-no-undefined"
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

  linking_mode_flags {
    mode: DYNAMIC
    linker_flag: "-lstdc++"
    linker_flag: "-lc"
    linker_flag: "-lgcc"
    linker_flag: "-lm"
    linker_flag: "-lenclave"
    linker_flag: "-Wl,-shared"
  }
}

# Fallback toolchain for non-sgx k8 cpus
toolchain {
  abi_version: "sgx_x86_64"
  abi_libc_version: "sgx_x86_64"
  compiler: "compiler"
  host_system_name: "x86_64-grtev4-linux-gnu"
  needsPic: true
  target_libc: "sgx-sdk"
  target_cpu: "k8"
  target_system_name: "x86_64-newlib-asylo"
  toolchain_identifier: "asylo_k8"
  default_python_version: "python2.7"
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

  compiler_flag: "-isystemexternal/com_google_asylo/asylo/platform/posix/include"
  compiler_flag: "-isystemexternal/com_google_asylo/asylo/platform/system/include"
  compiler_flag: "-D__LITTLE_ENDIAN"
  cxx_flag: "-std=gnu++11"
  objcopy_embed_flag: "--input-target=binary"
  objcopy_embed_flag: "--output-target=elf64-x86-64"
  objcopy_embed_flag: "--binary-architecture=i386:x86-64"

  cxx_builtin_include_directory: "external/com_google_asylo/asylo/platform/posix/include"
  cxx_builtin_include_directory: "external/com_google_asylo/asylo/platform/system/include"
  cxx_builtin_include_directory: "x86_64-elf/include"
  cxx_builtin_include_directory: "x86_64-elf/include/c++/7.3.0"
  cxx_builtin_include_directory: "x86_64-elf/include/c++/7.3.0/x86_64-elf"
  cxx_builtin_include_directory: "x86_64-elf/include/c++/7.3.0/backward"
  cxx_builtin_include_directory: "lib/gcc/x86_64-elf/7.3.0/include"
  cxx_builtin_include_directory: "lib/gcc/x86_64-elf/7.3.0/include-fixed"

  compiler_flag: "-D__ASYLO__"
  compiler_flag: "-D__LITTLE_ENDIAN__"
  compiler_flag: "-DCOMPILER_GCC3"
  compiler_flag: "-D__LINUX_ERRNO_EXTENSIONS__"
  compiler_flag: "-D_GLIBCXX_USE_C99"
  unfiltered_cxx_flag: "-no-canonical-prefixes"
  unfiltered_cxx_flag: "-fno-canonical-system-headers"

  # Make C++ compilation deterministic. Use linkstamping instead of these
  # compiler symbols.
  unfiltered_cxx_flag: "-Wno-builtin-macro-redefined"
  unfiltered_cxx_flag: "-D__DATE__=\"redacted\""
  unfiltered_cxx_flag: "-D__TIMESTAMP__=\"redacted\""
  unfiltered_cxx_flag: "-D__TIME__=\"redacted\""
  linker_flag: "-no-canonical-prefixes"

  # Required to enable optional newlib features.
  compiler_flag: "-D__TM_GMTOFF=tm_gmtoff"
  compiler_flag: "-D__TM_ZONE=tm_zone"
  compiler_flag: "-D_POSIX_MONOTONIC_CLOCK"
  compiler_flag: "-D_POSIX_READER_WRITER_LOCKS"
  compiler_flag: "-D_POSIX_THREADS"
  compiler_flag: "-D_UNIX98_THREAD_MUTEX_ATTRIBUTES"
  compiler_flag: "-DHAVE_FCNTL"
  compiler_flag: "-D_GNU_SOURCE"

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
    implies: 'legacy_compile_flags'
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
    implies: 'legacy_compile_flags'
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
    implies: 'legacy_compile_flags'
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
     implies: 'legacy_link_flags'
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
     implies: 'legacy_link_flags'
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
     implies: 'legacy_link_flags'
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

  feature {
    name: 'legacy_compile_flags'
    flag_set {
      expand_if_all_available: 'legacy_compile_flags'
      action: 'assemble'
      action: 'preprocess-assemble'
      action: 'c-compile'
      action: 'c++-compile'
      action: 'c++-header-parsing'
      action: 'c++-module-compile'
      action: 'c++-module-codegen'
      action: 'lto-backend'
      flag_group {
        iterate_over: 'legacy_compile_flags'
        flag: '%{legacy_compile_flags}'
      }
    }
  }

  # This differs from default behavior because it doesn't include
  # c++-link-executable
  feature {
     name: 'output_execpath_flags'
     flag_set {
         expand_if_all_available: 'output_execpath'
         action: 'c++-link-dynamic-library'
         action: 'c++-link-nodeps-dynamic-library'
         flag_group {
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
       expand_if_all_available: 'runtime_library_search_directories'
       action: 'c++-link-executable'
       action: 'c++-link-dynamic-library'
       action: 'c++-link-nodeps-dynamic-library'
       action: 'c++-link-static-library'
       flag_group {
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
         expand_if_all_available: 'library_search_directories'
         action: 'c++-link-executable'
         action: 'c++-link-dynamic-library'
         action: 'c++-link-nodeps-dynamic-library'
         action: 'c++-link-static-library'
         flag_group {
             iterate_over: 'library_search_directories'
             flag: "-L%{library_search_directories}"
         }
     }
  }

  # This is different from default because it includes alwayslink and pic.
  feature {
      name: 'archiver_flags'
      flag_set {
          expand_if_all_available: 'output_execpath'
          action: 'c++-link-static-library'
          flag_group {
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
         expand_if_all_available: 'force_pic'
         action: 'c++-link-executable'
         flag_group {
             flag: '-pie'
         }
     }
  }

  feature {
      name: 'user_link_flags'
      flag_set {
          expand_if_all_available: 'user_link_flags'
          action: 'c++-link-executable'
          action: 'c++-link-dynamic-library'
          action: 'c++-link-nodeps-dynamic-library'
          flag_group {
              iterate_over: 'user_link_flags'
              flag: '%{user_link_flags}'
          }
      }
  }

  feature {
      name: 'legacy_link_flags'
      flag_set {
          expand_if_all_available: 'legacy_link_flags'
          action: 'c++-link-executable'
          action: 'c++-link-dynamic-library'
          action: 'c++-link-nodeps-dynamic-library'
          flag_group {
              iterate_over: 'legacy_link_flags'
              flag: '%{legacy_link_flags}'
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
      expand_if_all_available: "dependency_file"
      flag_group {
        flag: "-MD"
        flag: "-MF"
        flag: "%{dependency_file}"
      }
    }
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
      expand_if_all_available: "pic"
      flag_group {
        flag: "-fPIC"
      }
    }
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
      expand_if_all_available: "fdo_profile_path"
      flag_group {
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
      expand_if_all_available: 'user_compile_flags'
      action: 'assemble'
      action: 'preprocess-assemble'
      action: 'c-compile'
      action: 'c++-compile'
      action: 'c++-header-parsing'
      action: 'c++-module-compile'
      action: 'c++-module-codegen'
      action: 'lto-backend'
      flag_group {
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
      expand_if_all_available: 'sysroot'
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
        iterate_over: 'sysroot'
        flag: '--sysroot=%{sysroot}'
      }
    }
  }

  feature {
    name: 'unfiltered_compile_flags'
    flag_set {
      expand_if_all_available: 'unfiltered_compile_flags'
      action: 'assemble'
      action: 'preprocess-assemble'
      action: 'c-compile'
      action: 'c++-compile'
      action: 'c++-header-parsing'
      action: 'c++-module-compile'
      action: 'c++-module-codegen'
      action: 'lto-backend'
      flag_group {
        iterate_over: 'unfiltered_compile_flags'
        flag: '%{unfiltered_compile_flags}'
      }
    }
  }

  # Compel Bazel to use the compiler_X_flags features, otherwise it will
  # duplicate flags to the compiler and cause errors.
  # This is a migration feature for Bazel 0.11.1 to support both
  # compiler_input_flags and compiler_output_flags features. Later versions of
  # Bazel don't need this feature, but we'll keep it to support older versions
  # of Bazel.
  feature { name: "compile_action_flags_in_flag_set" }

  # This is different from default because it doesn't include lto-backend, or
  # objc.
  feature {
    name: 'compiler_input_flags'
    flag_set {
      expand_if_all_available: 'source_file'
      action: 'assemble'
      action: 'preprocess-assemble'
      action: 'c-compile'
      action: 'c++-compile'
      action: 'c++-header-parsing'
      action: 'c++-module-compile'
      action: 'c++-module-codegen'
      flag_group {
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
          expand_if_all_available: "linker_param_file"
          action: "c++-link-executable"
          action: "c++-link-dynamic-library"
          action: 'c++-link-nodeps-dynamic-library'
          flag_group {
              flag: "-Wl,@%{linker_param_file}"
          }
      }
      flag_set {
          expand_if_all_available: "linker_param_file"
          action: "c++-link-static-library"
          flag_group {
              flag: "@%{linker_param_file}"
          }
      }
  }

  compilation_mode_flags {
    mode: DBG
    compiler_flag: "-g"
    compiler_flag: "-O0"
    linker_flag: "-O0"
  }

  compilation_mode_flags {
    mode: OPT
    compiler_flag: "-g0"
    compiler_flag: "-fdebug-types-section"
    compiler_flag: "-O2"
    compiler_flag: "-DNDEBUG"
    compiler_flag: "-ffunction-sections"
    compiler_flag: "-fdata-sections"
    linker_flag: "-Wl,--gc-sections"
    compiler_flag: "-fPIE"
    linker_flag: "-pie"
    linker_flag: "-Wl,-z,relro,-z,now"
    # The following are needed to compile Intel's SGX SDK in opt mode
    compiler_flag: "-Wno-array-bounds"
    compiler_flag: "-Wno-strict-aliasing"
    compiler_flag: "-Wno-maybe-uninitialized"
  }

  linking_mode_flags {
    mode: MOSTLY_STATIC
    linker_flag: "-lstdc++"
    linker_flag: "-lc"
    linker_flag: "-lgcc"
    linker_flag: "-lm"
    linker_flag: "-lenclave"
    linker_flag: "-Wl,-shared"
    linker_flag: "-Wl,-no-undefined"
  }

  linking_mode_flags {
    mode: FULLY_STATIC
    linker_flag: "-lstdc++"
    linker_flag: "-lc"
    linker_flag: "-lgcc"
    linker_flag: "-lm"
    linker_flag: "-lenclave"
    linker_flag: "-Wl,-shared"
    linker_flag: "-Wl,-no-undefined"
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

  linking_mode_flags {
    mode: DYNAMIC
    linker_flag: "-lstdc++"
    linker_flag: "-lc"
    linker_flag: "-lgcc"
    linker_flag: "-lm"
    linker_flag: "-lenclave"
    linker_flag: "-Wl,-shared"
  }
}

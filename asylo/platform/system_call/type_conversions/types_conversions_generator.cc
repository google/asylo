/*
 *
 * Copyright 2019 Asylo authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#include <fstream>
#include <string>
#include <vector>

#include "absl/container/flat_hash_map.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_format.h"
#include "gflags/gflags.h"
#include "asylo/util/logging.h"
#include "asylo/platform/system_call/type_conversions/types_macros.inc"

// A struct describing properties and values of a enum desired to be generated
// by the types conversions generator.
struct EnumProperties {
  int default_value_host;
  int default_value_newlib;
  bool multi_valued;
  bool skip_conversions_generation;

  // A vector of enum values in the format std::pair{Enum name, Enum value}.
  // Enum name is simply a literal describing the enum value as a string. This
  // cannot be simply a map from enum values to enum names since multiple enum
  // names may resolve to the same enum value.
  // Eg. AF_UNIX and AF_LOCAL both share the same value (typically 1).
  std::vector<std::pair<std::string, int>> values;
};

DEFINE_string(output_dir, "", "Path of the output dir for generated types.");

// Returns a mapping from enum name to EnumProperties.
absl::flat_hash_map<std::string, EnumProperties> *GetEnumPropertiesTable() {
  static absl::flat_hash_map<std::string, EnumProperties> *enum_map =
      new absl::flat_hash_map<std::string, EnumProperties>{ENUMS_INIT};
  return enum_map;
}

// Writes the provided includes to an output stream. These includes are needed
// by the type conversion functions for resolving the type definitions in
// newlib.
void WriteMacroProvidedIncludes(std::ostream *os) {
  *os << "// Includes provided for resolving types\n";
  std::vector<std::string> includes = {INCLUDES};
  for (const auto &incl : includes) {
    *os << absl::StreamFormat("#include <%s>\n", incl);
  }
  *os << "\n";
}

// Takes a {Enum name, EnumProperties} mapping and generates the enum
// definitions, the values for which are resolved based on the libc/Linux
// implementation on the host. Prefixes each enum value with the prefix
// obtained from types_macros.inc
void WriteTypeDefinitions(const absl::flat_hash_map<std::string, EnumProperties>
                              *enum_properties_table,
                          std::ostream *os) {
  // Write #ifdef guard
  std::string header_guard_name =
      "ASYLO_PLATFORM_SYSTEM_CALL_TYPE_CONVERSIONS_GENERATED_TYPES_"
      "H_";
  *os << "#ifndef " << header_guard_name << "\n"
      << "#define " << header_guard_name << "\n";

  // Write the includes. These may be needed when manually writing conversion
  // functions for certain automatically generated enums (where
  // skip_conversions_generation = true)
  WriteMacroProvidedIncludes(os);

  for (const auto &it : *enum_properties_table) {
    *os << absl::StreamFormat("\nenum %s {\n", it.first);

    // Accumulate comma separated resolved enum pairs (eg. kLinux_F_GETFD = 1,
    // kLinux_F_SETFD = 2,).
    for (const auto &current : it.second.values) {
      *os << absl::StreamFormat("  %s_%s = %d,\n", prefix, current.first,
                                current.second);
    }
    *os << "};\n";
  }

  // End #ifdef guard
  *os << "\n#endif  // " << header_guard_name << "\n";
}

// Generates the function body for enum type conversions where the enums can be
// multi-valued.
std::string GetOrBasedEnumBody(bool to_prefix, const std::string &enum_name,
                               const EnumProperties &enum_properties) {
  std::ostringstream func_body;
  std::string input_variable_name =
      to_prefix ? enum_name : absl::StrCat(prefix, "_", enum_name);
  std::string result_variable_name =
      to_prefix ? absl::StrCat(prefix, "_", enum_name) : enum_name;

  // Generate result variable declaration.
  func_body << "  int " << result_variable_name << " = "
            << (to_prefix ? enum_properties.default_value_host
                          : enum_properties.default_value_newlib)
            << ";\n";

  // Generate or-based enum result accumulation.
  for (const auto &enum_pair : enum_properties.values) {
    func_body << "  if (" << input_variable_name << " & "
              << (to_prefix ? enum_pair.first
                            : absl::StrCat(prefix, "_", enum_pair.first))
              << ") " << result_variable_name << " |= "
              << (to_prefix ? absl::StrCat(prefix, "_", enum_pair.first)
                            : enum_pair.first)
              << ";\n";
  }

  // Generate return statement.
  func_body << "  return " << result_variable_name << ";\n";

  return func_body.str();
}

// Generate the function body for enum type conversions where the enums cannot
// be multi-valued. Uses an if condition based implementation to find the
// matching enum. A switch case should not be used here because enum values may
// be duplicate.
std::string GetIfBasedEnumBody(bool to_prefix, const std::string &enum_name,
                               const EnumProperties &enum_properties) {
  std::ostringstream func_body;
  std::string input_variable_name =
      to_prefix ? enum_name : absl::StrCat(prefix, "_", enum_name);

  for (const auto &enum_pair : enum_properties.values) {
    func_body << "  if (" << input_variable_name << " == "
              << (to_prefix ? enum_pair.first
                            : absl::StrCat(prefix, "_", enum_pair.first))
              << ") {\n";
    func_body << "      return "
              << (to_prefix ? absl::StrCat(prefix, "_", enum_pair.first)
                            : enum_pair.first)
              << ";\n";
    func_body << "  }\n";
  }

  // Generate code for handling default case.
  func_body << "  return "
            << (to_prefix ? enum_properties.default_value_host
                          : enum_properties.default_value_newlib)
            << ";\n";

  return func_body.str();
}

// Generates and writes the enum types conversion functions to the output
// streams provided. Writes the conversion function declarations to |os_h| and
// the corresponding implementations to |os_cc|.
void WriteTypesConversions(
    absl::flat_hash_map<std::string, EnumProperties> *enum_properties_table,
    std::ostream *os_h, std::ostream *os_cc) {
  // Write #ifdef guard for .h file.
  std::string header_guard_name =
      "ASYLO_PLATFORM_SYSTEM_CALL_TYPE_CONVERSIONS_GENERATED_TYPES_"
      "FUNCTIONS_H_";
  *os_h << "#ifndef " << header_guard_name << "\n"
        << "#define " << header_guard_name << "\n\n";

  // Write all the includes.
  WriteMacroProvidedIncludes(os_h);
  *os_cc << "#include "
            "\"asylo/platform/system_call/type_conversions/"
            "generated_types_functions.h\"\n";
  *os_h << "#include "
           "\"asylo/platform/system_call/type_conversions/"
           "generated_types.h\"\n";

  for (const auto &it : *enum_properties_table) {
    if (it.second.skip_conversions_generation) {
      continue;
    }

    std::string enum_name_lower = it.first;
    std::transform(enum_name_lower.begin(), enum_name_lower.end(),
                   enum_name_lower.begin(), ::tolower);

    std::ostringstream to_prefix_declaration, from_prefix_declaration;
    to_prefix_declaration << "int To" << prefix << it.first << "(int "
                          << enum_name_lower << ")";
    from_prefix_declaration << "int From" << prefix << it.first << "(int "
                            << prefix << "_" << enum_name_lower << ")";

    // Write the function declarations to the header file.
    *os_h << "\n" << to_prefix_declaration.str() << "; \n";
    *os_h << "\n" << from_prefix_declaration.str() << "; \n";

    // Write the function body to the cc file.
    if (it.second.multi_valued) {
      *os_cc << "\n"
             << to_prefix_declaration.str() << " {\n"
             << GetOrBasedEnumBody(true, enum_name_lower, it.second) << "}\n";
      *os_cc << "\n"
             << from_prefix_declaration.str() << " {\n"
             << GetOrBasedEnumBody(false, enum_name_lower, it.second) << "}\n";
    } else {
      *os_cc << "\n"
             << to_prefix_declaration.str() << " {\n"
             << GetIfBasedEnumBody(true, enum_name_lower, it.second) << "}\n";
      *os_cc << "\n"
             << from_prefix_declaration.str() << " {\n"
             << GetIfBasedEnumBody(false, enum_name_lower, it.second) << "}\n";
    }
  }

  // End #ifdef guard for the header file.
  *os_h << "\n#endif  // " << header_guard_name << "\n";
}

int main(int argc, char **argv) {
  // Parse command-line arguments.
  google::ParseCommandLineFlags(&argc, &argv, true);

  CHECK(!FLAGS_output_dir.empty()) << "Must provide output dir path.";

  auto enum_properties_table = GetEnumPropertiesTable();
  std::ofstream types_h, types_functions_h, types_functions_cc;

  types_h.open(absl::StrCat(FLAGS_output_dir, "/generated_types.h"));
  types_functions_h.open(
      absl::StrCat(FLAGS_output_dir, "/generated_types_functions.h"));
  types_functions_cc.open(
      absl::StrCat(FLAGS_output_dir, "/generated_types_functions.cc"));

  WriteTypeDefinitions(enum_properties_table, &types_h);
  WriteTypesConversions(enum_properties_table, &types_functions_h,
                        &types_functions_cc);

  types_h.close();
  types_functions_h.close();
  types_functions_cc.close();

  return 0;
}

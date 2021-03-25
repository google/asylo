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
#include <map>
#include <string>
#include <vector>

#include "absl/container/flat_hash_map.h"
#include "absl/flags/flag.h"
#include "absl/flags/parse.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_format.h"
#include "absl/strings/str_replace.h"
#include "absl/strings/string_view.h"
#include "asylo/util/logging.h"
#include "asylo/platform/system_call/type_conversions/types_macros.inc"

// A struct describing properties and values of a enum desired to be generated
// by the types conversions generator.
struct EnumProperties {
  bool multi_valued;
  bool skip_conversions;
  bool wrap_macros_with_if_defined;
  std::string data_type;

  // A vector of enum values in the format std::pair{Enum name, Enum value}.
  // Enum name is simply a literal describing the enum value as a string. This
  // cannot be simply a map from enum values to enum names since multiple enum
  // names may resolve to the same enum value.
  // Eg. AF_UNIX and AF_LOCAL both share the same value (typically 1).
  std::vector<std::pair<std::string, int64_t>> values;
};

// A record describing a C++ struct.
struct StructProperties {
  bool pack_attributes;
  bool skip_conversions;

  // A vector of struct members in the format std::pair{member name, member
  // type}.
  std::vector<std::pair<std::string, std::string>> values;
};

ABSL_FLAG(std::string, output_dir, "",
          "Path of the output dir for generated types.");

// Returns a mapping from enum name to EnumProperties.
std::map<std::string, EnumProperties> *GetEnumPropertiesTable() {
  static auto enum_map = new std::map<std::string, EnumProperties>{ENUMS_INIT};
  return enum_map;
}

// Returns a mapping from struct name to StructProperties.
std::map<std::string, StructProperties> *GetStructPropertiesTable() {
  static auto struct_map =
      new std::map<std::string, StructProperties>{STRUCTS_INIT};
  return struct_map;
}

// Writes the provided includes to an output stream. These includes are needed
// by the type conversion functions for resolving the type definitions on the
// host C library.
void WriteMacroProvidedIncludes(std::ostream *os) {
  std::vector<std::string> includes = {INCLUDES};
  for (const auto &incl : includes) {
    *os << absl::StreamFormat("#include <%s>\n", incl);
  }
  *os << "\n";
}

// Generates the function body for enum type conversions where the enums can be
// multi-valued.
std::string GetOrBasedEnumBody(bool to_prefix, const std::string &enum_name,
                               const EnumProperties &enum_properties) {
  std::ostringstream os;

  // Generate result initialization.
  os << "  " << enum_properties.data_type << " output = 0;\n";

  // Catch empty input early and just bail out.
  os << "  if (input == 0) { return 0; }\n";

  // Generate or-based enum result accumulation. Since there are cases that enum
  // may contain multiple bits, the value has to be checked explicitly.
  for (const auto &enum_pair : enum_properties.values) {
    if (enum_properties.wrap_macros_with_if_defined) {
      os << "#if defined(" << enum_pair.first << ")\n";
    }
    const std::string input_bit =
        to_prefix ? enum_pair.first
                  : absl::StrCat(klinux_prefix, "_", enum_pair.first);
    const std::string output_bit =
        to_prefix ? absl::StrCat(klinux_prefix, "_", enum_pair.first)
                  : enum_pair.first;
    os << "  if ((input & " << input_bit << ") == " << input_bit << ") {\n"
       << "    output |= static_cast<" << enum_properties.data_type << ">("
       << output_bit << ");\n";
    // Mask off each handled bit so that we can later catch any unexpected bits.
    os << "    input &= ~" << input_bit << ";\n"
       << "  }\n";
    if (enum_properties.wrap_macros_with_if_defined) {
      os << "#endif\n";
    }
  }

  os << "  if (input != 0 && !ignore_unexpected_bits) return absl::nullopt;\n"
     << "  return output;\n";
  return os.str();
}

// Generate the function body for enum type conversions where the enums cannot
// be multi-valued. Uses an if condition based implementation to find the
// matching enum. A switch case should not be used here because enum values may
// be duplicate.
std::string GetIfBasedEnumBody(bool to_prefix, const std::string &enum_name,
                               const EnumProperties &enum_properties) {
  std::ostringstream os;

  for (const auto &enum_pair : enum_properties.values) {
    std::string input_val =
        to_prefix ? enum_pair.first
                  : absl::StrCat(klinux_prefix, "_", enum_pair.first);
    std::string output_val =
        to_prefix ? absl::StrCat(klinux_prefix, "_", enum_pair.first)
                  : enum_pair.first;

    if (enum_properties.wrap_macros_with_if_defined) {
      os << "#if defined(" << enum_pair.first << ")\n";
    }
    os << absl::StrReplaceAll(
        "  if (input == $input_val) return $output_val;\n",
        {{"$input_val", input_val}, {"$output_val", output_val}});
    if (enum_properties.wrap_macros_with_if_defined) {
      os << "#endif\n";
    }
  }

  // Generate code for handling default case.
  os << "  return absl::nullopt;\n";
  return os.str();
}

// Generate the function definition for struct type conversions. Depending on
// the value provided for |to_klinux|, this function generates the function
// definition for conversions to and from kernel struct types respectively.
std::string GetStructConversionsFuncBody(
    bool to_klinux, const std::string &input_struct,
    const std::string &output_struct,
    const StructProperties &struct_properties) {
  std::ostringstream os;
  os << "  if (!" << input_struct << " || !" << output_struct
     << ") return false;\n";

  for (const auto &member_pair : struct_properties.values) {
    std::string klinux_member =
        absl::StrCat(klinux_prefix, "_", member_pair.first);

    std::string output_member = to_klinux ? klinux_member : member_pair.first;
    std::string input_member = to_klinux ? member_pair.first : klinux_member;
    os << "  " << output_struct << "->" << output_member << " = "
       << input_struct << "->" << input_member << ";\n";
  }

  os << "\n";
  os << "  return true;\n";
  return os.str();
}

// Generate and write enum conversion function declarations and definitions to
// provided output streams for .h and .cc files.
void WriteEnumConversions(
    const std::map<std::string, EnumProperties> *enum_properties_table,
    std::ostream *os_h, std::ostream *os_cc) {
  for (const auto &it : *enum_properties_table) {
    if (it.second.skip_conversions) {
      continue;
    }

    std::string enum_name_lower = it.first;
    std::transform(enum_name_lower.begin(), enum_name_lower.end(),
                   enum_name_lower.begin(), ::tolower);

    const std::string return_data_type =
        absl::StrCat("absl::optional<", it.second.data_type, ">");

    absl::flat_hash_map<absl::string_view, absl::string_view> param_map = {
        {"$klinux_prefix", klinux_prefix},
        {"$enum_name", it.first},
        {"$data_type", it.second.data_type},
        {"$return_data_type", return_data_type}};

    const absl::string_view to_prefix_format =
        "$return_data_type "
        "To$klinux_prefix$enum_name($data_type input$optional_parameter)";
    const absl::string_view from_prefix_format =
        "$return_data_type "
        "From$klinux_prefix$enum_name($data_type input$optional_parameter)";

    // Write the function declarations to the header file.
    param_map["$optional_parameter"] =
        it.second.multi_valued ? ", bool ignore_unexpected_bits=false" : "";
    *os_h << "\n" << absl::StrReplaceAll(to_prefix_format, param_map) << "; \n";
    *os_h << "\n"
          << absl::StrReplaceAll(from_prefix_format, param_map) << "; \n";

    // Write the function body to the cc file.
    std::string to_body;
    std::string from_body;
    if (it.second.multi_valued) {
      to_body = GetOrBasedEnumBody(true, enum_name_lower, it.second);
      from_body = GetOrBasedEnumBody(false, enum_name_lower, it.second);
    } else {
      to_body = GetIfBasedEnumBody(true, enum_name_lower, it.second);
      from_body = GetIfBasedEnumBody(false, enum_name_lower, it.second);
    }

    param_map["$optional_parameter"] =
        it.second.multi_valued ? ", bool ignore_unexpected_bits" : "";
    *os_cc << "\n"
           << absl::StrReplaceAll(to_prefix_format, param_map) << " {\n"
           << to_body << "}\n";
    *os_cc << "\n"
           << absl::StrReplaceAll(from_prefix_format, param_map) << " {\n"
           << from_body << "}\n";
  }
}

// Generate and write struct conversion function declarations and definitions to
// provided output streams for .h and .cc files.
void WriteStructConversions(
    const std::map<std::string, StructProperties> *struct_properties_table,
    std::ostream *os_h, std::ostream *os_cc) {
  for (const auto &it : *struct_properties_table) {
    if (it.second.skip_conversions) {
      continue;
    }

    std::string struct_var = absl::StrCat("_", it.first);
    std::string klinux_struct_var =
        absl::StrCat("_", klinux_prefix, struct_var);

    std::string to_klinux_declaration = absl::StrReplaceAll(
        "bool To$klinux_prefix$name"
        "(const struct $name *$struct_var, "
        "struct $klinux_prefix_$name *$klinux_struct_var)",
        {{"$klinux_prefix", klinux_prefix},
         {"$name", it.first},
         {"$struct_var", struct_var},
         {"$klinux_struct_var", klinux_struct_var}});

    std::string from_klinux_declaration = absl::StrReplaceAll(
        "bool From$klinux_prefix$name(const struct "
        "$klinux_prefix_$name *$klinux_struct_var, struct $name *$struct_var)",
        {{"$klinux_prefix", klinux_prefix},
         {"$name", it.first},
         {"$struct_var", struct_var},
         {"$klinux_struct_var", klinux_struct_var}});

    // Write the function declarations to the header file.
    *os_h << "\n" << to_klinux_declaration << "; \n";
    *os_h << "\n" << from_klinux_declaration << "; \n";

    // Write the function body to the cc file.
    *os_cc << "\n"
           << to_klinux_declaration << " {\n"
           << GetStructConversionsFuncBody(true, struct_var, klinux_struct_var,
                                           it.second)
           << "}\n";
    *os_cc << "\n"
           << from_klinux_declaration << " {\n"
           << GetStructConversionsFuncBody(false, klinux_struct_var, struct_var,
                                           it.second)
           << "}\n";
  }
}

// Writes enum definitions obtained from |enum_properties_table| to an output
// stream provided.
void WriteEnumDefinitions(
    const std::map<std::string, EnumProperties> *enum_properties_table,
    std::ostream *os) {
  for (const auto &it : *enum_properties_table) {
    *os << absl::StreamFormat("\nenum %s : %s {\n", it.first,
                              it.second.data_type);

    // Accumulate comma separated resolved enum pairs (eg. kLinux_F_GETFD = 1,
    // kLinux_F_SETFD = 2,).
    for (const auto &current : it.second.values) {
      *os << absl::StreamFormat("  %s_%s = %d,\n", klinux_prefix, current.first,
                                current.second);
    }
    *os << "};\n";
  }
}

// Writes struct definitions obtained from |struct_properties_table| to an
// output stream provided.
void WriteStructDefinitions(
    const std::map<std::string, StructProperties> *struct_properties_table,
    std::ostream *os) {
  for (const auto &it : *struct_properties_table) {
    *os << absl::StreamFormat("\nstruct %s_%s {\n", klinux_prefix, it.first);

    for (const auto &current : it.second.values) {
      // Prefix |klinux_prefix| to each member name to avoid possible
      // collisions with macro names in enclave C library/host C library.
      *os << absl::StreamFormat("  %s %s_%s;\n", current.second, klinux_prefix,
                                current.first);
    }
    *os << "}" << (it.second.pack_attributes ? " ABSL_ATTRIBUTE_PACKED" : "")
        << ";\n";
  }
}

// Gets the mappings from type names to type properties and emits the C
// definitions for the types. Prefixes the appropriate klinux or klinux prefix
// to the type definitions generated. Currently supports enums and structs.
void WriteTypeDefinitions(
    const std::map<std::string, EnumProperties> *enum_properties_table,
    const std::map<std::string, StructProperties> *struct_properties_table,
    std::ostream *os) {
  // Write #ifdef guard
  std::string header_guard =
      "ASYLO_PLATFORM_SYSTEM_CALL_TYPE_CONVERSIONS_GENERATED_TYPES_"
      "H_";
  *os << "#ifndef " << header_guard << "\n"
      << "#define " << header_guard << "\n\n";

  // Write the includes. These may be needed when manually writing conversion
  // functions for certain automatically generated enums/structs (where
  // skip_conversions = true)
  WriteMacroProvidedIncludes(os);
  *os << "#include \"absl/base/attributes.h\""
      << "\n";

  WriteEnumDefinitions(enum_properties_table, os);
  WriteStructDefinitions(struct_properties_table, os);

  // End #ifdef guard
  *os << "\n#endif  // " << header_guard << "\n";
}

// Generates and writes the types conversion functions to the output streams
// provided. Writes the conversion function declarations to |os_h| and
// the corresponding implementations to |os_cc|. Currently supports enums and
// structs.
void WriteTypesConversions(
    std::map<std::string, EnumProperties> *enum_properties_table,
    std::map<std::string, StructProperties> *struct_properties_table,
    std::ostream *os_h, std::ostream *os_cc) {
  // Write #ifdef guard for .h file.
  std::string header_guard =
      "ASYLO_PLATFORM_SYSTEM_CALL_TYPE_CONVERSIONS_GENERATED_TYPES_"
      "FUNCTIONS_H_";
  *os_h << "#ifndef " << header_guard << "\n"
        << "#define " << header_guard << "\n\n";

  // Write all the includes.
  WriteMacroProvidedIncludes(os_h);
  *os_cc << "#include \"absl/types/optional.h\"\n"
         << "#include "
            "\"asylo/platform/system_call/type_conversions/"
            "generated_types_functions.h\"\n";
  *os_h << "#include \"absl/types/optional.h\"\n"
        << "#include "
           "\"asylo/platform/system_call/type_conversions/"
           "generated_types.h\"\n";

  WriteEnumConversions(enum_properties_table, os_h, os_cc);
  WriteStructConversions(struct_properties_table, os_h, os_cc);

  // End #ifdef guard for the header file.
  *os_h << "\n#endif  // " << header_guard << "\n";
}

int main(int argc, char **argv) {
  // Parse command-line arguments.
  absl::ParseCommandLine(argc, argv);

  CHECK(!absl::GetFlag(FLAGS_output_dir).empty())
      << "Must provide output dir path.";

  auto enum_properties_table = GetEnumPropertiesTable();
  auto struct_properties_table = GetStructPropertiesTable();
  std::ofstream types_h, types_functions_h, types_functions_cc;

  types_h.open(
      absl::StrCat(absl::GetFlag(FLAGS_output_dir), "/generated_types.h"));
  types_functions_h.open(absl::StrCat(absl::GetFlag(FLAGS_output_dir),
                                      "/generated_types_functions.h"));
  types_functions_cc.open(absl::StrCat(absl::GetFlag(FLAGS_output_dir),
                                       "/generated_types_functions.cc"));

  WriteTypeDefinitions(enum_properties_table, struct_properties_table,
                       &types_h);
  WriteTypesConversions(enum_properties_table, struct_properties_table,
                        &types_functions_h, &types_functions_cc);

  types_h.close();
  types_functions_h.close();
  types_functions_cc.close();

  return 0;
}

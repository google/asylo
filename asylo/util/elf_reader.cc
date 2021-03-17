/*
 *
 * Copyright 2018 Asylo authors
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

#include "asylo/util/elf_reader.h"

#include <cstring>

#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "absl/types/optional.h"
#include "asylo/util/status_macros.h"

namespace asylo {
namespace {

// Returns the subspan of |buffer| starting at |offset| and lasting for |size|
// bytes. If this subspan exceeds the boundary of |buffer|, then GetSubspan()
// returns nullopt.
absl::optional<absl::Span<const uint8_t>> GetSubspan(
    absl::Span<const uint8_t> buffer, size_t offset, size_t size) {
  if (offset + size > buffer.size()) {
    return absl::nullopt;
  }

  return buffer.subspan(offset, size);
}

// Returns a pointer to the memory at |offset| in |buffer| interpreted as an
// instance of type T. If the T instance would not lie entirely inside |buffer|,
// then GetSubspanAs() returns nullopt.
template <typename T>
absl::optional<const T *> GetSubspanAs(absl::Span<const uint8_t> buffer,
                                       size_t offset) {
  auto extent_or_none = GetSubspan(buffer, offset, sizeof(T));

  if (!extent_or_none.has_value()) {
    return absl::nullopt;
  }

  return reinterpret_cast<const T *>(extent_or_none.value().data());
}

// Returns a view of the string at |offset| in |buffer|. If |offset| is not a
// valid offset in |buffer|, then GetStringAtOffset() returns nullopt.
absl::optional<absl::string_view> GetStringAtOffset(
    absl::Span<const uint8_t> buffer, size_t offset) {
  if (offset > buffer.size()) {
    return absl::nullopt;
  }

  const char *c_string = reinterpret_cast<const char *>(&buffer[offset]);
  const size_t max_length = buffer.size() - offset;
  const size_t length = strnlen(c_string, max_length);

  return absl::string_view(c_string, length);
}

}  // namespace

// A helper class for creating ElfReaders. Isolates all of the validation and
// member mutation required to create a valid ElfReader.
class ElfReaderCreator {
 public:
  explicit ElfReaderCreator(absl::Span<const uint8_t> elf_file)
      : elf_file_(elf_file) {}

  // Returns an ElfReader for the passed file. Invalidates the
  // ElfReaderCreator.
  StatusOr<ElfReader> Create();

 private:
  // Initializes the section_headers_ and section_data_ members. Returns a
  // non-OK status if any of the section headers are invalid or unsupported.
  //
  // If InitializeSectionMaps() returns a non-OK status, then the
  // section_headers_ and section_data_ members are invalid.
  Status InitializeSectionMaps();

  // Returns a pointer to the file header, or an error if the file is invalid or
  // unsupported.
  StatusOr<const Elf64_Ehdr *> ElfHeader() const;

  // Returns the offset of the section header table in the file according to
  // |elf_header|, or an error if the file is invalid or unsupported.
  StatusOr<Elf64_Off> SectionTableStart(const Elf64_Ehdr *elf_header) const;

  // Returns the number of sections in the file according to |elf_header|, or an
  // error if the file is invalid or unsupported.
  StatusOr<uint16_t> NumSections(const Elf64_Ehdr *elf_header) const;

  // Returns the size of each entry in the section header table according to
  // |elf_header|, or an error if the file is invalid or unsupported.
  StatusOr<uint16_t> EntrySize(const Elf64_Ehdr *elf_header) const;

  // Returns the index of the section name string table section header in the
  // section header table according to |elf_header|, or an error if the file is
  // invalid or unsupported.
  StatusOr<uint16_t> NameTableIndex(const Elf64_Ehdr *elf_header) const;

  // Returns a view containing the section header table according to the inputs,
  // or an error if the file is invalid or unsupported.
  StatusOr<absl::Span<const uint8_t>> SectionHeaderTable(
      Elf64_Off section_table_start, uint16_t num_sections,
      uint16_t entry_size) const;

  // Returns the index of the section name string table section header in the
  // section header table according to the inputs, or an error if the file is
  // invalid or unsupported.
  StatusOr<const Elf64_Shdr *> NameTableHeader(
      absl::Span<const uint8_t> section_header_table, uint16_t entry_size,
      uint16_t name_table_index) const;

  // Returns a view containing the section name string table according to
  // |name_table_header|, or an error if the file is invalid or unsupported.
  StatusOr<absl::Span<const uint8_t>> NameTable(
      const Elf64_Shdr *name_table_header) const;

  // A view containing the file.
  absl::Span<const uint8_t> elf_file_;

  // A map from section names to section headers. Initialized by
  // InitializeSectionMaps().
  absl::flat_hash_map<std::string, const Elf64_Shdr *> section_headers_;

  // A map from section names to views of their data. Initialized by
  // InitializeSectionMaps().
  absl::flat_hash_map<std::string, absl::Span<const uint8_t>> section_data_;
};

StatusOr<ElfReader> ElfReader::CreateFromSpan(
    absl::Span<const uint8_t> elf_file) {
  return ElfReaderCreator(elf_file).Create();
}

StatusOr<absl::Span<const uint8_t>> ElfReader::GetSectionData(
    absl::string_view section_name) const {
  std::string section_name_string = std::string(section_name);
  auto section_header_lookup = section_headers_.find(section_name_string);

  if (section_header_lookup == section_headers_.cend()) {
    return Status(
        absl::StatusCode::kNotFound,
        absl::StrCat("File does not contain a section called ", section_name));
  }

  if (section_header_lookup->second->sh_type == SHT_NOBITS) {
    return Status(absl::StatusCode::kInvalidArgument,
                  absl::StrCat("Section ", section_name, " has no data"));
  }

  auto section_data_lookup = section_data_.find(section_name_string);
  if (section_data_lookup == section_data_.cend()) {
    return Status(absl::StatusCode::kInternal,
                  absl::StrCat("Could not locate data associated with section ",
                               section_name));
  }

  return section_data_lookup->second;
}

StatusOr<ElfReader> ElfReaderCreator::Create() {
  ASYLO_RETURN_IF_ERROR(InitializeSectionMaps());
  return ElfReader(elf_file_, std::move(section_headers_),
                   std::move(section_data_));
}

Status ElfReaderCreator::InitializeSectionMaps() {
  const Elf64_Ehdr *elf_header;

  ASYLO_ASSIGN_OR_RETURN(elf_header, ElfHeader());

  Elf64_Off section_table_start;
  uint16_t num_sections;
  uint16_t entry_size;
  uint16_t name_table_index;

  ASYLO_ASSIGN_OR_RETURN(section_table_start, SectionTableStart(elf_header));
  ASYLO_ASSIGN_OR_RETURN(num_sections, NumSections(elf_header));
  ASYLO_ASSIGN_OR_RETURN(entry_size, EntrySize(elf_header));
  ASYLO_ASSIGN_OR_RETURN(name_table_index, NameTableIndex(elf_header));

  absl::Span<const uint8_t> section_header_table;
  const Elf64_Shdr *name_table_header;

  ASYLO_ASSIGN_OR_RETURN(
      section_header_table,
      SectionHeaderTable(section_table_start, num_sections, entry_size));
  ASYLO_ASSIGN_OR_RETURN(
      name_table_header,
      NameTableHeader(section_header_table, entry_size, name_table_index));

  absl::Span<const uint8_t> name_table;

  ASYLO_ASSIGN_OR_RETURN(name_table, NameTable(name_table_header));

  // Add each section to the map(s) in the order they appear in the section
  // header table.
  for (uint16_t i = 0; i < num_sections; ++i) {
    const Elf64_Shdr *section_header = reinterpret_cast<const Elf64_Shdr *>(
        &section_header_table[i * entry_size]);

    // Retrieve the section name.
    const uint32_t name_index = section_header->sh_name;
    auto section_name_or_none = GetStringAtOffset(name_table, name_index);

    if (!section_name_or_none.has_value()) {
      return Status(absl::StatusCode::kInvalidArgument,
                    absl::StrCat("Malformed ELF file: section ", i,
                                 " has invalid sh_name"));
    }

    const absl::string_view section_name = section_name_or_none.value();

    // Insert the section header into the section headers map.
    auto header_insertion_result =
        section_headers_.insert({std::string(section_name), section_header});
    if (!header_insertion_result.second) {
      return Status(
          absl::StatusCode::kInvalidArgument,
          absl::StrCat("Malformed ELF file: duplicated section name: ",
                       section_name));
    }

    // Insert the section data into the section data map. Sections of type
    // SHT_NOBITS contain no data, so they do not get an entry in the section
    // data map.
    if (section_header->sh_type != SHT_NOBITS) {
      // Retrieve a view of the section data.
      const Elf64_Off section_start = section_header->sh_offset;
      const uint64_t section_size = section_header->sh_size;
      auto data_view_or_none =
          GetSubspan(elf_file_, section_start, section_size);

      if (!data_view_or_none.has_value()) {
        return Status(absl::StatusCode::kInvalidArgument,
                      absl::StrCat("Malformed ELF file: section ", section_name,
                                   " exceeds boundary of file"));
      }

      const absl::Span<const uint8_t> data_view = data_view_or_none.value();

      // Insert the section data into the map.
      auto data_insertion_result =
          section_data_.insert({std::string(section_name), data_view});
      if (!data_insertion_result.second) {
        return Status(absl::StatusCode::kInternal,
                      absl::StrCat("Failed to record data of section ",
                                   section_name, " in section data table"));
      }
    }
  }

  return absl::OkStatus();
}

StatusOr<const Elf64_Ehdr *> ElfReaderCreator::ElfHeader() const {
  auto elf_header_or_none = GetSubspanAs<Elf64_Ehdr>(elf_file_, 0);

  if (!elf_header_or_none.has_value()) {
    return Status(absl::StatusCode::kInvalidArgument,
                  "Unsupported file format: not a 64-bit ELF file");
  }

  const Elf64_Ehdr *elf_header = elf_header_or_none.value();

  if (elf_header->e_ident[EI_MAG0] != ELFMAG0 ||
      elf_header->e_ident[EI_MAG1] != ELFMAG1 ||
      elf_header->e_ident[EI_MAG2] != ELFMAG2 ||
      elf_header->e_ident[EI_MAG3] != ELFMAG3) {
    return Status(
        absl::StatusCode::kInvalidArgument,
        "Unsupported file format: file does not begin with ELF magic number");
  }

  if (elf_header->e_ident[EI_CLASS] != ELFCLASS64) {
    return Status(absl::StatusCode::kInvalidArgument,
                  "Unsupported file format: only 64-bit ELF is supported");
  }

  if (elf_header->e_ident[EI_DATA] != ELFDATA2LSB) {
    return Status(absl::StatusCode::kInvalidArgument,
                  "Unsupported file format: only little-endian ELF is "
                  "supported");
  }

  if (elf_header->e_ident[EI_VERSION] != EV_CURRENT ||
      elf_header->e_version != EV_CURRENT) {
    return Status(absl::StatusCode::kInvalidArgument,
                  "Unsupported file format: unknown ELF version");
  }

  return elf_header;
}

StatusOr<Elf64_Off> ElfReaderCreator::SectionTableStart(
    const Elf64_Ehdr *elf_header) const {
  if (elf_header->e_shoff == 0) {
    return Status(absl::StatusCode::kInvalidArgument,
                  "ELF file contains no section header table");
  }

  return elf_header->e_shoff;
}

StatusOr<uint16_t> ElfReaderCreator::NumSections(
    const Elf64_Ehdr *elf_header) const {
  // An e_shnum value of 0 may indicate that there are more than 65,279
  // sections, in which case the actual number of sections is located elsewhere.
  // However, ElfReader does not currently support this option.
  if (elf_header->e_shnum == 0) {
    return Status(
        absl::StatusCode::kInvalidArgument,
        "ELF file contains no section header table or has too many sections");
  }

  return elf_header->e_shnum;
}

StatusOr<uint16_t> ElfReaderCreator::EntrySize(
    const Elf64_Ehdr *elf_header) const {
  if (elf_header->e_shentsize < sizeof(Elf64_Shdr)) {
    return Status(absl::StatusCode::kInvalidArgument,
                  "Malformed ELF file: malformed section header size");
  }

  return elf_header->e_shentsize;
}

StatusOr<uint16_t> ElfReaderCreator::NameTableIndex(
    const Elf64_Ehdr *elf_header) const {
  if (elf_header->e_shstrndx == SHN_UNDEF) {
    return Status(absl::StatusCode::kInvalidArgument,
                  "ELF file contains no section name string table section");
  }

  return elf_header->e_shstrndx;
}

StatusOr<absl::Span<const uint8_t>> ElfReaderCreator::SectionHeaderTable(
    Elf64_Off section_table_start, uint16_t num_sections,
    uint16_t entry_size) const {
  auto section_header_table_or_none =
      GetSubspan(elf_file_, section_table_start, num_sections * entry_size);

  if (!section_header_table_or_none.has_value()) {
    return Status(
        absl::StatusCode::kInvalidArgument,
        "Malformed ELF file: section header table exceeds boundary of file");
  }

  return section_header_table_or_none.value();
}

StatusOr<const Elf64_Shdr *> ElfReaderCreator::NameTableHeader(
    absl::Span<const uint8_t> section_header_table, uint16_t entry_size,
    uint16_t name_table_index) const {
  auto name_table_header_or_none = GetSubspanAs<Elf64_Shdr>(
      section_header_table, name_table_index * entry_size);

  if (!name_table_header_or_none.has_value()) {
    return Status(absl::StatusCode::kInvalidArgument,
                  "Malformed ELF file: section name string table header "
                  "lies outside "
                  "section header table");
  }

  const Elf64_Shdr *name_table_header = name_table_header_or_none.value();

  if (name_table_header->sh_type != SHT_STRTAB) {
    return Status(absl::StatusCode::kInvalidArgument,
                  "Malformed ELF file: section name string table section "
                  "is not of type "
                  "SHT_STRTAB");
  }

  return name_table_header;
}

StatusOr<absl::Span<const uint8_t>> ElfReaderCreator::NameTable(
    const Elf64_Shdr *name_table_header) const {
  const Elf64_Off name_table_start = name_table_header->sh_offset;
  const uint64_t name_table_size = name_table_header->sh_size;
  auto name_table_or_none =
      GetSubspan(elf_file_, name_table_start, name_table_size);

  if (!name_table_or_none.has_value()) {
    return Status(absl::StatusCode::kInvalidArgument,
                  "Malformed ELF file: section name string table exceeds "
                  "boundary of "
                  "file");
  }

  return name_table_or_none.value();
}

}  // namespace asylo

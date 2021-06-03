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

#include <elf.h>

#include <cstring>
#include <limits>
#include <string>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "absl/flags/flag.h"
#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "absl/types/span.h"
#include "asylo/util/logging.h"
#include "asylo/test/util/status_matchers.h"
#include "asylo/util/file_mapping.h"

ABSL_FLAG(std::string, elf_file, "", "The ELF file to use for testing");
ABSL_FLAG(std::string, section_name, "",
          "The name of the section to use for testing");
ABSL_FLAG(std::string, expected_contents, "",
          "The expected contents of the test section");

namespace asylo {
namespace {

using ::testing::Not;

// A section name that is not used in absl::GetFlag(FLAGS_elf_file).
constexpr char kAbsentSectionName[] = "\r%";

class ElfReaderTest : public ::testing::Test {
 public:
  ElfReaderTest() : ElfReaderTest(ElfReaderTestMembers()) {}

 protected:
  struct ElfReaderTestMembers {
    FileMapping elf_file_mapping;
    Elf64_Ehdr *elf_header;
    Elf64_Shdr *name_table_header;
    absl::string_view name_table_name;
    uint16_t target_section_index;
    Elf64_Shdr *target_section_header;

    ElfReaderTestMembers() {
      // Load the ELF file from absl::GetFlag(FLAGS_elf_file).
      auto from_elf_file_result =
          FileMapping::CreateFromFile(absl::GetFlag(FLAGS_elf_file));
      CHECK(from_elf_file_result.ok());
      elf_file_mapping = std::move(from_elf_file_result.value());

      // Find the file's header.
      absl::Span<uint8_t> elf_file = elf_file_mapping.buffer();
      CHECK_GT(elf_file.size(), sizeof(Elf64_Ehdr));
      elf_header = reinterpret_cast<Elf64_Ehdr *>(elf_file.data());

      // Find the section header table.
      Elf64_Off section_header_table_start = elf_header->e_shoff;
      uint16_t num_sections = elf_header->e_shnum;
      uint64_t entry_size = elf_header->e_shentsize;
      Elf64_Off section_header_table_end =
          section_header_table_start + num_sections * entry_size;

      CHECK_LE(section_header_table_end, elf_file.size());

      // Find the section name string table.
      uint16_t name_table_index = elf_header->e_shstrndx;

      CHECK_LT(name_table_index, num_sections);

      name_table_header = reinterpret_cast<Elf64_Shdr *>(
          &elf_file[section_header_table_start +
                    name_table_index * entry_size]);
      Elf64_Off section_names_start = name_table_header->sh_offset;
      uint64_t section_names_size = name_table_header->sh_size;

      CHECK_LT(section_names_start + section_names_size, elf_file.size());

      // Find the name of the section name string table section.
      uint32_t name_table_name_index = name_table_header->sh_name;

      CHECK_LT(name_table_name_index, section_names_size);

      char *name_table_name_start = reinterpret_cast<char *>(
          &elf_file[section_names_start + name_table_name_index]);
      size_t name_table_name_length = strnlen(
          name_table_name_start, section_names_size - name_table_name_index);

      name_table_name =
          absl::string_view(name_table_name_start, name_table_name_length);

      // Find the section header of the desired section.
      for (uint16_t i = 0; i < num_sections; ++i) {
        // Find the name of section i.
        Elf64_Shdr *section_header = reinterpret_cast<Elf64_Shdr *>(
            &elf_file[section_header_table_start + i * entry_size]);
        uint32_t section_i_name_index = section_header->sh_name;

        CHECK_LE(section_i_name_index, section_names_size);

        char *section_i_name = reinterpret_cast<char *>(
            &elf_file[section_names_start + section_i_name_index]);

        // If the name matches absl::GetFlag(FLAGS_section_name), save its data.
        if (strncmp(section_i_name, absl::GetFlag(FLAGS_section_name).data(),
                    absl::GetFlag(FLAGS_section_name).size()) == 0 &&
            section_i_name[absl::GetFlag(FLAGS_section_name).size()] == '\0') {
          target_section_index = i;
          target_section_header = section_header;
          break;
        }
      }
    }
  };

  explicit ElfReaderTest(ElfReaderTestMembers members)
      : elf_file_mapping_(std::move(members.elf_file_mapping)),
        elf_header_(members.elf_header),
        name_table_header_(members.name_table_header),
        name_table_name_(members.name_table_name),
        target_section_index_(members.target_section_index),
        target_section_header_(members.target_section_header) {}

  // Checks that CreateFromSpan returns an INVALID_ARGUMENT error with the given
  // error message when asked to find the absl::GetFlag(FLAGS_section_name)
  // section in elf_file_mapping_.buffer().
  void ExpectBadReaderInput(absl::string_view error_message) {
    auto create_from_span_result =
        ElfReader::CreateFromSpan(elf_file_mapping_.buffer());
    EXPECT_THAT(create_from_span_result,
                StatusIs(absl::StatusCode::kInvalidArgument, error_message));
  }

  // The mapping of the ELF file.
  FileMapping elf_file_mapping_;

  // A pointer to the header of the ELF file.
  Elf64_Ehdr *const elf_header_;

  // A pointer to the section header of the section name string table section of
  // the ELF file.
  Elf64_Shdr *const name_table_header_;

  // The name of the section name string table section.
  const absl::string_view name_table_name_;

  // The index of the section header of the desired section in the section
  // header table.
  const uint16_t target_section_index_;

  // A pointer to the section header of the desired section in the ELF file.
  Elf64_Shdr *const target_section_header_;
};

// Tests that GetSectionData locates the desired section in a valid ELF file.
TEST_F(ElfReaderTest, WorksOnValidInputs) {
  auto from_data_file_result =
      FileMapping::CreateFromFile(absl::GetFlag(FLAGS_expected_contents));
  ASSERT_THAT(from_data_file_result, IsOk());
  FileMapping expected_contents_mapping =
      std::move(from_data_file_result.value());

  ASSERT_GE(elf_file_mapping_.buffer().size(), sizeof(Elf64_Ehdr));

  auto create_from_span_result =
      ElfReader::CreateFromSpan(elf_file_mapping_.buffer());
  EXPECT_THAT(create_from_span_result, IsOk());
  ElfReader reader = create_from_span_result.value();

  auto get_section_data_result =
      reader.GetSectionData(absl::GetFlag(FLAGS_section_name));
  EXPECT_THAT(get_section_data_result, IsOk());
  absl::Span<const uint8_t> section_data = get_section_data_result.value();

  EXPECT_EQ(section_data.size(), expected_contents_mapping.buffer().size());
  EXPECT_EQ(
      memcmp(section_data.data(), expected_contents_mapping.buffer().data(),
             expected_contents_mapping.buffer().size()),
      0);
}

// Tests that CreateFromSpan returns an appropriate error if the input file does
// not start with the ELF magic number.
TEST_F(ElfReaderTest, ReturnsAppropriateErrorIfBadMagicNumber) {
  elf_header_->e_ident[EI_MAG0] = ~ELFMAG0;

  ExpectBadReaderInput(
      "Unsupported file format: file does not begin with ELF magic number");
}

// Tests that CreateFromSpan returns an appropriate error if the input file is a
// 32-bit ELF file.
TEST_F(ElfReaderTest, ReturnsAppropriateErrorIf32BitElf) {
  elf_header_->e_ident[EI_CLASS] = ELFCLASS32;

  ExpectBadReaderInput("Unsupported file format: only 64-bit ELF is supported");
}

// Tests that CreateFromSpan returns an appropriate error if the input file is
// big endian.
TEST_F(ElfReaderTest, ReturnsAppropriateErrorIfBigEndian) {
  elf_header_->e_ident[EI_DATA] = ELFDATA2MSB;

  ExpectBadReaderInput(
      "Unsupported file format: only little-endian ELF is supported");
}

// Tests that CreateFromSpan returns an appropriate error if the input file uses
// an unsupported version of the ELF standard.
TEST_F(ElfReaderTest, ReturnsAppropriateErrorIfWrongVersion) {
  elf_header_->e_ident[EI_VERSION] = EV_NONE;

  ExpectBadReaderInput("Unsupported file format: unknown ELF version");
}

// Tests that CreateFromSpan returns an appropriate error if the input file has
// no section header table.
TEST_F(ElfReaderTest, ReturnsAppropriateErrorIfNoSectionHeaderTable) {
  elf_header_->e_shoff = 0;

  ExpectBadReaderInput("ELF file contains no section header table");
}

// Tests that CreateFromSpan returns an appropriate error if the input file has
// too many section.
TEST_F(ElfReaderTest, ReturnsAppropriateErrorIfTooManySections) {
  elf_header_->e_shnum = 0;

  ExpectBadReaderInput(
      "ELF file contains no section header table or has too many sections");
}

// Tests that CreateFromSpan returns an appropriate error if the input file has
// a nonsensical section header table entry size.
TEST_F(ElfReaderTest, ReturnsAppropriateErrorIfBadShentsize) {
  elf_header_->e_shentsize = 0;

  ExpectBadReaderInput("Malformed ELF file: malformed section header size");
}

// Tests that CreateFromSpan returns an appropriate error if the input file has
// no section name string table.
TEST_F(ElfReaderTest, ReturnsAppropriateErrorIfNoSectionNameStringTable) {
  elf_header_->e_shstrndx = SHN_UNDEF;

  ExpectBadReaderInput(
      "ELF file contains no section name string table section");
}

// Tests that CreateFromSpan returns an appropriate error if the input file has
// a section header table that extends outside the boundary of the file.
TEST_F(ElfReaderTest, ReturnsAppropriateErrorIfSectionHeaderTableOverflow) {
  elf_header_->e_shoff = std::numeric_limits<Elf64_Off>::max() / 2;

  ExpectBadReaderInput(
      "Malformed ELF file: section header table exceeds boundary of file");
}

// Tests that CreateFromSpan returns an appropriate error if the input file's
// section name string table index is invalid.
TEST_F(ElfReaderTest, ReturnsAppropriateErrorIfBadShstrndx) {
  elf_header_->e_shstrndx = elf_header_->e_shnum + 1;

  ExpectBadReaderInput(
      "Malformed ELF file: section name string table header lies outside "
      "section header table");
}

// Tests that CreateFromSpan returns an appropriate error if the input file's
// section name string table has an invalid type.
TEST_F(ElfReaderTest, ReturnsAppropriateErrorIfBadNameTableType) {
  name_table_header_->sh_type = SHT_PROGBITS;

  ExpectBadReaderInput(
      "Malformed ELF file: section name string table section is not of "
      "type "
      "SHT_STRTAB");
}

// Tests that CreateFromSpan returns an appropriate error if the input file's
// section name string table exceeds the boundary of the file.
TEST_F(ElfReaderTest, ReturnsAppropriateErrorIfNameTableTooBig) {
  name_table_header_->sh_offset = std::numeric_limits<Elf64_Off>::max() / 2;

  ExpectBadReaderInput(
      "Malformed ELF file: section name string table exceeds boundary of "
      "file");
}

// Tests that CreateFromSpan returns an appropriate error if a section name in
// the input file lies outside the section name string table.
TEST_F(ElfReaderTest, ReturnsAppropriateErrorIfSectionNameOutsideTable) {
  target_section_header_->sh_name = std::numeric_limits<uint32_t>::max() / 2;

  ExpectBadReaderInput(absl::StrCat("Malformed ELF file: section ",
                                    target_section_index_,
                                    " has invalid sh_name"));
}

// Tests that CreateFromSpan returns an appropriate error if two sections in the
// input file have the same name.
TEST_F(ElfReaderTest, ReturnsAppropriateErrorIfDuplicateSectionNames) {
  target_section_header_->sh_name = name_table_header_->sh_name;

  ExpectBadReaderInput(absl::StrCat(
      "Malformed ELF file: duplicated section name: ", name_table_name_));
}

// Tests that CreateFromSpan returns an appropriate error if a section in the
// input file exceeds the boundary of the file.
TEST_F(ElfReaderTest, ReturnsAppropriateErrorIfSectionTooBig) {
  target_section_header_->sh_offset = std::numeric_limits<Elf64_Off>::max() / 2;

  ExpectBadReaderInput(absl::StrCat("Malformed ELF file: section ",
                                    absl::GetFlag(FLAGS_section_name),
                                    " exceeds boundary of file"));
}

// Tests that GetSectionData returns an appropriate error if the requested
// section does not exist.
TEST_F(ElfReaderTest, ReturnsAppropriateErrorIfSectionNotFound) {
  auto create_from_span_result =
      ElfReader::CreateFromSpan(elf_file_mapping_.buffer());
  ASSERT_THAT(create_from_span_result, IsOk());
  ElfReader reader = create_from_span_result.value();

  auto get_section_data_result = reader.GetSectionData(kAbsentSectionName);
  EXPECT_THAT(get_section_data_result,
              StatusIs(absl::StatusCode::kNotFound,
                       absl::StrCat("File does not contain a section called ",
                                    kAbsentSectionName)));
}

// Tests that GetSectionData returns an appropriate error if the requested
// section has no associated data.
TEST_F(ElfReaderTest, ReturnsAppropriateErrorIfTargetSectionHasNoData) {
  target_section_header_->sh_type = SHT_NOBITS;

  auto create_from_span_result =
      ElfReader::CreateFromSpan(elf_file_mapping_.buffer());
  ASSERT_THAT(create_from_span_result, IsOk());
  ElfReader reader = create_from_span_result.value();

  auto get_section_data_result =
      reader.GetSectionData(absl::GetFlag(FLAGS_section_name));
  EXPECT_THAT(
      get_section_data_result,
      StatusIs(absl::StatusCode::kInvalidArgument,
               absl::StrCat("Section ", absl::GetFlag(FLAGS_section_name),
                            " has no data")));
}

// Tests that CreateFromSpan returns an appropriate error if the input file is
// smaller than the ELF section header structure.
TEST(ElfReaderFixturelessTest, ReturnsAppropriateErrorIfFileTooSmall) {
  uint8_t too_small_buffer[sizeof(Elf64_Ehdr) - 1];

  auto create_from_span_result = ElfReader::CreateFromSpan(
      absl::Span<uint8_t>(too_small_buffer, sizeof(too_small_buffer)));
  EXPECT_THAT(create_from_span_result,
              StatusIs(absl::StatusCode::kInvalidArgument,
                       "Unsupported file format: not a 64-bit ELF file"));
}

}  // namespace
}  // namespace asylo

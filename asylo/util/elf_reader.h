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

#ifndef ASYLO_UTIL_ELF_READER_H_
#define ASYLO_UTIL_ELF_READER_H_

#include <elf.h>
#include <cstdint>
#include <string>
#include <utility>

#include "absl/container/flat_hash_map.h"
#include "absl/strings/string_view.h"
#include "absl/types/span.h"
#include "asylo/util/statusor.h"

namespace asylo {

// A class for reading ELF files. Only supports 64-bit little-endian ELF files.
class ElfReader {
 public:
  // Constructs an ElfReader from an ELF file in a buffer in memory. The
  // lifetime of the buffer must not be shorter than the lifetime of the
  // ElfReader.
  //
  // If the underlying buffer is modified after the ElfReader is constructed,
  // there is no guarantee that ElfReader remains valid.
  static StatusOr<ElfReader> CreateFromSpan(absl::Span<const uint8_t> elf_file);

  ElfReader() = default;

  ElfReader(const ElfReader &other) = default;
  ElfReader &operator=(const ElfReader &other) = default;

  // Returns a view into the given ELF file containing the contents of the
  // section |section_name|.
  StatusOr<absl::Span<const uint8_t>> GetSectionData(
      absl::string_view section_name) const;

 private:
  // This class is defined in elf_reader.cc.
  friend class ElfReaderCreator;

  ElfReader(
      absl::Span<const uint8_t> elf_file,
      absl::flat_hash_map<std::string, const Elf64_Shdr *> &&section_headers,
      absl::flat_hash_map<std::string, absl::Span<const uint8_t>>
          &&section_data)
      : elf_file_(elf_file),
        section_headers_(std::move(section_headers)),
        section_data_(std::move(section_data)) {}

  // A view containing the file.
  absl::Span<const uint8_t> elf_file_;

  // A map from section names to section headers.
  absl::flat_hash_map<std::string, const Elf64_Shdr *> section_headers_;

  // A map from section names to views of their data.
  absl::flat_hash_map<std::string, absl::Span<const uint8_t>> section_data_;
};

}  // namespace asylo

#endif  // ASYLO_UTIL_ELF_READER_H_

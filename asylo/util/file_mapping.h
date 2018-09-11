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

#ifndef ASYLO_UTIL_FILE_MAPPING_H_
#define ASYLO_UTIL_FILE_MAPPING_H_

#include <cstdint>

#include "absl/strings/string_view.h"
#include "absl/types/span.h"
#include "asylo/util/statusor.h"

namespace asylo {

// An RAII object that owns a mapping of a file into memory.
//
// The mapping has copy-on-write semantics: any writes to the associated region
// of memory are not propagated to the backing file.
class FileMapping {
 public:
  // Returns a new FileMapping of |file_name| into memory, or a non-OK status if
  // the mapping workflow fails.
  static StatusOr<FileMapping> CreateFromFile(absl::string_view file_name);

  FileMapping() = default;

  FileMapping(const FileMapping &other) = delete;
  FileMapping &operator=(const FileMapping &other) = delete;

  FileMapping(FileMapping &&other) { MoveFrom(&other); }
  FileMapping &operator=(FileMapping &&other) {
    MoveFrom(&other);
    return *this;
  }

  ~FileMapping();

  // Returns the buffer that the specified file is mapped into.
  absl::Span<uint8_t> buffer() const { return mapped_region_; }

 private:
  // A constructor used by CreateFromFile when no errors are encountered.
  FileMapping(std::string &&file_name, absl::Span<uint8_t> mapped_region)
      : file_name_(std::move(file_name)), mapped_region_(mapped_region) {}

  // A utility function to eliminate code duplication between the move
  // constructor and move assignment operators.
  void MoveFrom(FileMapping *other);

  // The name of the file being mapped.
  std::string file_name_;

  // The buffer that the file is mapped into.
  absl::Span<uint8_t> mapped_region_;
};

}  // namespace asylo

#endif  // ASYLO_UTIL_FILE_MAPPING_H_

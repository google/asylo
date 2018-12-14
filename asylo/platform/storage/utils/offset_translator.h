/*
 *
 * Copyright 2017 Asylo authors
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

#ifndef ASYLO_PLATFORM_STORAGE_UTILS_OFFSET_TRANSLATOR_H_
#define ASYLO_PLATFORM_STORAGE_UTILS_OFFSET_TRANSLATOR_H_

#include <sys/types.h>
#include <memory>

namespace asylo {
namespace platform {
namespace storage {

// Class exposes interface to facilitate translating between "physical" offset
// in a secure file where file data is interlaced with file metadata, and the
// "logical" offset in the file's view that does not include file metadata.
//
// The mapping between "physical" and "logical" offsets is based on the
// following data and metadata layout in the file:
// <header> | <block 0 payload> | <block 0 metadata> | <block 1 payload> | ...
// Here block N payload and block N metadata compose a full block, and the
// header contains metadata that is not specific to any block and describes the
// file as a whole - this may include digest of the file data, etc.
//
// The physical offset evaluated by this class never falls into metadata
// regions. Metadata regions are considered right-open in offset-increasing
// direction.
class OffsetTranslator {
 public:
  // Represents an invalid offset.
  static constexpr off_t kInvalidOffset = -1;

  static std::unique_ptr<OffsetTranslator> Create(size_t header_len,
                                                  size_t payload_len,
                                                  size_t block_len);

  // Converts the file's physical offset to its logical view exposed to the
  // client of the secure storage API. Returned kInvalidOffset indicates a
  // failure.
  off_t PhysicalToLogical(off_t offset) const;

  // Converts the file's logical offset exposed to the client of the secure
  // storage API to the corresponding physical offset in the file with metadata.
  // Returned kInvalidOffset indicates a failure.
  off_t LogicalToPhysical(off_t offset) const;

  // Given the logical offset and the total count of bytes in a range,
  // calculates the count of bytes in partial blocks, and the total count of
  // bytes in the full inclusive blocks. Expects non-negative |logical_offset|.
  void ReduceLogicalRangeToFullLogicalBlocks(
      off_t logical_offset, size_t count,
      size_t *first_partial_block_bytes_count,
      size_t *last_partial_block_bytes_count,
      size_t *full_inclusive_blocks_bytes_count);

 private:
  OffsetTranslator(size_t header_len, size_t payload_len, size_t block_len);
  const size_t header_length_;
  const size_t payload_length_;
  const size_t block_length_;
};

}  // namespace storage
}  // namespace platform
}  // namespace asylo

#endif  // ASYLO_PLATFORM_STORAGE_UTILS_OFFSET_TRANSLATOR_H_

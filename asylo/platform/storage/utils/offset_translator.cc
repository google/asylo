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

// Implementation for the OffsetTranslator class.

#include "asylo/platform/storage/utils/offset_translator.h"

#include <sys/types.h>

#include "absl/memory/memory.h"

namespace asylo {
namespace platform {
namespace storage {

std::unique_ptr<OffsetTranslator> OffsetTranslator::Create(size_t header_len,
                                                           size_t payload_len,
                                                           size_t block_len) {
  // Ensure the layout is not degenerate - header, payload, and metadata at the
  // end of the block are all non-empty.
  if (header_len == 0 || payload_len == 0 || block_len == 0 ||
      payload_len >= block_len) {
    return nullptr;
  }

  return absl::WrapUnique<OffsetTranslator>(
      new OffsetTranslator(header_len, payload_len, block_len));
}

OffsetTranslator::OffsetTranslator(size_t header_len, size_t payload_len,
                                   size_t block_len)
    : header_length_(header_len),
      payload_length_(payload_len),
      block_length_(block_len) {}

off_t OffsetTranslator::PhysicalToLogical(off_t offset) const {
  off_t header_length_offset = header_length_;
  if (offset < header_length_offset) {
    return kInvalidOffset;
  }

  off_t tail = (offset - header_length_) % block_length_;
  if (tail >= payload_length_) {
    return kInvalidOffset;
  }

  return ((offset - header_length_) / block_length_) * payload_length_ + tail;
}

off_t OffsetTranslator::LogicalToPhysical(off_t offset) const {
  if (offset < 0) {
    return kInvalidOffset;
  }

  return header_length_ + (offset / payload_length_) * block_length_ +
         offset % payload_length_;
}

void OffsetTranslator::ReduceLogicalRangeToFullLogicalBlocks(
    off_t logical_offset, size_t count, size_t *first_partial_block_bytes_count,
    size_t *last_partial_block_bytes_count,
    size_t *full_inclusive_blocks_bytes_count) {
  off_t in_block_offset = logical_offset % payload_length_;
  *first_partial_block_bytes_count =
      (in_block_offset > 0) ? (payload_length_ - in_block_offset) : 0;
  *last_partial_block_bytes_count = 0;
  size_t full_blocks_bytes_count = 0;
  if (*first_partial_block_bytes_count >= count) {
    *first_partial_block_bytes_count = count;
  } else {
    *last_partial_block_bytes_count =
        (count - *first_partial_block_bytes_count) % payload_length_;
    full_blocks_bytes_count = count - *first_partial_block_bytes_count -
                              *last_partial_block_bytes_count;
  }
  *full_inclusive_blocks_bytes_count = full_blocks_bytes_count;
  if (*first_partial_block_bytes_count > 0) {
    *full_inclusive_blocks_bytes_count += payload_length_;
  }
  if (*last_partial_block_bytes_count > 0) {
    *full_inclusive_blocks_bytes_count += payload_length_;
  }
}

}  // namespace storage
}  // namespace platform
}  // namespace asylo

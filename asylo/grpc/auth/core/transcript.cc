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

#include "asylo/grpc/auth/core/transcript.h"

#include <cstdint>
#include <string>
#include <vector>

#include <google/protobuf/io/zero_copy_stream.h>
#include "asylo/crypto/hash_interface.h"
#include "asylo/crypto/util/byte_container_util.h"
#include "asylo/util/status.h"

namespace asylo {

void Transcript::Add(google::protobuf::io::ZeroCopyInputStream *input) {
  const void *buffer;
  int size;
  while (input->Next(&buffer, &size)) {
    Add(buffer, size);
  }
}

bool Transcript::SetHasher(HashInterface *hasher) {
  if (hasher_) {
    return false;
  }
  hasher_.reset(hasher);
  hasher_->Init();
  hasher_->Update(bytes_to_hash_);
  bytes_to_hash_.clear();
  return true;
}

bool Transcript::Hash(std::string *digest) {
  if (!hasher_) {
    return false;
  }
  std::vector<uint8_t> tmp_digest;
  Status status = hasher_->CumulativeHash(&tmp_digest);
  if (!status.ok()) {
    LOG(ERROR) << "Error while generating transcript hash: " << status;
    return false;
  }
  *digest = CopyToByteContainer<std::string>(tmp_digest);
  return true;
}

void Transcript::Add(const void *data, size_t len) {
  if (hasher_) {
    // Append to the hash function context.
    hasher_->Update({data, len});
  } else {
    // Append to the internal buffer.
    bytes_to_hash_.append(reinterpret_cast<const char *>(data), len);
  }
}

}  // namespace asylo

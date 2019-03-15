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

#ifndef ASYLO_PLATFORM_STORAGE_SECURE_CTMMT_AUTHENTICATED_DICTIONARY_H_
#define ASYLO_PLATFORM_STORAGE_SECURE_CTMMT_AUTHENTICATED_DICTIONARY_H_

#include "absl/memory/memory.h"
#include "asylo/platform/storage/secure/authenticated_dictionary.h"
#include <merkletree/merkle_tree.h>

namespace asylo {
namespace platform {
namespace storage {

// Authenticated Dictionary implementation backed by Certificate Transparency
// Mutable Merkle Tree.
class CTMMTAuthenticatedDictionary : public AuthenticatedDictionary {
 public:
  CTMMTAuthenticatedDictionary()
      : mtree_(absl::make_unique<MutableMerkleTree>(
            absl::make_unique<Sha256Hasher>())) {}

  size_t LeafCount() const final { return mtree_->LeafCount(); }

  size_t AddLeaf(const std::string &data) final {
    return mtree_->AddLeaf(data);
  }

  size_t AddLeafHash(const std::string &hash) final {
    return mtree_->AddLeafHash(hash);
  }

  std::string CurrentRoot() final { return mtree_->CurrentRoot(); }

  std::string LeafHash(size_t leaf) const final {
    return mtree_->LeafHash(leaf);
  }

  std::string LeafHash(const std::string &data) const final {
    return mtree_->LeafHash(data);
  }

  bool UpdateLeaf(size_t leaf, const std::string &data) final;

 private:
  std::unique_ptr<MutableMerkleTree> mtree_;
};

}  // namespace storage
}  // namespace platform
}  // namespace asylo

#endif  // ASYLO_PLATFORM_STORAGE_SECURE_CTMMT_AUTHENTICATED_DICTIONARY_H_

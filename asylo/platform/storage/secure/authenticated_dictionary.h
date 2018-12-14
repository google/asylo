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

#ifndef ASYLO_PLATFORM_STORAGE_SECURE_AUTHENTICATED_DICTIONARY_H_
#define ASYLO_PLATFORM_STORAGE_SECURE_AUTHENTICATED_DICTIONARY_H_

#include <string>

namespace asylo {
namespace platform {
namespace storage {

// Generic abstract interface for operating on an Authenticated Dictionary. An
// Authenticated Dictionary for a data set divided into blocks is a data
// structure that holds block hashes, maintains block hashes on block
// modifications, and allows to efficiently calculate a "digest" (authentication
// tag) of the data set based on the hashes of all blocks in the data set.
class AuthenticatedDictionary {
 public:
  virtual ~AuthenticatedDictionary() = default;

  // Returns number of leaves in the tree.
  virtual size_t LeafCount() const = 0;

  // Adds a new leaf to the tree. Returns the position of the leaf in the tree.
  // Since indexing starts from 1, the returned value is the number of leaves in
  // the tree after the new leaf has been added.
  virtual size_t AddLeaf(const std::string &data) = 0;

  // Add a new leaf to the tree. It is the caller's responsibility to ensure
  // that the hash is correct. Returns the position of the leaf in the tree.
  // Since indexing starts from 1, the returned value is the number of leaves in
  // the tree after the new leaf has been added.
  virtual size_t AddLeafHash(const std::string &hash) = 0;

  // Updates and returns the current root of the tree. Returns the hash of an
  // empty string if the tree is empty.
  virtual std::string CurrentRoot() = 0;

  // Returns the |leaf|th leaf hash in the tree. Indexing starts from 1.
  virtual std::string LeafHash(size_t leaf) const = 0;

  // Returns the hash that the given data would have as a leaf.
  virtual std::string LeafHash(const std::string &data) const = 0;

  // Updates the |leaf|th leaf in the tree. Indexing starts from 1. Returns
  // false if update fails.
  virtual bool UpdateLeaf(size_t leaf, const std::string &data) = 0;
};

}  // namespace storage
}  // namespace platform
}  // namespace asylo

#endif  // ASYLO_PLATFORM_STORAGE_SECURE_AUTHENTICATED_DICTIONARY_H_

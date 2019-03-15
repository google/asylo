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

#include "asylo/platform/storage/secure/ctmmt_authenticated_dictionary.h"

#include "absl/memory/memory.h"
#include <merkletree/merkle_tree.h>

namespace asylo {
namespace platform {
namespace storage {

bool CTMMTAuthenticatedDictionary::UpdateLeaf(size_t leaf,
                                              const std::string &data) {
  return mtree_->UpdateLeafHash(leaf, mtree_->LeafHash(data));
}

}  // namespace storage
}  // namespace platform
}  // namespace asylo

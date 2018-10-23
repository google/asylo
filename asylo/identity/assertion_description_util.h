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

#ifndef ASYLO_IDENTITY_ASSERTION_DESCRIPTION_UTIL_H_
#define ASYLO_IDENTITY_ASSERTION_DESCRIPTION_UTIL_H_

#include <string>

#include "absl/container/flat_hash_set.h"
#include "asylo/identity/identity.pb.h"
#include "asylo/util/statusor.h"

namespace asylo {

// Hash-computing functor. This functor can be passed as the hash-functor
// template parameter to hash-based containers that store AssertionDescription
// protos.
struct AssertionDescriptionHasher {
  size_t operator()(const AssertionDescription &description) const;
};

// Equality-checking functor. This functor can be passed as the
// equality-checking-functor template parameter to hash-based containers that
// store AssertionDescription protos.
struct AssertionDescriptionEq {
  bool operator()(const AssertionDescription &lhs,
                  const AssertionDescription &rhs) const;
};

// Serializes the assertion description |description| to a string. The
// serialization is guaranteed to be deterministic and unique.
StatusOr<std::string> SerializeAssertionDescription(
    const AssertionDescription &description);

using AssertionDescriptionHashSet =
    absl::flat_hash_set<AssertionDescription, AssertionDescriptionHasher,
                        AssertionDescriptionEq>;

}  // namespace asylo

#endif  // ASYLO_IDENTITY_ASSERTION_DESCRIPTION_UTIL_H_

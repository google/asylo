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

#ifndef ASYLO_CRYPTO_HASH_INTERFACE_H_
#define ASYLO_CRYPTO_HASH_INTERFACE_H_

#include <cstdint>
#include <cstdlib>
#include <vector>

#include "asylo/crypto/algorithms.pb.h"  // IWYU pragma: export
#include "asylo/crypto/util/byte_container_view.h"
#include "asylo/util/status.h"

namespace asylo {

// HashInterface defines an interface for hash functions.
//
// Data may be added to an instance of HashInterface via the Update() method at
// any point during the object's lifetime. A user may call the CumulativeHash()
// method to get a hash of all data added to the object since its creation or
// last call to its Init() method.
//
// Implementations of this interface need not be thread-safe.
class HashInterface {
 public:
  HashInterface(const HashInterface &) = delete;
  HashInterface &operator=(const HashInterface &) = delete;
  HashInterface() = default;
  virtual ~HashInterface() = default;

  // Returns the hash algorithm implemented by this object.
  virtual HashAlgorithm GetHashAlgorithm() const = 0;

  // Returns the size of the message-digest of this hash algorithm. A return
  // value of zero indicates that the object does not implement a fixed-size
  // hash function.
  virtual size_t DigestSize() const = 0;

  // Initializes this hash object to a clean state. Calling this method clears
  // the effects of all previous Update() operations. Note that a newly
  // constructed hash object is always expected to be in a clean state and users
  // are not required to call Init() on such objects.
  virtual void Init() = 0;

  // Updates this hash object by adding the contents of |data|.
  virtual void Update(ByteContainerView data) = 0;

  // Computes the hash of the data added so far and writes it to |digest|.
  // Returns a non-OK status on error.
  //
  // Note that the internal state of the object remains unchanged, and the
  // object can continue to accumulate additional data via Update() operations.
  virtual Status CumulativeHash(std::vector<uint8_t> *digest) const = 0;
};

}  // namespace asylo

#endif  // ASYLO_CRYPTO_HASH_INTERFACE_H_

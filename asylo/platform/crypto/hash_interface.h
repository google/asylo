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

#ifndef ASYLO_PLATFORM_CRYPTO_HASH_INTERFACE_H_
#define ASYLO_PLATFORM_CRYPTO_HASH_INTERFACE_H_

#include <cstdint>
#include <cstdlib>
#include <string>

namespace asylo {

// HashInterface defines an interface for hash functions.
//
// Data may be added to an instance of HashInterface via the Update method at
// any point during the object's lifetime. A user may call the Hash method to
// get a hash of all data added to the object since its creation.
//
// Implementations of this interface need not be thread-safe.
class HashInterface {
 public:
  HashInterface(const HashInterface &) = delete;
  HashInterface &operator=(const HashInterface &) = delete;
  HashInterface() = default;
  virtual ~HashInterface() {}

  // Updates this hash object by adding |len| bytes from |data|.
  virtual void Update(const void *data, size_t len) = 0;

  // Returns a string containing the current hash.
  virtual std::string Hash() = 0;
};

}  // namespace asylo

#endif  // ASYLO_PLATFORM_CRYPTO_HASH_INTERFACE_H_

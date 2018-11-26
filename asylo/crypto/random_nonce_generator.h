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

#ifndef ASYLO_CRYPTO_RANDOM_NONCE_GENERATOR_H_
#define ASYLO_CRYPTO_RANDOM_NONCE_GENERATOR_H_

#include <cstdint>
#include <memory>

#include "absl/types/span.h"
#include "asylo/crypto/nonce_generator_interface.h"
#include "asylo/util/status.h"

namespace asylo {

// RandomNonceGenerator generates nonces whose size is configured at
// construction. The generated nonces are uniformly distributed over the set of
// all nonces of the chosen size.
class RandomNonceGenerator : public NonceGeneratorInterface {
 public:
  // Creates a NonceGenerator compliant with the standard for AES-GCM nonces.
  static std::unique_ptr<RandomNonceGenerator> CreateAesGcmNonceGenerator();

  // From NonceGeneratorInterface.

  size_t NonceSize() const override;

  Status NextNonce(absl::Span<uint8_t> nonce) override;

 private:
  // Creates a RandomNonceGenerator that creates nonces of size |size|.
  RandomNonceGenerator(size_t size);

  // The size of the nonces created by this object.
  const size_t nonce_size_;
};

}  // namespace asylo

#endif  // ASYLO_CRYPTO_RANDOM_NONCE_GENERATOR_H_

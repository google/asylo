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

#ifndef ASYLO_CRYPTO_SIGNING_KEY_H_
#define ASYLO_CRYPTO_SIGNING_KEY_H_

#include <cstdint>

#include "asylo/crypto/algorithms.pb.h"
#include "asylo/crypto/util/byte_container_view.h"
#include "asylo/util/status.h"
#include "asylo/util/statusor.h"

namespace asylo {

// VerifyingKey abstracts a verifying key from an asymmetric key-pair.
class VerifyingKey {
 public:
  virtual ~VerifyingKey() = default;

  // Returns the signature scheme used by this VerifyingKey.
  virtual SignatureScheme GetSignatureScheme() const = 0;

  // Verifies that |signature| is a valid signature over a hash of |message|
  // produced by the underlying hash function. Returns true if verification
  // succeeds, and false if verification failed or an error occurred during
  // verification.
  virtual Status Verify(ByteContainerView message,
                        ByteContainerView signature) const = 0;
};

// SigningKey abstracts a signing key from an asymmetric key-pair.
class SigningKey {
 public:
  virtual ~SigningKey() = default;

  // Returns the signature scheme used by this SigningKey.
  virtual SignatureScheme GetSignatureScheme() const = 0;

  // Returns a VerifyingKey that can verify signatures produced by this
  // SigningKey.
  virtual StatusOr<std::unique_ptr<VerifyingKey>> GetVerifyingKey() const = 0;

  // Signs a hash of the given |message| produced by the underlying hash
  // function, and places the resulting signature in |signature|. Returns a
  // non-OK Status if the signing operation failed.
  virtual Status Sign(ByteContainerView message,
                      std::vector<uint8_t> *signature) const = 0;
};

}  // namespace asylo

#endif  // ASYLO_CRYPTO_SIGNING_KEY_H_

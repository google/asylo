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

#ifndef ASYLO_CRYPTO_AEAD_TEST_VECTOR_H_
#define ASYLO_CRYPTO_AEAD_TEST_VECTOR_H_

#include <string>

#include "absl/strings/string_view.h"
#include "asylo/util/cleansing_types.h"

namespace asylo {

// A vector that includes all relevant information for testing an AEAD
// implementation - the plaintext, the key, the associated data, the nonce, and
// the authenticated ciphertext.
struct AeadTestVector {
  AeadTestVector() = default;

  // All passed parameters are hex-encoded. They are transformed to byte strings
  // before being stored. In addition, |ciphertext_hex| and |tag_hex| are first
  // concatenated to be stored as the authenticated ciphertext.
  AeadTestVector(absl::string_view plaintext_hex, absl::string_view key_hex,
                 absl::string_view aad_hex, absl::string_view nonce_hex,
                 absl::string_view ciphertext_hex, absl::string_view tag_hex);

  std::string aad;
  std::string unauthenticated_ciphertext;
  std::string authenticated_ciphertext;
  CleansingVector<uint8_t> key;
  std::string nonce;
  CleansingVector<uint8_t> plaintext;
};

}  // namespace asylo

#endif  // ASYLO_CRYPTO_AEAD_TEST_VECTOR_H_

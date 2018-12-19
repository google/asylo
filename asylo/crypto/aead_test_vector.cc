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

#include "asylo/crypto/aead_test_vector.h"

#include "absl/strings/escaping.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "asylo/util/cleansing_types.h"

namespace asylo {
namespace {

// Creates a CleansingVector of bytes from a hex string.
// Precondition: |hex_string| is a valid hex representation.
CleansingVector<uint8_t> CreateCleansingVectorFromHexString(
    absl::string_view hex_string) {
  std::string str = absl::HexStringToBytes(hex_string);
  return CleansingVector<uint8_t>(str.cbegin(), str.cend());
}

}  // namespace

AeadTestVector::AeadTestVector(absl::string_view plaintext_hex,
                               absl::string_view key_hex,
                               absl::string_view aad_hex,
                               absl::string_view nonce_hex,
                               absl::string_view ciphertext_hex,
                               absl::string_view tag_hex)
    : aad(absl::HexStringToBytes(aad_hex)),
      unauthenticated_ciphertext(absl::HexStringToBytes(ciphertext_hex)),
      authenticated_ciphertext(
          absl::HexStringToBytes(absl::StrCat(ciphertext_hex, tag_hex))),
      key(CreateCleansingVectorFromHexString(key_hex)),
      nonce(absl::HexStringToBytes(nonce_hex)),
      plaintext(CreateCleansingVectorFromHexString(plaintext_hex)) {}

}  // namespace asylo

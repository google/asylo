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

#include "asylo/crypto/aes_gcm_siv.h"

#include <openssl/rand.h>
#include <string>

#include "absl/strings/str_cat.h"
#include "asylo/crypto/util/bssl_util.h"
#include "asylo/util/status.h"

namespace asylo {

Status AesGcmSivNonceGenerator::NextNonce(
    const std::vector<uint8_t> &key_id,
    AesGcmSivNonceGenerator::AesGcmSivNonce *nonce) {
  if (RAND_bytes(nonce->data(), nonce->size()) != 1) {
    return Status(error::GoogleError::INTERNAL,
                  absl::StrCat("RAND_bytes failed", BsslLastErrorString()));
  }
  return Status::OkStatus();
}

}  // namespace asylo

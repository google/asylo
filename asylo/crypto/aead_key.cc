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

#include "asylo/crypto/aead_key.h"

#include <openssl/aead.h>

#include <memory>

#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "asylo/crypto/algorithms.pb.h"
#include "asylo/crypto/util/bssl_util.h"
#include "asylo/util/cleanup.h"
#include "asylo/util/status_macros.h"

namespace asylo {
namespace {

constexpr size_t kAes128KeySize = 16;
constexpr size_t kAes256KeySize = 32;

// Returns the appropriate EVP_AEAD based on |aead_scheme|.
const EVP_AEAD *GetEvpAead(AeadScheme aead_scheme) {
  switch (aead_scheme) {
    case AES128_GCM:
      return EVP_aead_aes_128_gcm();
    case AES256_GCM:
      return EVP_aead_aes_256_gcm();
    case AES128_GCM_SIV:
      return EVP_aead_aes_128_gcm_siv();
    case AES256_GCM_SIV:
      return EVP_aead_aes_256_gcm_siv();
    case UNKNOWN_AEAD_SCHEME:
    default:
      return nullptr;
  }
}

// Returns the appropriate AeadScheme for AES-GCM based on |key_size|.
AeadScheme GetAesGcmAeadScheme(size_t key_size) {
  if (key_size == kAes128KeySize) {
    return AES128_GCM;
  } else if (key_size == kAes256KeySize) {
    return AES256_GCM;
  }
  return UNKNOWN_AEAD_SCHEME;
}

// Returns the appropriate AeadScheme for AES-GCM-SIV based on |key_size|.
AeadScheme GetAesGcmSivAeadScheme(size_t key_size) {
  if (key_size == kAes128KeySize) {
    return AES128_GCM_SIV;
  } else if (key_size == kAes256KeySize) {
    return AES256_GCM_SIV;
  }
  return UNKNOWN_AEAD_SCHEME;
}

}  // namespace

StatusOr<std::unique_ptr<AeadKey>> AeadKey::CreateAesGcmKey(
    ByteContainerView key) {
  AeadScheme scheme = GetAesGcmAeadScheme(key.size());
  if (scheme == UNKNOWN_AEAD_SCHEME) {
    return Status(absl::StatusCode::kInvalidArgument,
                  absl::StrCat("Invalid AES-GCM key length: ", key.size(),
                               " (must be 16 or 32 bytes)"));
  }
  return absl::WrapUnique<AeadKey>(new AeadKey(scheme, key));
}

StatusOr<std::unique_ptr<AeadKey>> AeadKey::CreateAesGcmSivKey(
    ByteContainerView key) {
  AeadScheme scheme = GetAesGcmSivAeadScheme(key.size());
  if (scheme == UNKNOWN_AEAD_SCHEME) {
    return Status(absl::StatusCode::kInvalidArgument,
                  absl::StrCat("Invalid AES-GCM-SIV key length: ", key.size(),
                               " (must be 16 or 32 bytes)"));
  }
  return absl::WrapUnique<AeadKey>(new AeadKey(scheme, key));
}

AeadScheme AeadKey::GetAeadScheme() const { return aead_scheme_; }

size_t AeadKey::NonceSize() const { return nonce_size_; }

size_t AeadKey::MaxSealOverhead() const { return max_seal_overhead_; }

Status AeadKey::Seal(ByteContainerView plaintext,
                     ByteContainerView associated_data, ByteContainerView nonce,
                     absl::Span<uint8_t> ciphertext, size_t *ciphertext_size) {
  if (nonce.size() != nonce_size_) {
    return Status(absl::StatusCode::kInvalidArgument,
                  absl::StrCat("Invalid nonce length: ", nonce.size(),
                               " (must be ", nonce_size_, " bytes)"));
  }

  EVP_AEAD_CTX context;
  Cleanup cleanup_context([&context]() { EVP_AEAD_CTX_cleanup(&context); });

  if (EVP_AEAD_CTX_init(&context, aead_, key_.data(), key_.size(),
                        EVP_AEAD_max_tag_len(aead_),
                        /*impl=*/nullptr) != 1) {
    return Status(
        absl::StatusCode::kInternal,
        absl::StrCat("EVP_AEAD_CTX_init failed: ", BsslLastErrorString()));
  }

  if (EVP_AEAD_CTX_seal(&context, ciphertext.data(), ciphertext_size,
                        ciphertext.size(), nonce.data(), nonce.size(),
                        plaintext.data(), plaintext.size(),
                        associated_data.data(), associated_data.size()) != 1) {
    return Status(
        absl::StatusCode::kInternal,
        absl::StrCat("EVP_AEAD_CTX_seal failed: ", BsslLastErrorString()));
  }

  return absl::OkStatus();
}

Status AeadKey::Open(ByteContainerView ciphertext,
                     ByteContainerView associated_data, ByteContainerView nonce,
                     absl::Span<uint8_t> plaintext, size_t *plaintext_size) {
  if (nonce.size() != nonce_size_) {
    return Status(absl::StatusCode::kInvalidArgument,
                  absl::StrCat("Invalid nonce length: ", nonce.size(),
                               " (must be ", nonce_size_, " bytes)"));
  }

  EVP_AEAD_CTX context;
  Cleanup cleanup_context([&context]() { EVP_AEAD_CTX_cleanup(&context); });
  if (EVP_AEAD_CTX_init(&context, aead_, key_.data(), key_.size(),
                        EVP_AEAD_max_tag_len(aead_),
                        /*impl=*/nullptr) != 1) {
    return Status(
        absl::StatusCode::kInternal,
        absl::StrCat("EVP_AEAD_CTX_init failed: ", BsslLastErrorString()));
  }

  if (EVP_AEAD_CTX_open(&context, plaintext.data(), plaintext_size,
                        plaintext.size(), nonce.data(), nonce.size(),
                        ciphertext.data(), ciphertext.size(),
                        associated_data.data(), associated_data.size()) != 1) {
    return Status(
        absl::StatusCode::kInternal,
        absl::StrCat("EVP_AEAD_CTX_open failed: ", BsslLastErrorString()));
  }

  return absl::OkStatus();
}

AeadKey::AeadKey(AeadScheme aead_scheme, ByteContainerView key)
    : aead_(GetEvpAead(aead_scheme)),
      aead_scheme_(aead_scheme),
      key_(key.cbegin(), key.cend()),
      max_seal_overhead_(EVP_AEAD_max_overhead(aead_)),
      nonce_size_(EVP_AEAD_nonce_length(aead_)) {}

}  // namespace asylo

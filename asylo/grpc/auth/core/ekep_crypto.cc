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

#include "asylo/grpc/auth/core/ekep_crypto.h"

#include <openssl/curve25519.h>
#include <openssl/digest.h>
#include <openssl/hkdf.h>
#include <openssl/hmac.h>
#include <openssl/mem.h>
#include <openssl/rand.h>

#include <cstdint>
#include <memory>

#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "asylo/crypto/sha256_hash.h"
#include "asylo/crypto/util/bssl_util.h"
#include "asylo/crypto/util/byte_container_view.h"
#include "asylo/util/logging.h"
#include "asylo/grpc/auth/core/ekep_errors.h"
#include "asylo/util/proto_enum_util.h"
#include "asylo/util/status.h"

namespace asylo {
namespace {

constexpr size_t kEkepSecretSize =
    (kEkepPrimarySecretSize + kEkepAuthenticatorSecretSize);

constexpr char kEkepHkdfSalt[] = "EKEP Handshake v1";
constexpr char kEkepHkdfSaltRecordProtocol[] = "EKEP Record Protocol v1";
constexpr char kServerAuthenticatedText[] = "EKEP Handshake v1: Server Finish";
constexpr char kClientAuthenticatedText[] = "EKEP Handshake v1: Client Finish";

// Computes the HMAC of |authenticated_text| using the given |key|. The HMAC
// function is initialized using the hash function from |ciphersuite|. On
// success, writes the message authentication code to |mac|.
//
// If the ciphersuite is unsupported, returns BAD_HANDSHAKE_CIPHER.
Status Hmac(const HandshakeCipher &ciphersuite, ByteContainerView key,
            ByteContainerView authenticated_text,
            CleansingVector<uint8_t> *mac) {
  mac->clear();
  const EVP_MD *digest = nullptr;
  switch (ciphersuite) {
    case CURVE25519_SHA256:
      digest = EVP_sha256();
      mac->resize(kSha256DigestLength);
      break;
    default:
      return EkepError(
          Abort::BAD_HANDSHAKE_CIPHER,
          "Ciphersuite not supported: " + ProtoEnumValueName(ciphersuite));
  }

  unsigned int mac_size = mac->size();
  if (!HMAC(digest, key.data(), key.size(), authenticated_text.data(),
            authenticated_text.size(), mac->data(), &mac_size)) {
    LOG(ERROR) << "HMAC failed: " << BsslLastErrorString();
    return EkepError(Abort::INTERNAL_ERROR, "Internal error");
  }
  return absl::OkStatus();
}

}  // namespace

Status DeriveSecrets(const HandshakeCipher &ciphersuite,
                     ByteContainerView transcript_hash,
                     ByteContainerView peer_dh_public_key,
                     ByteContainerView self_dh_private_key,
                     CleansingVector<uint8_t> *primary_secret,
                     CleansingVector<uint8_t> *authenticator_secret) {
  const EVP_MD *digest = nullptr;
  CleansingVector<uint8_t> shared_secret;

  // Generate the shared secret and initialize a hash function for HKDF based on
  // the ciphersuite.
  switch (ciphersuite) {
    case CURVE25519_SHA256:
      // Validate the arguments.
      if (peer_dh_public_key.size() != X25519_PUBLIC_VALUE_LEN) {
        return EkepError(Abort::PROTOCOL_ERROR,
                         absl::StrCat("Public parameter has incorrect size: ",
                                      peer_dh_public_key.size()));
      }
      if (self_dh_private_key.size() != X25519_PRIVATE_KEY_LEN) {
        return EkepError(Abort::INTERNAL_ERROR,
                         absl::StrCat("Private parameter has incorrect size: ",
                                      self_dh_private_key.size()));
      }

      // Compute the shared secret.
      shared_secret.resize(X25519_SHARED_KEY_LEN);
      if (!X25519(shared_secret.data(), self_dh_private_key.data(),
                  peer_dh_public_key.data())) {
        LOG(ERROR) << "X25519 failed: " << BsslLastErrorString();
        return EkepError(Abort::INTERNAL_ERROR, "Internal error");
      }

      // Initialize a SHA256-digest for HKDF.
      digest = EVP_sha256();
      break;
    default:
      return EkepError(
          Abort::BAD_HANDSHAKE_CIPHER,
          "Ciphersuite not supported: " + ProtoEnumValueName(ciphersuite));
  }

  // Derive the primary and authenticator secrets using HKDF.
  std::string salt(kEkepHkdfSalt);
  CleansingVector<uint8_t> output_key;
  output_key.resize(kEkepSecretSize);
  if (!HKDF(output_key.data(), kEkepSecretSize, digest, shared_secret.data(),
            shared_secret.size(),
            reinterpret_cast<const uint8_t *>(salt.data()), salt.size(),
            transcript_hash.data(), transcript_hash.size())) {
    LOG(ERROR) << "HKDF failed: " << BsslLastErrorString();
    return EkepError(Abort::INTERNAL_ERROR, "Internal error");
  }

  // Copy the primary secret.
  std::copy(output_key.cbegin(), output_key.cbegin() + kEkepPrimarySecretSize,
            std::back_inserter(*primary_secret));

  // Copy the authenticator secret.
  std::copy(output_key.cbegin() + kEkepPrimarySecretSize, output_key.cend(),
            std::back_inserter(*authenticator_secret));

  return absl::OkStatus();
}

Status DeriveRecordProtocolKey(const HandshakeCipher &ciphersuite,
                               const RecordProtocol &record_protocol,
                               ByteContainerView transcript_hash,
                               ByteContainerView primary_secret,
                               CleansingVector<uint8_t> *record_protocol_key) {
  record_protocol_key->clear();
  const EVP_MD *digest = nullptr;
  switch (ciphersuite) {
    case CURVE25519_SHA256:
      digest = EVP_sha256();
      break;
    default:
      return EkepError(
          Abort::BAD_HANDSHAKE_CIPHER,
          "Ciphersuite not supported: " + ProtoEnumValueName(ciphersuite));
  }

  // Resize the output vector to an appropriate size for the selected record
  // protocol.
  switch (record_protocol) {
    case ALTSRP_AES128_GCM:
      record_protocol_key->resize(kAltsRecordProtocolAes128GcmKeySize);
      // Randomize the key bytes just in case the key is mistakenly used even
      // when the key derivation fails. The byte-sequence in uninitialized
      // memory could be predictable and, as a result, an attacker may be able
      // to recover data that is encrypted by a key whose underlying bytes are
      // uninitialized. Initializing the key with a truly random value makes it
      // impossible for an attacker to recover any data that is mistakenly
      // encrypted with the key.
      RAND_bytes(record_protocol_key->data(), record_protocol_key->size());
      break;
    default:
      return EkepError(Abort::BAD_RECORD_PROTOCOL,
                       "Record protocol not supported " +
                           ProtoEnumValueName(record_protocol));
  }

  std::string salt(kEkepHkdfSaltRecordProtocol);
  if (!HKDF(record_protocol_key->data(), record_protocol_key->size(), digest,
            primary_secret.data(), primary_secret.size(),
            reinterpret_cast<const uint8_t *>(salt.data()), salt.size(),
            transcript_hash.data(), transcript_hash.size())) {
    LOG(ERROR) << "HKDF failed: " << BsslLastErrorString();
    return EkepError(Abort::INTERNAL_ERROR, "Internal error");
  }
  return absl::OkStatus();
}

Status ComputeClientHandshakeAuthenticator(
    const HandshakeCipher &ciphersuite, ByteContainerView authenticator_secret,
    CleansingVector<uint8_t> *authenticator) {
  std::string input(kClientAuthenticatedText);
  return Hmac(ciphersuite, authenticator_secret, input, authenticator);
}

Status ComputeServerHandshakeAuthenticator(
    const HandshakeCipher &ciphersuite, ByteContainerView authenticator_secret,
    CleansingVector<uint8_t> *authenticator) {
  std::string input(kServerAuthenticatedText);
  return Hmac(ciphersuite, authenticator_secret, input, authenticator);
}

bool CheckMacEquality(CleansingVector<uint8_t> mac1,
                      CleansingVector<uint8_t> mac2) {
  if (mac1.size() != mac2.size()) {
    return false;
  }
  return CRYPTO_memcmp(mac1.data(), mac2.data(), mac1.size()) == 0;
}

}  // namespace asylo

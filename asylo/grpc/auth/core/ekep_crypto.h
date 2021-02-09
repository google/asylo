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

#ifndef ASYLO_GRPC_AUTH_CORE_EKEP_CRYPTO_H_
#define ASYLO_GRPC_AUTH_CORE_EKEP_CRYPTO_H_

#include <cstdint>
#include <memory>
#include <vector>

#include "asylo/crypto/util/byte_container_view.h"
#include "asylo/grpc/auth/core/handshake.pb.h"
#include "asylo/util/cleansing_types.h"
#include "asylo/util/status.h"

namespace asylo {

constexpr size_t kEkepPrimarySecretSize = 64;
constexpr size_t kEkepAuthenticatorSecretSize = 64;
constexpr size_t kAltsRecordProtocolAes128GcmKeySize = 16;

// Derives EKEP secrets based on the selected |ciphersuite| and the input
// |transcript_hash|, |peer_dh_public_key|, and |self_dh_private_key|. On
// success, writes the primary secret to |primary_secret| and the authenticator
// secret to |authenticator_secret|.
//
// Note that |self_dh_private_key| is a ByteContainerView, which does not
// enforce any data safety policy on the underlying container. The caller
// should take care to pass their private key using a self-cleansing
// container.
//
// If the ciphersuite is unsupported, returns BAD_HANDSHAKE_CIPHER.
// If the peer's public key has an invalid size, returns PROTOCOL_ERROR.
// If self's private key has an invalid size, returns INTERNAL_ERROR.
// Returns INTERNAL_ERROR on other errors.
Status DeriveSecrets(const HandshakeCipher &ciphersuite,
                     ByteContainerView transcript_hash,
                     ByteContainerView peer_dh_public_key,
                     ByteContainerView self_dh_private_key,
                     CleansingVector<uint8_t> *primary_secret,
                     CleansingVector<uint8_t> *authenticator_secret);

// Derives a record protocol key for the given |record_protocol| using HKDF
// initialized with the hash function from |ciphersuite| and the input key
// material |primary_secret|. On success, writes the record protocol key to
// |record_protocol_key|.
//
// Note that |primary_secret| is a ByteContainerView, which does not enforce
// any data safety policy on the underlying container. The caller should take
// care to pass their primary secret using a self-cleansing container.
//
// If the ciphersuite is unsupported, returns BAD_HANDSHAKE_CIPHER.
// If the record protocol is unsupported, returns BAD_RECORD_PROTOCOL.
// Returns INTERNAL_ERROR on other errors.
Status DeriveRecordProtocolKey(const HandshakeCipher &ciphersuite,
                               const RecordProtocol &record_protocol,
                               ByteContainerView transcript_hash,
                               ByteContainerView primary_secret,
                               CleansingVector<uint8_t> *record_protocol_key);

// The following two methods compute the handshake authenticator for the
// client and the server using HMAC initialized with the hash function from
// |ciphersuite|, and the key in |authenticator_secret|. On success they write
// the handshake authenticator tag to |authenticator|.
//
// Note that |authenticator_secret| is a ByteContainerView, which does not
// enforce any data safety policy on the underlying container. The caller
// should take care to pass their authenticator secret using a self-cleansing
// container.
//
// If the ciphersuite is unsupported, returns BAD_HANDSHAKE_CIPHER.
Status ComputeClientHandshakeAuthenticator(
    const HandshakeCipher &ciphersuite, ByteContainerView authenticator_secret,
    CleansingVector<uint8_t> *authenticator);

Status ComputeServerHandshakeAuthenticator(
    const HandshakeCipher &ciphersuite, ByteContainerView authenticator_secret,
    CleansingVector<uint8_t> *authenticator);

// Performs a constant-time equality comparison of |mac1| and |mac2|.
bool CheckMacEquality(CleansingVector<uint8_t> mac1,
                      CleansingVector<uint8_t> mac2);

}  // namespace asylo

#endif  // ASYLO_GRPC_AUTH_CORE_EKEP_CRYPTO_H_

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

#ifndef ASYLO_CRYPTO_ECDSA_P256_SHA256_SIGNING_KEY_H_
#define ASYLO_CRYPTO_ECDSA_P256_SHA256_SIGNING_KEY_H_

#include <openssl/nid.h>

#include "asylo/crypto/algorithms.pb.h"
#include "asylo/crypto/ecdsa_signing_key.h"
#include "asylo/crypto/sha256_hash.h"

namespace asylo {

using EccP256CurvePoint = internal::EccCurvePoint<32>;

// A specialization of EcdsaVerifyingKey using ECDSA-P256 keys
// for signature verification and SHA256 for hashing.
using EcdsaP256Sha256VerifyingKey =
    internal::EcdsaVerifyingKey<SignatureScheme::ECDSA_P256_SHA256,
                                NID_X9_62_prime256v1, 32, Sha256Hash>;

// A specialization of EcdsaSigningKey using ECDSA-P256 keys
// for signing and SHA256 for hashing.
using EcdsaP256Sha256SigningKey =
    internal::EcdsaSigningKey<SignatureScheme::ECDSA_P256_SHA256,
                              NID_X9_62_prime256v1, 32, Sha256Hash>;

}  // namespace asylo
#endif  // ASYLO_CRYPTO_ECDSA_P256_SHA256_SIGNING_KEY_H_

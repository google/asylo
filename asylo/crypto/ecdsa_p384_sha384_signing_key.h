/*
 * Copyright 2020 Asylo authors
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
 */

#ifndef ASYLO_CRYPTO_ECDSA_P384_SHA384_SIGNING_KEY_H_
#define ASYLO_CRYPTO_ECDSA_P384_SHA384_SIGNING_KEY_H_

#include <openssl/nid.h>

#include "asylo/crypto/algorithms.pb.h"
#include "asylo/crypto/ecdsa_signing_key.h"
#include "asylo/crypto/sha384_hash.h"

namespace asylo {

using EccP384CurvePoint = internal::EccCurvePoint<48>;

// A specialization of EcdsaVerifyingKey using ECDSA-P384 keys
// for signature verification and SHA 384 for message hashing.
using EcdsaP384Sha384VerifyingKey =
    internal::EcdsaVerifyingKey<SignatureScheme::ECDSA_P384_SHA384,
                                NID_secp384r1, 48, Sha384Hash>;

// A specialization of EcdsaSigningKey using ECDSA-P384 keys
// for signing and SHA 384 for message hashing.
using EcdsaP384Sha384SigningKey =
    internal::EcdsaSigningKey<SignatureScheme::ECDSA_P384_SHA384, NID_secp384r1,
                              48, Sha384Hash>;

}  // namespace asylo

#endif  // ASYLO_CRYPTO_ECDSA_P384_SHA384_SIGNING_KEY_H_

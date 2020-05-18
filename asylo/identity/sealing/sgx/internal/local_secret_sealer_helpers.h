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

#ifndef ASYLO_IDENTITY_SEALING_SGX_INTERNAL_LOCAL_SECRET_SEALER_HELPERS_H_
#define ASYLO_IDENTITY_SEALING_SGX_INTERNAL_LOCAL_SECRET_SEALER_HELPERS_H_

#include "asylo/crypto/aead_cryptor.h"
#include "asylo/crypto/algorithms.pb.h"
#include "asylo/crypto/util/byte_container_view.h"
#include "asylo/crypto/util/bytes.h"
#include "asylo/identity/platform/sgx/code_identity.pb.h"
#include "asylo/identity/platform/sgx/internal/identity_key_management_structs.h"
#include "asylo/identity/platform/sgx/sgx_identity.pb.h"
#include "asylo/identity/sealing/sealed_secret.pb.h"
#include "asylo/util/cleansing_types.h"
#include "asylo/util/status.h"

namespace asylo {
namespace sgx {
namespace internal {

extern const char *const kSgxLocalSecretSealerRootName;

// Performs validity checks on the sealed secret header, and extracts parameters
// necessary for generating the cryptor key.
Status ParseKeyGenerationParamsFromSealedSecretHeader(
    const SealedSecretHeader &header, AeadScheme *aead_scheme,
    SgxIdentityExpectation *sgx_expectation);

// Converts |spec| to the KEYPOLICY bit vector defined in the Intel SDM.
uint16_t ConvertMatchSpecToKeypolicy(const SgxIdentityMatchSpec &spec);

// Generates the key used by the AEAD Cryptor to perform the Seal or the Open
// operation.
Status GenerateCryptorKey(AeadScheme aead_scheme, const std::string &key_id,
                          const SgxIdentityExpectation &sgx_expectation,
                          size_t key_size, CleansingVector<uint8_t> *key);

// Creates a cryptor that uses |key| and the algorithm denoted by
// |aead_scheme|. Returns a non-OK status if a cryptor cannot be generated.
StatusOr<std::unique_ptr<AeadCryptor>> MakeCryptor(
    AeadScheme aead_scheme, ByteContainerView key);

// Seals |secret| and |additional_data| into |sealed_secret|, using |cryptor|.
Status Seal(AeadCryptor *cryptor, ByteContainerView secret,
            ByteContainerView additional_data, SealedSecret *sealed_secret);

// Opens |sealed_secret| into |secret|, using |cryptor| with |additional_data|.
Status Open(AeadCryptor *cryptor, const SealedSecret &sealed_secret,
            ByteContainerView additional_data,
            CleansingVector<uint8_t> *secret);

// Parses and returns the AEAD scheme associated with |header|. Returns a non-OK
// status if |header| cannot be parsed.
StatusOr<AeadScheme> GetAeadSchemeFromSealedSecretHeader(
    const SealedSecretHeader &header);

}  // namespace internal
}  // namespace sgx
}  // namespace asylo

#endif  // ASYLO_IDENTITY_SEALING_SGX_INTERNAL_LOCAL_SECRET_SEALER_HELPERS_H_

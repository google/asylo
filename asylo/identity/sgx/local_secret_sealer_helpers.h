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

#ifndef ASYLO_IDENTITY_SGX_LOCAL_SECRET_SEALER_HELPERS_H_
#define ASYLO_IDENTITY_SGX_LOCAL_SECRET_SEALER_HELPERS_H_

#include "asylo/crypto/util/bytes.h"
#include "asylo/identity/sealed_secret.pb.h"
#include "asylo/identity/sgx/code_identity.pb.h"
#include "asylo/identity/sgx/identity_key_management_structs.h"
#include "asylo/identity/sgx/local_sealed_secret.pb.h"
#include "asylo/util/cleansing_types.h"
#include "asylo/util/status.h"

namespace asylo {
namespace sgx {
namespace internal {

extern const char *const kSgxLocalSecretSealerRootName;

// Performs validity checks on the sealed secret header, and extracts parameters
// necessary for generating the cryptor key.
Status ParseKeyGenerationParamsFromSealedSecretHeader(
    const SealedSecretHeader &header, UnsafeBytes<kCpusvnSize> *cpusvn,
    CipherSuite *cipher_suite, CodeIdentityExpectation *sgx_expectation);

// Converts |spec| to the KEYPOLICY bit vector defined in the Intel SDM.
uint16_t ConvertMatchSpecToKeypolicy(const CodeIdentityMatchSpec &spec);

// Generates the key used by the AEAD Cryptor to perform the Seal or the Open
// operation.
Status GenerateCryptorKey(CipherSuite cipher_suite, const std::string &key_id,
                          const UnsafeBytes<kCpusvnSize> &cpusvn,
                          const CodeIdentityExpectation &sgx_expectation,
                          size_t key_size, CleansingVector<uint8_t> *key);

}  // namespace internal
}  // namespace sgx
}  // namespace asylo

#endif  // ASYLO_IDENTITY_SGX_LOCAL_SECRET_SEALER_HELPERS_H_

/*
 *
 * Copyright 2019 Asylo authors
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

#ifndef ASYLO_IDENTITY_ATTESTATION_SGX_INTERNAL_REMOTE_ASSERTION_GENERATOR_ENCLAVE_TEST_UTIL_H_
#define ASYLO_IDENTITY_ATTESTATION_SGX_INTERNAL_REMOTE_ASSERTION_GENERATOR_ENCLAVE_TEST_UTIL_H_

#include "asylo/crypto/certificate.pb.h"

namespace asylo {
namespace sgx {

// Appends a PCK Certificate for kFakePckPem, the Asylo Fake SGX Processor CA
// Certificate, and the Asylo Fake SGX Root CA certificate to
// |certificate_chain|.
void AppendFakePckCertificateChain(CertificateChain *certificate_chain);

// Returns a fake certificate chain containing the following certificates:
//   * PCK Certificate for kFakePckPem
//   * Asylo Fake SGX Processor CA Certificate
//   * Asylo Fake SGX Root CA Certificate
CertificateChain GetFakePckCertificateChain();

}  // namespace sgx
}  // namespace asylo

#endif  // ASYLO_IDENTITY_ATTESTATION_SGX_INTERNAL_REMOTE_ASSERTION_GENERATOR_ENCLAVE_TEST_UTIL_H_

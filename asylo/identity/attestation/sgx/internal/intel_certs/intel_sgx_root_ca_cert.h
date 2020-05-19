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

#ifndef ASYLO_IDENTITY_ATTESTATION_SGX_INTERNAL_INTEL_CERTS_INTEL_SGX_ROOT_CA_CERT_H_
#define ASYLO_IDENTITY_ATTESTATION_SGX_INTERNAL_INTEL_CERTS_INTEL_SGX_ROOT_CA_CERT_H_

#include "asylo/crypto/certificate.pb.h"

namespace asylo {

// Constant representing the Intel SGX root CA certificate. This certificate is
// the root certificate for certificates from the Intel SGX PCK Platform CA and
// the Intel SGX PCK Processor CA, and the root certificate for the Intel SGX
// TCB Signing Certificate.
extern const char *const kIntelSgxRootCaCertificate;

// Returns the Intel SGX root CA certificate in a form compatible with the Asylo
// `Certificate` proto message.
Certificate MakeIntelSgxRootCaCertificateProto();

}  // namespace asylo

#endif  // ASYLO_IDENTITY_ATTESTATION_SGX_INTERNAL_INTEL_CERTS_INTEL_SGX_ROOT_CA_CERT_H_

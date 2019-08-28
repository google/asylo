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

#ifndef ASYLO_IDENTITY_SGX_REMOTE_ASSERTION_UTIL_H_
#define ASYLO_IDENTITY_SGX_REMOTE_ASSERTION_UTIL_H_

#include <string>
#include <vector>

#include "asylo/crypto/certificate.pb.h"
#include "asylo/crypto/signing_key.h"
#include "asylo/identity/sgx/remote_assertion.pb.h"
#include "asylo/identity/sgx/sgx_identity.pb.h"
#include "asylo/util/status.h"

namespace asylo {
namespace sgx {

// Creates a RemoteAssertion that binds |user_data| to a statement about
// |identity| and signs this assertion with |signing_key|. Adds all certificate
// chains in |cert_chains| to the assertion. Places the resulting assertion in
// |assertion|.
Status MakeRemoteAssertion(const std::string &user_data,
                           const SgxIdentity &identity,
                           const SigningKey &signing_key,
                           const std::vector<CertificateChain> &cert_chains,
                           RemoteAssertion *assertion);

// Verifies |assertion| by verifying the following:
//   * |assertion| is cryptographically-bound to |user_data|
//   * The payload in |assertion| is signed by |verifying_key|
//   * |assertion| provides a certificate chain for |verifying_key| for each
//   root certificate in |root_certificates|.
//
// On success, extracts the peer's verified CodeIdentity to |identity|.
Status VerifyRemoteAssertion(const std::string &user_data,
                             const VerifyingKey &verifying_key,
                             const std::vector<Certificate> &root_certificates,
                             const RemoteAssertion &assertion,
                             SgxIdentity *identity);

}  // namespace sgx
}  // namespace asylo

#endif  // ASYLO_IDENTITY_SGX_REMOTE_ASSERTION_UTIL_H_

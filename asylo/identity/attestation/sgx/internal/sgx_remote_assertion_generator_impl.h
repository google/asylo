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

#ifndef ASYLO_IDENTITY_ATTESTATION_SGX_INTERNAL_SGX_REMOTE_ASSERTION_GENERATOR_IMPL_H_
#define ASYLO_IDENTITY_ATTESTATION_SGX_INTERNAL_SGX_REMOTE_ASSERTION_GENERATOR_IMPL_H_

#include <memory>
#include <vector>

#include "asylo/crypto/certificate.pb.h"
#include "asylo/crypto/signing_key.h"
#include "asylo/identity/attestation/sgx/internal/sgx_remote_assertion_generator.grpc.pb.h"
#include "asylo/util/mutex_guarded.h"
#include "asylo/util/status.h"
#include "include/grpcpp/server_context.h"

namespace asylo {

// SgxRemoteAssertionGeneratorImpl generates SGX remote assertions for
// authenticated local SGX callers.
//
// This service requires that the peer authenticates with their SGX code
// identity. The gRPC server's credentials configuration should enforce this
// authentication policy.
class SgxRemoteAssertionGeneratorImpl
    : public SgxRemoteAssertionGenerator::Service {
 public:
  SgxRemoteAssertionGeneratorImpl();

  // Creates a service that signs assertions with |signing_key| and uses
  // |certificate_chains| to prove the authenticity of assertions.
  SgxRemoteAssertionGeneratorImpl(
      std::unique_ptr<SigningKey> signing_key,
      const std::vector<CertificateChain> &certificate_chains);

  // Generates an SGX remote assertion satisfying |request| for the caller
  // described in |context|, if that caller is an authenticated local SGX
  // enclave entity. On success, writes the assertion to |response|. Returns an
  // UNAUTHENTICATED error if the caller does not authenticate with their SGX
  // identity.
  ::grpc::Status GenerateSgxRemoteAssertion(
      ::grpc::ServerContext *context,
      const GenerateSgxRemoteAssertionRequest *request,
      GenerateSgxRemoteAssertionResponse *response) override;

  // Updates |signing_key_| and |certificate_chains_| with |signing_key| and
  // |certificate_chains| respectively.
  void UpdateSigningKeyAndCertificateChains(
      std::unique_ptr<SigningKey> signing_key,
      const std::vector<CertificateChain> &certificate_chains);

 private:
  // The key used to sign attestations.
  MutexGuarded<std::unique_ptr<SigningKey>> signing_key_;

  // Certificate chains that serve to prove the authenticity of signatures
  // produced by |signing_key_|.
  MutexGuarded<std::vector<CertificateChain>> certificate_chains_;
};

}  // namespace asylo

#endif  // ASYLO_IDENTITY_ATTESTATION_SGX_INTERNAL_SGX_REMOTE_ASSERTION_GENERATOR_IMPL_H_

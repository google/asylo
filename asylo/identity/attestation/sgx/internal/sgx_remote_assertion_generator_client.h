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

#ifndef ASYLO_IDENTITY_ATTESTATION_SGX_INTERNAL_SGX_REMOTE_ASSERTION_GENERATOR_CLIENT_H_
#define ASYLO_IDENTITY_ATTESTATION_SGX_INTERNAL_SGX_REMOTE_ASSERTION_GENERATOR_CLIENT_H_

#include <memory>

#include "asylo/crypto/util/byte_container_view.h"
#include "asylo/identity/attestation/sgx/internal/remote_assertion.pb.h"
#include "asylo/identity/attestation/sgx/internal/sgx_remote_assertion_generator.grpc.pb.h"
#include "asylo/util/statusor.h"
#include "include/grpcpp/grpcpp.h"

namespace asylo {

// A gRPC client for the SgxRemoteAssertionGenerator service.
class SgxRemoteAssertionGeneratorClient {
 public:
  // Creates an SgxRemoteAssertionGeneratorClient that uses |channel| to talk to
  // the remote server.
  explicit SgxRemoteAssertionGeneratorClient(
      const std::shared_ptr<::grpc::ChannelInterface> &channel);

  // Creates an SgxRemoteAssertionGeneratorClient that uses |stub| to talk to
  // the remote server.
  explicit SgxRemoteAssertionGeneratorClient(
      std::unique_ptr<SgxRemoteAssertionGenerator::StubInterface>
          stub);

  // Requests an SGX remote assertion that is bound to |user_data| from the
  // remote server.
  StatusOr<sgx::RemoteAssertion> GenerateSgxRemoteAssertion(
      ByteContainerView user_data);

 private:
  std::unique_ptr<SgxRemoteAssertionGenerator::StubInterface> stub_;
};

}  // namespace asylo

#endif  // ASYLO_IDENTITY_ATTESTATION_SGX_INTERNAL_SGX_REMOTE_ASSERTION_GENERATOR_CLIENT_H_

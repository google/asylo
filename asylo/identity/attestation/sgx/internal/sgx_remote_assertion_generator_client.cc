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

#include "asylo/identity/attestation/sgx/internal/sgx_remote_assertion_generator_client.h"

#include "asylo/util/status.h"
#include "asylo/util/status_helpers.h"
#include "include/grpcpp/client_context.h"

namespace asylo {

SgxRemoteAssertionGeneratorClient::SgxRemoteAssertionGeneratorClient(
    const std::shared_ptr<::grpc::ChannelInterface> &channel)
    : stub_(SgxRemoteAssertionGenerator::NewStub(channel)) {}

SgxRemoteAssertionGeneratorClient::SgxRemoteAssertionGeneratorClient(
    std::unique_ptr<SgxRemoteAssertionGenerator::StubInterface> stub)
    : stub_(std::move(stub)) {}

StatusOr<sgx::RemoteAssertion>
SgxRemoteAssertionGeneratorClient::GenerateSgxRemoteAssertion(
    ByteContainerView user_data) {
  ::grpc::ClientContext context;

  GenerateSgxRemoteAssertionRequest request;
  request.set_user_data(user_data.data(), user_data.size());
  GenerateSgxRemoteAssertionResponse response;

  ::grpc::Status status =
      stub_->GenerateSgxRemoteAssertion(&context, request, &response);
  if (!status.ok()) {
    return ConvertStatus<asylo::Status>(status);
  }

  return response.assertion();
}

}  // namespace asylo

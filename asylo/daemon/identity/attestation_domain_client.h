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

#ifndef ASYLO_DAEMON_IDENTITY_ATTESTATION_DOMAIN_CLIENT_H_
#define ASYLO_DAEMON_IDENTITY_ATTESTATION_DOMAIN_CLIENT_H_

#include <memory>
#include <string>

#include "asylo/daemon/identity/attestation_domain.grpc.pb.h"
#include "asylo/util/statusor.h"
#include "include/grpcpp/grpcpp.h"

namespace asylo {
namespace daemon {

class AttestationDomainClient {
 public:
  // Constructs an AttestationDomainClient from |channel|.
  explicit AttestationDomainClient(
      const std::shared_ptr<grpc::ChannelInterface> &channel)
      : stub_{AttestationDomainService::NewStub(
            channel, grpc::StubOptions())} {}

  // Constructs an AttestationDomainClient from |stub|.
  explicit AttestationDomainClient(
      std::unique_ptr<AttestationDomainService::StubInterface> stub)
      : stub_{std::move(stub)} {}

  // Gets attestation domain string via stub_.
  StatusOr<std::string> GetAttestationDomain();

 private:
  std::unique_ptr<AttestationDomainService::StubInterface> stub_;
};

}  // namespace daemon
}  // namespace asylo

#endif  // ASYLO_DAEMON_IDENTITY_ATTESTATION_DOMAIN_CLIENT_H_

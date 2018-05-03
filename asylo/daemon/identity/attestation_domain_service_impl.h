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

#ifndef ASYLO_DAEMON_IDENTITY_ATTESTATION_DOMAIN_SERVICE_IMPL_H_
#define ASYLO_DAEMON_IDENTITY_ATTESTATION_DOMAIN_SERVICE_IMPL_H_

#include <string>

#include "grpcpp/grpcpp.h"
#include "asylo/daemon/identity/attestation_domain.grpc.pb.h"

namespace asylo {
namespace daemon {

class AttestationDomainServiceImpl final
    : public AttestationDomainService::Service {
 public:
  // Constructs an AttestationDomainServiceImpl object that retrieves the
  // attestation-domain name from |domain_file_path|.
  explicit AttestationDomainServiceImpl(std::string domain_file_path)
      : domain_file_path_{std::move(domain_file_path)} {}

  // Retrieves the attestation-domain name from domain_file_path_ and sets
  // |response| accordingly.
  grpc::Status GetAttestationDomain(
      ::grpc::ServerContext *context,
      const GetAttestationDomainRequest *request,
      GetAttestationDomainResponse *response) override;

 private:
  const std::string domain_file_path_;
};

}  // namespace daemon
}  // namespace asylo

#endif  // ASYLO_DAEMON_IDENTITY_ATTESTATION_DOMAIN_SERVICE_IMPL_H_

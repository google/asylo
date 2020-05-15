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

#ifndef ASYLO_IDENTITY_ATTESTATION_SGX_INTERNAL_MOCK_SGX_INFRASTRUCTURAL_ENCLAVE_MANAGER_H_
#define ASYLO_IDENTITY_ATTESTATION_SGX_INTERNAL_MOCK_SGX_INFRASTRUCTURAL_ENCLAVE_MANAGER_H_

#include <gmock/gmock.h>
#include "asylo/crypto/certificate.pb.h"
#include "asylo/crypto/keys.pb.h"
#include "asylo/identity/attestation/sgx/internal/remote_assertion_generator_enclave.pb.h"
#include "asylo/identity/attestation/sgx/internal/sgx_infrastructural_enclave_manager.h"
#include "asylo/identity/platform/sgx/machine_configuration.pb.h"
#include "asylo/identity/provisioning/sgx/internal/platform_provisioning.pb.h"

namespace asylo {

class MockSgxInfrastructuralEnclaveManager
    : public SgxInfrastructuralEnclaveManager {
 public:
  MOCK_METHOD4(AgeGenerateKeyAndCsr,
               Status(const sgx::TargetInfoProto &, sgx::ReportProto *,
                      std::string *, sgx::TargetedCertificateSigningRequest *));
  MOCK_METHOD2(
      AgeGeneratePceInfoSgxHardwareReport,
      StatusOr<sgx::ReportProto>(const sgx::TargetInfoProto &,
                                 const AsymmetricEncryptionKeyProto &));
  MOCK_METHOD2(AgeUpdateCerts,
               StatusOr<SealedSecret>(const std::vector<CertificateChain> &,
                                      bool));
  MOCK_METHOD0(AgeStartServer, Status());
  MOCK_METHOD1(AgeStartServer, Status(const SealedSecret &));
  MOCK_METHOD0(AgeGetSgxIdentity, StatusOr<SgxIdentity>());
  MOCK_METHOD2(PceGetTargetInfo, Status(sgx::TargetInfoProto *, sgx::PceSvn *));
  MOCK_METHOD6(PceGetInfo,
               Status(const sgx::ReportProto &,
                      const AsymmetricEncryptionKeyProto &, sgx::PceSvn *,
                      sgx::PceId *, SignatureScheme *, std::string *));
  MOCK_METHOD3(PceSignReport,
               StatusOr<Signature>(const sgx::PceSvn &, const sgx::CpuSvn &,
                                   const sgx::ReportProto &));
};

}  // namespace asylo

#endif  // ASYLO_IDENTITY_ATTESTATION_SGX_INTERNAL_MOCK_SGX_INFRASTRUCTURAL_ENCLAVE_MANAGER_H_

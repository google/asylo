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

#ifndef ASYLO_IDENTITY_ATTESTATION_SGX_INTERNAL_MOCK_INTEL_ARCHITECTURAL_ENCLAVE_INTERFACE_H_
#define ASYLO_IDENTITY_ATTESTATION_SGX_INTERNAL_MOCK_INTEL_ARCHITECTURAL_ENCLAVE_INTERFACE_H_

#include <cstdint>
#include <string>

#include <gmock/gmock.h>
#include "absl/types/span.h"
#include "asylo/crypto/algorithms.pb.h"
#include "asylo/crypto/util/bytes.h"
#include "asylo/identity/attestation/sgx/internal/intel_architectural_enclave_interface.h"
#include "asylo/identity/platform/sgx/internal/identity_key_management_structs.h"
#include "asylo/util/status.h"

namespace asylo {
namespace sgx {

class MockIntelArchitecturalEnclaveInterface
    : public IntelArchitecturalEnclaveInterface {
 public:
  MOCK_METHOD(Status, SetPckCertificateChain, (const CertificateChain &),
              (override));
  MOCK_METHOD(Status, SetEnclaveDir, (const std::string &), (override));
  MOCK_METHOD(Status, GetPceTargetinfo, (Targetinfo *, uint16_t *), (override));
  MOCK_METHOD(Status, GetPceInfo,
              (const Report &, absl::Span<const uint8_t>,
               AsymmetricEncryptionScheme, std::string *, uint16_t *,
               uint16_t *, SignatureScheme *),
              (override));
  MOCK_METHOD(Status, PceSignReport,
              (const Report &, uint16_t target_pce_svn,
               UnsafeBytes<kCpusvnSize>, std::string *),
              (override));
  MOCK_METHOD(StatusOr<Targetinfo>, GetQeTargetinfo, (), (override));
  MOCK_METHOD(StatusOr<std::vector<uint8_t>>, GetQeQuote,
              (const Report &report), (override));
};

}  // namespace sgx
}  // namespace asylo

#endif  // ASYLO_IDENTITY_ATTESTATION_SGX_INTERNAL_MOCK_INTEL_ARCHITECTURAL_ENCLAVE_INTERFACE_H_

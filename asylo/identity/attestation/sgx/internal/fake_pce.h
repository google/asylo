/*
 *
 * Copyright 2020 Asylo authors
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

#ifndef ASYLO_IDENTITY_ATTESTATION_SGX_INTERNAL_FAKE_PCE_H_
#define ASYLO_IDENTITY_ATTESTATION_SGX_INTERNAL_FAKE_PCE_H_

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "absl/types/span.h"
#include "asylo/crypto/algorithms.pb.h"
#include "asylo/crypto/signing_key.h"
#include "asylo/crypto/util/bytes.h"
#include "asylo/identity/attestation/sgx/internal/intel_architectural_enclave_interface.h"
#include "asylo/identity/platform/sgx/internal/identity_key_management_structs.h"
#include "asylo/util/status.h"
#include "asylo/util/statusor.h"

namespace asylo {
namespace sgx {

// Implementation of a fake PCE with a configurable PCK, PCE SVN, PCE ID, and
// PPID. For simplicity, the PCE accepts any REPORTs as valid. It does not check
// for the PROVISION_KEY ATTRIBUTE bit.
//
// FakePce only implements PCE functions from the
// IntelArchitecturalEnclaveInterface. It does not implement any QE functions.
class FakePce : public IntelArchitecturalEnclaveInterface {
 public:
  static constexpr uint16_t kPceSvn = 7;
  static constexpr uint16_t kPceId = 0;
  static const UnsafeBytes<kPpidSize> kPpid;

  FakePce(std::unique_ptr<SigningKey> pck, uint16_t pce_svn, uint16_t pce_id,
          UnsafeBytes<kPpidSize> ppid);

  // Creates a FakePce that uses the fake PCK from the Asylo Fake SGX PKI,
  // kPceSvn, and kPceId.
  static StatusOr<std::unique_ptr<FakePce>> CreateFromFakePki();

  Status SetPckCertificateChain(const CertificateChain &chain) override;
  Status SetEnclaveDir(const std::string &path) override;
  Status GetPceTargetinfo(Targetinfo *targetinfo, uint16_t *pce_svn) override;
  Status PceSignReport(const Report &report, uint16_t target_pce_svn,
                       UnsafeBytes<kCpusvnSize> target_cpu_svn,
                       std::string *signature) override;
  Status GetPceInfo(const Report &report,
                    absl::Span<const uint8_t> ppid_encryption_key,
                    AsymmetricEncryptionScheme ppid_encryption_scheme,
                    std::string *ppid_encrypted, uint16_t *pce_svn,
                    uint16_t *pce_id,
                    SignatureScheme *signature_scheme) override;

  // Not implemented
  StatusOr<Targetinfo> GetQeTargetinfo() override;

  // Not implemented
  StatusOr<std::vector<uint8_t>> GetQeQuote(const Report &report) override;

 private:
  std::unique_ptr<SigningKey> pck_;
  uint16_t pce_svn_;
  uint16_t pce_id_;
  UnsafeBytes<kPpidSize> ppid_;
};

}  // namespace sgx
}  // namespace asylo

#endif  // ASYLO_IDENTITY_ATTESTATION_SGX_INTERNAL_FAKE_PCE_H_

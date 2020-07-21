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

#ifndef ASYLO_IDENTITY_ATTESTATION_SGX_INTERNAL_DCAP_INTEL_ARCHITECTURAL_ENCLAVE_INTERFACE_H_
#define ASYLO_IDENTITY_ATTESTATION_SGX_INTERNAL_DCAP_INTEL_ARCHITECTURAL_ENCLAVE_INTERFACE_H_

#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <vector>

#include "absl/types/span.h"
#include "asylo/crypto/algorithms.pb.h"
#include "asylo/crypto/util/bytes.h"
#include "asylo/identity/attestation/sgx/internal/dcap_library_interface.h"
#include "asylo/identity/attestation/sgx/internal/intel_architectural_enclave_interface.h"
#include "asylo/identity/platform/sgx/internal/identity_key_management_structs.h"
#include "asylo/util/status.h"

namespace asylo {
namespace sgx {

// DcapIntelArchitecturalEnclaveInterface implements the
// IntelArchitecturalEnclaveInterface using Intel's Data Center Attestation
// Primitives (DCAP) library, which communicates with local instances of Intel
// architectural enclaves using the Architectural Enclave Service Manager Daemon
// (aesmd).
class DcapIntelArchitecturalEnclaveInterface
    : public IntelArchitecturalEnclaveInterface {
 public:
  // Constructs an object that calls the redirected |dcap_library| instead
  // of the real Intel DCAP library.
  explicit DcapIntelArchitecturalEnclaveInterface(
      std::unique_ptr<DcapLibraryInterface> dcap_library);

  ~DcapIntelArchitecturalEnclaveInterface() override = default;

  // From IntelArchitecturalEnclaveInterface.

  Status SetPckCertificateChain(const CertificateChain &chain) override;

  Status SetEnclaveDir(const std::string &path) override;

  Status GetPceTargetinfo(Targetinfo *targetinfo, uint16_t *pce_svn) override;

  Status GetPceInfo(const Report &report,
                    absl::Span<const uint8_t> ppid_encryption_key,
                    AsymmetricEncryptionScheme ppid_encryption_scheme,
                    std::string *ppid_encrypted, uint16_t *pce_svn,
                    uint16_t *pce_id,
                    SignatureScheme *signature_scheme) override;

  Status PceSignReport(const Report &report, uint16_t target_pce_svn,
                       UnsafeBytes<kCpusvnSize> target_cpu_svn,
                       std::string *signature) override;

  StatusOr<Targetinfo> GetQeTargetinfo() override;

  StatusOr<std::vector<uint8_t>> GetQeQuote(const Report &report) override;

 private:
  std::unique_ptr<DcapLibraryInterface> dcap_library_;
};

}  // namespace sgx
}  // namespace asylo

#endif  // ASYLO_IDENTITY_ATTESTATION_SGX_INTERNAL_DCAP_INTEL_ARCHITECTURAL_ENCLAVE_INTERFACE_H_

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

#ifndef ASYLO_IDENTITY_SGX_DCAP_INTEL_ARCHITECTURAL_ENCLAVE_INTERFACE_H_
#define ASYLO_IDENTITY_SGX_DCAP_INTEL_ARCHITECTURAL_ENCLAVE_INTERFACE_H_

#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <vector>

#include "absl/types/span.h"
#include "asylo/crypto/algorithms.pb.h"
#include "asylo/crypto/util/bytes.h"
#include "asylo/identity/sgx/identity_key_management_structs.h"
#include "asylo/identity/sgx/intel_architectural_enclave_interface.h"
#include "asylo/util/status.h"
#include "QuoteGeneration/pce_wrapper/inc/sgx_pce.h"
#include "QuoteGeneration/quote_wrapper/common/inc/sgx_ql_lib_common.h"

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
  // DcapLibraryInterface provides an interface allowing unit tests to inject
  // mocks when constructing DcapIntelArchitecturalEnclaveInterface.
  class DcapLibraryInterface {
   public:
    virtual ~DcapLibraryInterface() = default;

    // Wraps sgx_qe_set_enclave_dirpath.
    virtual quote3_error_t qe_set_enclave_dirpath(const char *) const = 0;

    // Wraps sgx_pce_get_target.
    virtual sgx_pce_error_t pce_get_target(
        sgx_target_info_t *p_pce_target,
        sgx_isv_svn_t *p_pce_isv_svn) const = 0;

    // Wraps sgx_get_pce_info.
    virtual sgx_pce_error_t get_pce_info(
        const sgx_report_t *p_report, const uint8_t *p_pek, uint32_t pek_size,
        uint8_t crypto_suite, uint8_t *p_encrypted_ppid,
        uint32_t encrypted_ppid_size, uint32_t *p_encrypted_ppid_out_size,
        sgx_isv_svn_t *p_pce_isvsvn, uint16_t *p_pce_id,
        uint8_t *p_signature_scheme) const = 0;

    // Wraps sgx_pce_sign_report.
    virtual sgx_pce_error_t pce_sign_report(
        const sgx_isv_svn_t *isv_svn, const sgx_cpu_svn_t *cpu_svn,
        const sgx_report_t *p_report, uint8_t *p_signature,
        uint32_t signature_buf_size, uint32_t *p_signature_out_size) const = 0;

    // Wraps sgx_qe_get_target_info.
    virtual quote3_error_t qe_get_target_info(
        sgx_target_info_t *p_qe_target_info) const = 0;

    // Wraps sgx_qe_get_quote_size.
    virtual quote3_error_t qe_get_quote_size(uint32_t *p_quote_size) const = 0;

    // Wraps sgx_qe_get_quote.
    virtual quote3_error_t qe_get_quote(const sgx_report_t *p_app_report,
                                        uint32_t quote_size,
                                        uint8_t *p_quote) const = 0;
  };

  // Constructs an object that calls into the Intel DCAP library.
  DcapIntelArchitecturalEnclaveInterface();

  // Constructs an object that calls the redirected |dcap_library| instead
  // of the real Intel DCAP library.
  explicit DcapIntelArchitecturalEnclaveInterface(
      std::unique_ptr<DcapLibraryInterface> dcap_library);

  ~DcapIntelArchitecturalEnclaveInterface() override = default;

  // From IntelArchitecturalEnclaveInterface.

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

#endif  // ASYLO_IDENTITY_SGX_DCAP_INTEL_ARCHITECTURAL_ENCLAVE_INTERFACE_H_

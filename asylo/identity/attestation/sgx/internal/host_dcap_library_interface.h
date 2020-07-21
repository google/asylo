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

#ifndef ASYLO_IDENTITY_ATTESTATION_SGX_INTERNAL_HOST_DCAP_LIBRARY_INTERFACE_H_
#define ASYLO_IDENTITY_ATTESTATION_SGX_INTERNAL_HOST_DCAP_LIBRARY_INTERFACE_H_

#include <cstdint>

#include "asylo/identity/attestation/sgx/internal/dcap_library_interface.h"
#include "include/sgx_report.h"
#include "QuoteGeneration/pce_wrapper/inc/sgx_pce_types.h"
#include "QuoteGeneration/quote_wrapper/common/inc/sgx_ql_lib_common.h"

namespace asylo {
namespace sgx {

// Wraps host calls directly into the Intel DCAP library. This implementation is
// not safe to call from inside of an enclave.
//
// Note that these functions are not unit tested, and should thus be simple
// pass-throughs with no additional functionality beyond what Intel's API
// provides. All additional functionality must be put into
// DcapIntelArchitecturalEnclaveInterface so that it may be unit tested.
class HostDcapLibraryInterface : public DcapLibraryInterface {
 public:
  ~HostDcapLibraryInterface() override = default;

  quote3_error_t SetQuoteConfig(const sgx_ql_config_t &config) const override;

  quote3_error_t QeSetEnclaveDirpath(const char *dirpath) const override;

  sgx_pce_error_t PceGetTarget(sgx_target_info_t *p_pce_target,
                               sgx_isv_svn_t *p_pce_isv_svn) const override;

  sgx_pce_error_t GetPceInfo(const sgx_report_t *p_report, const uint8_t *p_pek,
                             uint32_t pek_size, uint8_t crypto_suite,
                             uint8_t *p_encrypted_ppid,
                             uint32_t encrypted_ppid_size,
                             uint32_t *p_encrypted_ppid_out_size,
                             sgx_isv_svn_t *p_pce_isvsvn, uint16_t *p_pce_id,
                             uint8_t *p_signature_scheme) const override;

  sgx_pce_error_t PceSignReport(const sgx_isv_svn_t *isv_svn,
                                const sgx_cpu_svn_t *cpu_svn,
                                const sgx_report_t *p_report,
                                uint8_t *p_signature,
                                uint32_t signature_buf_size,
                                uint32_t *p_signature_out_size) const override;

  quote3_error_t QeGetTargetInfo(
      sgx_target_info_t *p_qe_target_info) const override;

  quote3_error_t QeGetQuoteSize(uint32_t *p_quote_size) const override;

  quote3_error_t QeGetQuote(const sgx_report_t *p_app_report,
                            uint32_t quote_size,
                            uint8_t *p_quote) const override;
};

}  // namespace sgx
}  // namespace asylo

#endif  // ASYLO_IDENTITY_ATTESTATION_SGX_INTERNAL_HOST_DCAP_LIBRARY_INTERFACE_H_

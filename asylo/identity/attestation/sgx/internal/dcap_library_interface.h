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

#ifndef ASYLO_IDENTITY_ATTESTATION_SGX_INTERNAL_DCAP_LIBRARY_INTERFACE_H_
#define ASYLO_IDENTITY_ATTESTATION_SGX_INTERNAL_DCAP_LIBRARY_INTERFACE_H_

#include <cstdint>

#include "include/sgx_report.h"
#include "QuoteGeneration/pce_wrapper/inc/sgx_pce_types.h"
#include "QuoteGeneration/quote_wrapper/common/inc/sgx_ql_lib_common.h"

namespace asylo {
namespace sgx {

// DcapLibraryInterface provides an interface allowing unit tests to inject
// mocks when constructing DcapIntelArchitecturalEnclaveInterface.
//
// Use of this interface is documented in
// https://download.01.org/intel-sgx/dcap-1.2/linux/docs/Intel_SGX_ECDSA_QuoteGenReference_DCAP_API_Linux_1.2.pdf
class DcapLibraryInterface {
 public:
  virtual ~DcapLibraryInterface() = default;

  // Wraps sgx_ql_set_quote_config. Returns a value from the `quote3_error_t`
  // enumeration to indicate status.
  virtual quote3_error_t SetQuoteConfig(
      const sgx_ql_config_t &config) const = 0;

  // Wraps sgx_qe_set_enclave_dirpath. Returns a value from the `quote3_error_t`
  // enumeration to indicate status.
  virtual quote3_error_t QeSetEnclaveDirpath(const char *dirpath) const = 0;

  // Wraps sgx_pce_get_target. Returns a value from the `sgx_pce_error_t`
  // enumeration to indicate status.
  virtual sgx_pce_error_t PceGetTarget(sgx_target_info_t *p_pce_target,
                                       sgx_isv_svn_t *p_pce_isv_svn) const = 0;

  // Wraps sgx_get_pce_info. Returns a value from the `sgx_pce_error_t`
  // enumeration to indicate status.
  virtual sgx_pce_error_t GetPceInfo(
      const sgx_report_t *p_report, const uint8_t *p_pek, uint32_t pek_size,
      uint8_t crypto_suite, uint8_t *p_encrypted_ppid,
      uint32_t encrypted_ppid_size, uint32_t *p_encrypted_ppid_out_size,
      sgx_isv_svn_t *p_pce_isvsvn, uint16_t *p_pce_id,
      uint8_t *p_signature_scheme) const = 0;

  // Wraps sgx_pce_sign_report. Returns a value from the `sgx_pce_error_t`
  // enumeration to indicate status.
  virtual sgx_pce_error_t PceSignReport(
      const sgx_isv_svn_t *isv_svn, const sgx_cpu_svn_t *cpu_svn,
      const sgx_report_t *p_report, uint8_t *p_signature,
      uint32_t signature_buf_size, uint32_t *p_signature_out_size) const = 0;

  // Wraps sgx_qe_get_target_info. Returns a value from the `quote3_error_t`
  // enumeration to indicate status.
  virtual quote3_error_t QeGetTargetInfo(
      sgx_target_info_t *p_qe_target_info) const = 0;

  // Wraps sgx_qe_get_quote_size. Returns a value from the `quote3_error_t`
  // enumeration to indicate status.
  virtual quote3_error_t QeGetQuoteSize(uint32_t *p_quote_size) const = 0;

  // Wraps sgx_qe_get_quote. Returns a value from the `quote3_error_t`
  // enumeration to indicate status.
  virtual quote3_error_t QeGetQuote(const sgx_report_t *p_app_report,
                                    uint32_t quote_size,
                                    uint8_t *p_quote) const = 0;
};

}  // namespace sgx
}  // namespace asylo

#endif  // ASYLO_IDENTITY_ATTESTATION_SGX_INTERNAL_DCAP_LIBRARY_INTERFACE_H_

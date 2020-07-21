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

#include "asylo/identity/attestation/sgx/internal/enclave_dcap_library_interface.h"

#include <cstdint>

#include "asylo/platform/primitives/sgx/trusted_sgx.h"
#include "include/sgx_report.h"
#include "QuoteGeneration/pce_wrapper/inc/sgx_pce_types.h"
#include "QuoteGeneration/quote_wrapper/common/inc/sgx_ql_lib_common.h"

namespace asylo {
namespace sgx {

quote3_error_t EnclaveDcapLibraryInterface::SetQuoteConfig(
    const sgx_ql_config_t &config) const {
  return static_cast<quote3_error_t>(
      primitives::enc_untrusted_ql_set_quote_config(&config));
}

quote3_error_t EnclaveDcapLibraryInterface::QeSetEnclaveDirpath(
    const char *dirpath) const {
  // This API is not required inside of enclaves.
  return SGX_QL_INTERFACE_UNAVAILABLE;
}

sgx_pce_error_t EnclaveDcapLibraryInterface::PceGetTarget(
    sgx_target_info_t *p_pce_target, sgx_isv_svn_t *p_pce_isv_svn) const {
  // This API is not required inside of enclaves.
  return SGX_PCE_INTERFACE_UNAVAILABLE;
}

sgx_pce_error_t EnclaveDcapLibraryInterface::GetPceInfo(
    const sgx_report_t *p_report, const uint8_t *p_pek, uint32_t pek_size,
    uint8_t crypto_suite, uint8_t *p_encrypted_ppid,
    uint32_t encrypted_ppid_size, uint32_t *p_encrypted_ppid_out_size,
    sgx_isv_svn_t *p_pce_isvsvn, uint16_t *p_pce_id,
    uint8_t *p_signature_scheme) const {
  // This API is not required inside of enclaves.
  return SGX_PCE_INTERFACE_UNAVAILABLE;
}

sgx_pce_error_t EnclaveDcapLibraryInterface::PceSignReport(
    const sgx_isv_svn_t *isv_svn, const sgx_cpu_svn_t *cpu_svn,
    const sgx_report_t *p_report, uint8_t *p_signature,
    uint32_t signature_buf_size, uint32_t *p_signature_out_size) const {
  // This API is not required inside of enclaves.
  return SGX_PCE_INTERFACE_UNAVAILABLE;
}

quote3_error_t EnclaveDcapLibraryInterface::QeGetTargetInfo(
    sgx_target_info_t *p_qe_target_info) const {
  return static_cast<quote3_error_t>(
      primitives::enc_untrusted_qe_get_target_info(p_qe_target_info));
}

quote3_error_t EnclaveDcapLibraryInterface::QeGetQuoteSize(
    uint32_t *p_quote_size) const {
  return static_cast<quote3_error_t>(
      primitives::enc_untrusted_qe_get_quote_size(p_quote_size));
}

quote3_error_t EnclaveDcapLibraryInterface::QeGetQuote(
    const sgx_report_t *p_app_report, uint32_t quote_size,
    uint8_t *p_quote) const {
  return static_cast<quote3_error_t>(primitives::enc_untrusted_qe_get_quote(
      p_app_report, quote_size, p_quote));
}

}  // namespace sgx
}  // namespace asylo

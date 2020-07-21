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

#include "asylo/identity/attestation/sgx/internal/host_dcap_library_interface.h"

#include <cstdint>

#include "include/sgx_report.h"
#include "QuoteGeneration/pce_wrapper/inc/sgx_pce.h"
#include "QuoteGeneration/pce_wrapper/inc/sgx_pce_types.h"
#include "QuoteGeneration/quote_wrapper/common/inc/sgx_ql_lib_common.h"
#include "QuoteGeneration/quote_wrapper/ql/inc/sgx_dcap_ql_wrapper.h"
#include "QuoteGeneration/quote_wrapper/quote/inc/sgx_ql_core_wrapper.h"

namespace asylo {
namespace sgx {

quote3_error_t HostDcapLibraryInterface::SetQuoteConfig(
    const sgx_ql_config_t &config) const {
  return sgx_ql_set_quote_config(&config);
}

quote3_error_t HostDcapLibraryInterface::QeSetEnclaveDirpath(
    const char *dirpath) const {
  return sgx_qe_set_enclave_dirpath(dirpath);
}

sgx_pce_error_t HostDcapLibraryInterface::PceGetTarget(
    sgx_target_info_t *p_pce_target, sgx_isv_svn_t *p_pce_isv_svn) const {
  return sgx_pce_get_target(p_pce_target, p_pce_isv_svn);
}

sgx_pce_error_t HostDcapLibraryInterface::GetPceInfo(
    const sgx_report_t *p_report, const uint8_t *p_pek, uint32_t pek_size,
    uint8_t crypto_suite, uint8_t *p_encrypted_ppid,
    uint32_t encrypted_ppid_size, uint32_t *p_encrypted_ppid_out_size,
    sgx_isv_svn_t *p_pce_isvsvn, uint16_t *p_pce_id,
    uint8_t *p_signature_scheme) const {
  return sgx_get_pce_info(p_report, p_pek, pek_size, crypto_suite,
                          p_encrypted_ppid, encrypted_ppid_size,
                          p_encrypted_ppid_out_size, p_pce_isvsvn, p_pce_id,
                          p_signature_scheme);
}

sgx_pce_error_t HostDcapLibraryInterface::PceSignReport(
    const sgx_isv_svn_t *isv_svn, const sgx_cpu_svn_t *cpu_svn,
    const sgx_report_t *p_report, uint8_t *p_signature,
    uint32_t signature_buf_size, uint32_t *p_signature_out_size) const {
  return sgx_pce_sign_report(isv_svn, cpu_svn, p_report, p_signature,
                             signature_buf_size, p_signature_out_size);
}

quote3_error_t HostDcapLibraryInterface::QeGetTargetInfo(
    sgx_target_info_t *p_qe_target_info) const {
  return sgx_qe_get_target_info(p_qe_target_info);
}

quote3_error_t HostDcapLibraryInterface::QeGetQuoteSize(
    uint32_t *p_quote_size) const {
  return sgx_qe_get_quote_size(p_quote_size);
}

quote3_error_t HostDcapLibraryInterface::QeGetQuote(
    const sgx_report_t *p_app_report, uint32_t quote_size,
    uint8_t *p_quote) const {
  return sgx_qe_get_quote(p_app_report, quote_size, p_quote);
}

}  // namespace sgx
}  // namespace asylo

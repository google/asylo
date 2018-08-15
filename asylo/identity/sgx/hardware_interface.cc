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

#include "asylo/identity/sgx/hardware_interface.h"

#include "asylo/util/logging.h"
#include "asylo/identity/sgx/identity_key_management_structs.h"
#include "include/sgx.h"

// The following functions are defined by the Intel SGX SDK. However,
// these are supposed to be internal functions, and are not supposed to
// be invoked by external entities. As a result, the header declaring these
// function is not made visible outside the Intel SGX SDK. Thus, the prototypes
// of these functions are declared below. The "hardware_interface"
// target of the Asylo SDK will closely track the Intel SGX SDK, and
// consequently it is OK to call internal functions from the Intel SGX SDK.
extern "C" {
// Executes the ENCLU[EREPORT] instruction using the |target_info| and
// |report_data| inputs, and writes the output to |report|. Note that the
// sgx_target_info_t, sgx_report_data_t and sgx_report_t are just
// Intel SDK implementations of the TARGETINFO, REPORTDATA, and REPORT
// data types defined in the Intel SDM, and consequently, are compatible
// with the Targetinfo, Reportdata, and Report types defined in the
// Asylo SDK.
void do_ereport(const sgx_target_info_t *target_info,
                const sgx_report_data_t *report_data, sgx_report_t *report);

// Executes the ENCLU[EGETKEY] instruction with the |key_request| input and
// writes the result to |key|. The function returns zero on success or a
// non-zero error code on error. Note that the sgx_keyrequest_t type defined by
// the Intel SGX SDK is an implementation of the KEYREQUEST type defined in the
// Intel SDM, and consequently, it is compatible with the Keyrequest type
// defined by the Asylo SDK. Additionally, sgx_key_128bit_t is just a
// byte-array of 16 bytes, and hence is compatible with the HardwareKey type
// defined by the Asylo SDK.
int do_egetkey(const sgx_key_request_t *key_request, sgx_key_128bit_t *key);
}  // extern "C"

namespace asylo {
namespace sgx {

bool GetHardwareRand64(uint64_t *value) {
  LOG(ERROR) << "This function is not yet implemented.";
  return false;
}

bool GetHardwareKey(const Keyrequest &request, HardwareKey *key) {
  return (do_egetkey(reinterpret_cast<const sgx_key_request_t *>(&request),
                     reinterpret_cast<sgx_key_128bit_t *>(key)) == 0);
}

bool GetHardwareReport(const Targetinfo &tinfo, const Reportdata &reportdata,
                       Report *report) {
  do_ereport(reinterpret_cast<const sgx_target_info_t *>(&tinfo),
             reinterpret_cast<const sgx_report_data_t *>(&reportdata),
             reinterpret_cast<sgx_report_t *>(report));
  return true;
}

}  // namespace sgx
}  // namespace asylo

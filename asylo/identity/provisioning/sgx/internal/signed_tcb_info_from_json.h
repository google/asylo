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

#ifndef ASYLO_IDENTITY_PROVISIONING_SGX_INTERNAL_SIGNED_TCB_INFO_FROM_JSON_H_
#define ASYLO_IDENTITY_PROVISIONING_SGX_INTERNAL_SIGNED_TCB_INFO_FROM_JSON_H_

#include <string>

#include "asylo/identity/provisioning/sgx/internal/sgx_pcs_client.pb.h"
#include "asylo/util/statusor.h"

namespace asylo {
namespace sgx {

// Parses |json_string| into a SignedTcbInfo proto. Returns a non-OK status if
// |json_string| does not match the specification of "TcbInfo" returned by
// Intel's Get TCB Info API (as documented at
// https://api.portal.trustedservices.intel.com/documentation#pcs-tcb-info).
//
// This function does not perform any cryptographic checks on the contents of
// the returned SignedTcbInfo. The caller is responsible for performing
// cryptographic checks needed for verifying the returned SignedTcbInfo
// structure.
StatusOr<SignedTcbInfo> SignedTcbInfoFromJson(const std::string &json_string);

}  // namespace sgx
}  // namespace asylo

#endif  // ASYLO_IDENTITY_PROVISIONING_SGX_INTERNAL_SIGNED_TCB_INFO_FROM_JSON_H_

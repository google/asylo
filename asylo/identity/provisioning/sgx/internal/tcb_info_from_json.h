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

#ifndef ASYLO_IDENTITY_PROVISIONING_SGX_INTERNAL_TCB_INFO_FROM_JSON_H_
#define ASYLO_IDENTITY_PROVISIONING_SGX_INTERNAL_TCB_INFO_FROM_JSON_H_

#include <string>

#include "asylo/identity/provisioning/sgx/internal/tcb.pb.h"
#include "asylo/util/statusor.h"

namespace asylo {
namespace sgx {

// Parses |json_string| into a Tcb proto. If the |json_string| is not a JSON
// string that follows the specification of the "tcb" field of the JSON returned
// by Intel's Get PCK certificates API (as documented at
// https://api.portal.trustedservices.intel.com/documentation#pcs-certificates),
// then TcbFromJson() returns an error.
//
// If unrecognized fields are encountered, then TcbFromJson() logs warnings
// but does not return an error.
StatusOr<Tcb> TcbFromJson(const std::string &json_string);

// Parses |json_string| into a TcbInfo proto. If the |json_string| does not
// match the specification of the "tcbInfo" field of the JSON returned by
// Intel's Get TCB Info API (as documented at
// https://api.portal.trustedservices.intel.com/documentation#pcs-tcb-info),
// then TcbInfoFromJson() returns an error.
//
// Currently, TcbInfoFromJson() only supports TCB info JSON objects with a
// version of 1 or 2.
//
// If unrecognized fields are encountered, then TcbInfoFromJson() logs warnings
// but does not return an error.
//
// If |json_string| contains multiple TCB levels with the same "tcb" and the
// same "status", then they are de-duplicated and a warning is logged. If it
// contains multiple TCB levels with the same "tcb" and different "status"es,
// then an error is returned.
StatusOr<TcbInfo> TcbInfoFromJson(const std::string &json_string);

}  // namespace sgx
}  // namespace asylo

#endif  // ASYLO_IDENTITY_PROVISIONING_SGX_INTERNAL_TCB_INFO_FROM_JSON_H_

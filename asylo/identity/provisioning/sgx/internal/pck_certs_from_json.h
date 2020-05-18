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

#ifndef ASYLO_IDENTITY_PROVISIONING_SGX_INTERNAL_PCK_CERTS_FROM_JSON_H_
#define ASYLO_IDENTITY_PROVISIONING_SGX_INTERNAL_PCK_CERTS_FROM_JSON_H_

#include <string>

#include "asylo/identity/provisioning/sgx/internal/pck_certificates.pb.h"
#include "asylo/util/statusor.h"

namespace asylo {
namespace sgx {

// Parses |json_str| into a PckCertificates proto. Returns an error if
// |json_str| does not match the specification of the "PckCerts" field of the
// JSON returned by Intel's Get PCK Certificates API. See
// https://api.portal.trustedservices.intel.com/documentation#pcs-certificates)
// for more information.
//
// If unrecognized fields are encountered, logs warning but does not return an
// error.
StatusOr<PckCertificates> PckCertificatesFromJson(const std::string &json_str);

}  // namespace sgx
}  // namespace asylo

#endif  // ASYLO_IDENTITY_PROVISIONING_SGX_INTERNAL_PCK_CERTS_FROM_JSON_H_

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

#ifndef ASYLO_IDENTITY_SGX_PCK_CERTIFICATES_H_
#define ASYLO_IDENTITY_SGX_PCK_CERTIFICATES_H_

#include "asylo/identity/sgx/pck_certificates.pb.h"
#include "asylo/util/status.h"

namespace asylo {
namespace sgx {

// Validates a PckCertificates message. Returns an OK status if and only if the
// message is valid.
//
// A PckCertificates message is valid if and only if:
//
//   * Each of its |certs| satisfies the following:
//
//     * Its |tcb_level|, |tcbm|, and |cert| fields are all present.
//     * All of those fields are valid.
//     * The PCE SVNs in its |tcb_level| and |tcbm| are the same.
//
//   * There are no two distinct, unequal |certs| with identical |tcb_level|s or
//     |tcbm|s.
Status ValidatePckCertificates(const PckCertificates &pck_certificates);

}  // namespace sgx
}  // namespace asylo

#endif  // ASYLO_IDENTITY_SGX_PCK_CERTIFICATES_H_

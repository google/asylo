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

#ifndef ASYLO_DAEMON_IDENTITY_ATTESTATION_DOMAIN_H_
#define ASYLO_DAEMON_IDENTITY_ATTESTATION_DOMAIN_H_

#include <string>

#include "asylo/util/statusor.h"

namespace asylo {

// Size of attestation domain name.
constexpr size_t kAttestationDomainNameSize = 16;

// Returns a 16-byte attestation domain that can be used by enclaves to
// determine whether two enclaves belong to the same local attestation domain.
// Two enclaves belong to the same local attestation domain if they have the
// same attestation-domain name. Enclaves belonging to the same local
// attestation domain can use the cheaper, symmetric-key-based local attestation
// to verify each other's identity.
//
// Note that the attestation domain value may change per boot.
StatusOr<std::string> GetAttestationDomain();

}  // namespace asylo

#endif  // ASYLO_DAEMON_IDENTITY_ATTESTATION_DOMAIN_H_

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

#ifndef ASYLO_GRPC_AUTH_CORE_EKEP_HANDSHAKER_UTIL_H_
#define ASYLO_GRPC_AUTH_CORE_EKEP_HANDSHAKER_UTIL_H_

#include <string>
#include <vector>

#include "asylo/identity/attestation/enclave_assertion_generator.h"
#include "asylo/identity/attestation/enclave_assertion_verifier.h"
#include "asylo/identity/identity.pb.h"
#include "asylo/util/status.h"

namespace asylo {

// Configuration options for an EKEP handshake. These options can be validated
// by calling Validate(). See the comment above Validate() for restrictions on
// field values.
struct EkepHandshakerOptions {
  // The maximum frame size supported by the EKEP participant.
  size_t max_frame_size = 1 << 20;

  // Assertions offered by the EKEP participant.
  std::vector<AssertionDescription> self_assertions;

  // Peer assertions accepted by the EKEP participant.
  std::vector<AssertionDescription> accepted_peer_assertions;

  // Additional data presented by the EKEP participant during the handshake.
  std::string additional_authenticated_data;

  // Validates the handshaker options. All of the following conditions must
  // hold, otherwise returns INVALID_ARGUMENT:
  //   * max_frame_size is non-zero and does not exceed
  //   EkepHandshaker::kFrameSizeLimit
  //   * self_assertions is non-empty
  //   * For each assertion description in self_assertions, there is an
  //   appropriate assertion-generation library available
  //   * accepted_peer_assertions is non-empty
  //   * For each assertion description in accepted_peer_assertions, there is an
  //   appropriate assertion-verification library available
  //   * The size of additional_authenticated_data is less than or equal to
  //   max_frame_size
  Status Validate() const;
};

// Returns a pointer to the EnclaveAssertionGenerator corresponding to identity
// type |description|.identity_type() and authority type
// |description|.authority_type() from the AssertionGenerator static map, or
// nullptr if such a generator does not exist.
const EnclaveAssertionGenerator *GetEnclaveAssertionGenerator(
    const AssertionDescription &description);

// Returns a pointer to the EnclaveAssertionVerifier corresponding to identity
// type |description|.identity_type() and authority type
// |description|.authority_type() from the AssertionVerifier static map, or
// nullptr if such a verifier does not exist.
const EnclaveAssertionVerifier *GetEnclaveAssertionVerifier(
    const AssertionDescription &description);

// Searches |list| for the given |description| and, if found, returns an
// iterator to the element. Return a past-the-end iterator if |description| is
// not found.
std::vector<AssertionDescription>::const_iterator FindAssertionDescription(
    const std::vector<AssertionDescription> &list,
    const AssertionDescription &description);

// Creates a unique EKEP context blob consisting of |public_key| and
// |transcript_hash| and writes it to |ekep_context|. Returns true on success.
bool MakeEkepContextBlob(const std::string &public_key,
                         const std::string &transcript_hash,
                         std::string *ekep_context);

}  // namespace asylo

#endif  // ASYLO_GRPC_AUTH_CORE_EKEP_HANDSHAKER_UTIL_H_

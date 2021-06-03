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

#include "asylo/grpc/auth/core/ekep_handshaker_util.h"

#include <google/protobuf/util/message_differencer.h>
#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "asylo/grpc/auth/core/ekep_handshaker.h"
#include "asylo/identity/attestation/enclave_assertion_generator.h"
#include "asylo/identity/attestation/enclave_assertion_verifier.h"
#include "asylo/identity/enclave_assertion_authority.h"
#include "asylo/util/status.h"

namespace asylo {

const EnclaveAssertionGenerator *GetEnclaveAssertionGenerator(
    const AssertionDescription &description) {
  std::string authority_id =
      EnclaveAssertionAuthority::GenerateAuthorityId(
          description.identity_type(), description.authority_type())
          .value();
  auto it = AssertionGeneratorMap::GetValue(authority_id);
  return (it == AssertionGeneratorMap::value_end()) ? nullptr : &*it;
}

const EnclaveAssertionVerifier *GetEnclaveAssertionVerifier(
    const AssertionDescription &description) {
  std::string authority_id =
      EnclaveAssertionAuthority::GenerateAuthorityId(
          description.identity_type(), description.authority_type())
          .value();
  auto it = AssertionVerifierMap::GetValue(authority_id);
  return (it == AssertionVerifierMap::value_end()) ? nullptr : &*it;
}

Status EkepHandshakerOptions::Validate() const {
  if (max_frame_size > EkepHandshaker::kFrameSizeLimit) {
    return absl::InvalidArgumentError(absl::StrCat(
        "max_frame_size cannot exceed ", EkepHandshaker::kFrameSizeLimit));
  }

  if (additional_authenticated_data.size() > max_frame_size) {
    return absl::InvalidArgumentError(
        "additional_authenticated_data size cannot be more than "
        "max_frame_size");
  }

  if (self_assertions.empty()) {
    return absl::InvalidArgumentError(
        "Must supply at least one self assertion");
  }
  if (accepted_peer_assertions.empty()) {
    return absl::InvalidArgumentError(
        "Must supply at least one accepted peer assertion");
  }

  for (const AssertionDescription &description : self_assertions) {
    StatusOr<std::string> authority_id_result =
        EnclaveAssertionAuthority::GenerateAuthorityId(
            description.identity_type(), description.authority_type());
    if (!authority_id_result.ok()) {
      return absl::InternalError("Failed to generate authority id");
    }

    std::string authority_id = authority_id_result.value();
    if (AssertionGeneratorMap::GetValue(authority_id) ==
        AssertionGeneratorMap::value_end()) {
      return absl::InvalidArgumentError(absl::StrCat(
          "Could not find EnclaveAssertionGenerator library for: {",
          description.ShortDebugString(), "}"));
    }
  }

  for (const AssertionDescription &description : accepted_peer_assertions) {
    StatusOr<std::string> authority_id_result =
        EnclaveAssertionAuthority::GenerateAuthorityId(
            description.identity_type(), description.authority_type());
    if (!authority_id_result.ok()) {
      return absl::InternalError("Failed to generate authority id");
    }

    std::string authority_id = authority_id_result.value();
    if (AssertionVerifierMap::GetValue(authority_id) ==
        AssertionVerifierMap::value_end()) {
      return absl::InvalidArgumentError(
          absl::StrCat("Could not find EnclaveAssertionVerifier library for: {",
                       description.ShortDebugString(), "}"));
    }
  }

  return absl::OkStatus();
}

std::vector<AssertionDescription>::const_iterator FindAssertionDescription(
    const std::vector<AssertionDescription> &list,
    const AssertionDescription &description) {
  return std::find_if(list.cbegin(), list.cend(),
                      [&description](const AssertionDescription &desc) -> bool {
                        return google::protobuf::util::MessageDifferencer::Equals(
                            desc, description);
                      });
}

bool MakeEkepContextBlob(const std::string &public_key,
                         const std::string &transcript_hash,
                         std::string *ekep_context) {
  return SerializeByteContainers(ekep_context, public_key, transcript_hash)
      .ok();
}

}  // namespace asylo

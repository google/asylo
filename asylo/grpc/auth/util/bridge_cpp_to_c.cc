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

#include "asylo/grpc/auth/util/bridge_cpp_to_c.h"

#include <cstdint>
#include <cstdlib>

#include "asylo/grpc/auth/core/assertion_description.h"
#include "asylo/identity/assertion_description_util.h"

namespace asylo {
namespace {

// Copies the description in |src| to a corresponding C structure in |dest|. The
// input description |dest| must have already been initialized.
void FromAssertionDescription(const AssertionDescription &src,
                              assertion_description *dest) {
  assertion_description_free(dest);
  assertion_description_assign(static_cast<int32_t>(src.identity_type()),
                               src.authority_type().data(),
                               src.authority_type().size(), dest);
}

// Copies the list in |src| to a corresponding C structure in |dest|. The input
// array in |dest| must have already been initialized.
void CopyAssertionDescriptions(const AssertionDescriptionHashSet &src,
                               assertion_description_array *dest) {
  assertion_description_array_free(dest);
  assertion_description_array_init(/*count=*/src.size(), dest);
  size_t i = 0;
  for (const AssertionDescription &assertion_description : src) {
    FromAssertionDescription(assertion_description, &dest->descriptions[i]);
    ++i;
  }
}

}  // namespace

void CopyEnclaveCredentialsOptions(const EnclaveCredentialsOptions &src,
                                   grpc_enclave_credentials_options *dest) {
  grpc_enclave_credentials_options_destroy(dest);
  CopyAssertionDescriptions(src.self_assertions, &dest->self_assertions);
  CopyAssertionDescriptions(src.accepted_peer_assertions,
                            &dest->accepted_peer_assertions);
  if (!src.additional_authenticated_data.empty()) {
    safe_string_assign(&dest->additional_authenticated_data,
                       src.additional_authenticated_data.size(),
                       src.additional_authenticated_data.data());
  }

  dest->peer_acl = src.peer_acl;
}

}  // namespace asylo

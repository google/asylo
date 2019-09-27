/*
 *
 * Copyright 2018 Asylo authors
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
#include "asylo/grpc/auth/enclave_credentials_options.h"

#include "asylo/identity/identity_acl.pb.h"

namespace asylo {
namespace {

IdentityAclPredicate CombineIdentityAclPredicates(
    const IdentityAclPredicate &lhs, const IdentityAclPredicate &rhs) {
  IdentityAclPredicate combined;
  IdentityAclGroup *combined_group = combined.mutable_acl_group();
  combined_group->set_type(IdentityAclGroup::OR);
  *combined_group->add_predicates() = lhs;
  *combined_group->add_predicates() = rhs;
  return combined;
}

}  // namespace

EnclaveCredentialsOptions &EnclaveCredentialsOptions::Add(
    const EnclaveCredentialsOptions &additional) {
  self_assertions.insert(additional.self_assertions.begin(),
                         additional.self_assertions.end());
  accepted_peer_assertions.insert(additional.accepted_peer_assertions.begin(),
                                  additional.accepted_peer_assertions.end());
  if (additional.peer_acl.has_value()) {
    if (peer_acl.has_value()) {
      peer_acl = CombineIdentityAclPredicates(peer_acl.value(),
                                              additional.peer_acl.value());
    } else {
      peer_acl = additional.peer_acl;
    }
  }

  return *this;
}

}  // namespace asylo

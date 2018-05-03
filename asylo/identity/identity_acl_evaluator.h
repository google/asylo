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

#ifndef ASYLO_IDENTITY_IDENTITY_ACL_EVALUATOR_H_
#define ASYLO_IDENTITY_IDENTITY_ACL_EVALUATOR_H_

#include "asylo/identity/identity.pb.h"
#include "asylo/identity/identity_acl.pb.h"
#include "asylo/identity/identity_expectation_matcher.h"
#include "asylo/util/statusor.h"

namespace asylo {

// Uses |matcher| to evaluate whether |identities| satisfies |acl|. Returns a
// non-OK status if |acl| is malformed or if |matcher|.Match() returns a non-OK
// status when invoked with any of |identities|.
//
// An IdentityAclPredicate is a recursive proto, each layer of which must
// conform to the following constraints:
//  - A nested IdentityAclPredicate |predicate| must have |predicate|.item set.
//  - A nested IdentityAclGroup |group| must have a non-empty
//    |group|.predicates.
//     - If |group|.type is GroupType::NOT, |group|.predicates must contain
//       exactly one predicate.
StatusOr<bool> EvaluateIdentityAcl(
    const std::vector<EnclaveIdentity> &identities,
    const IdentityAclPredicate &acl, const IdentityExpectationMatcher &matcher);

}  // namespace asylo

#endif  // ASYLO_IDENTITY_IDENTITY_ACL_EVALUATOR_H_

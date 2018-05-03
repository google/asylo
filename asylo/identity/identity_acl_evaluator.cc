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

#include "asylo/identity/identity_acl_evaluator.h"

#include <google/protobuf/repeated_field.h>
#include "absl/strings/str_cat.h"
#include "asylo/util/status.h"

namespace asylo {
namespace {

using google::protobuf::RepeatedPtrField;

// Uses |matcher| to evaluate |predicates| and returns true if any predicates
// are fulfilled by |identities|.
StatusOr<bool> EvaluateAclOrPredicateGroup(
    const std::vector<EnclaveIdentity> &identities,
    const RepeatedPtrField<IdentityAclPredicate> &predicates,
    const IdentityExpectationMatcher &matcher) {
  for (const IdentityAclPredicate &predicate : predicates) {
    const StatusOr<bool> result =
        EvaluateIdentityAcl(identities, predicate, matcher);
    if (!result.ok()) {
      return result;
    }

    if (result.ValueOrDie()) {
      return true;
    }
  }

  return false;
}

// Uses |matcher| to evaluate |predicates| and returns true if all predicates
// are fulfilled by |identities|.
StatusOr<bool> EvaluateAclAndPredicateGroup(
    const std::vector<EnclaveIdentity> &identities,
    const RepeatedPtrField<IdentityAclPredicate> &predicates,
    const IdentityExpectationMatcher &matcher) {
  for (const IdentityAclPredicate &predicate : predicates) {
    const StatusOr<bool> result =
        EvaluateIdentityAcl(identities, predicate, matcher);
    if (!result.ok()) {
      return result;
    }

    if (!result.ValueOrDie()) {
      return false;
    }
  }

  return true;
}

// Uses |matcher| to evaluate |predicates| and returns true if no predicates are
// fulfilled by |identities|. |predicates| must have exactly one element.
StatusOr<bool> EvaluateAclNotPredicateGroup(
    const std::vector<EnclaveIdentity> &identities,
    const RepeatedPtrField<IdentityAclPredicate> &predicates,
    const IdentityExpectationMatcher &matcher) {
  if (predicates.size() != 1) {
    return Status(error::GoogleError::INVALID_ARGUMENT,
                  "NOT predicate groups must have exactly one element");
  }

  const StatusOr<bool> result =
      EvaluateIdentityAcl(identities, predicates[0], matcher);
  if (!result.ok()) {
    return result;
  }

  return !result.ValueOrDie();
}

// Uses |matcher| to evaluate whether |acl_group| is fulfilled by |identities|.
StatusOr<bool> EvaluateAclPredicateGroup(
    const std::vector<EnclaveIdentity> &identities,
    const IdentityAclGroup &acl_group,
    const IdentityExpectationMatcher &matcher) {
  const RepeatedPtrField<IdentityAclPredicate> &predicates =
      acl_group.predicates();

  if (predicates.empty()) {
    return Status(error::GoogleError::INVALID_ARGUMENT,
                  "ACL predicate groups cannot be empty");
  }

  switch (acl_group.type()) {
    case IdentityAclGroup::OR:
      return EvaluateAclOrPredicateGroup(identities, predicates, matcher);
    case IdentityAclGroup::AND:
      return EvaluateAclAndPredicateGroup(identities, predicates, matcher);
    case IdentityAclGroup::NOT:
      return EvaluateAclNotPredicateGroup(identities, predicates, matcher);
    default:
      return Status(error::GoogleError::INVALID_ARGUMENT,
                    absl::StrCat("Unknown acl_group type: ", acl_group.type()));
  }
}

// Uses |matcher| to evaluate |expectation| and returns true if any |identities|
// match it.
StatusOr<bool> EvaluateAclExpectation(
    const std::vector<EnclaveIdentity> &identities,
    const EnclaveIdentityExpectation &expectation,
    const IdentityExpectationMatcher &matcher) {
  for (const EnclaveIdentity &identity : identities) {
    const StatusOr<bool> result = matcher.Match(identity, expectation);
    if (!result.ok()) {
      return result;
    }

    if (result.ValueOrDie()) {
      return true;
    }
  }

  return false;
}

}  // namespace

StatusOr<bool> EvaluateIdentityAcl(
    const std::vector<EnclaveIdentity> &identities,
    const IdentityAclPredicate &acl,
    const IdentityExpectationMatcher &matcher) {
  switch (acl.item_case()) {
    case IdentityAclPredicate::kAclGroup:
      return EvaluateAclPredicateGroup(identities, acl.acl_group(), matcher);
    case IdentityAclPredicate::kExpectation:
      return EvaluateAclExpectation(identities, acl.expectation(), matcher);
    case IdentityAclPredicate::ITEM_NOT_SET:
      return Status(
          error::GoogleError::INVALID_ARGUMENT,
          "Invalid ACL predicate: must be either a group or an expectation.");
    default:
      return Status(error::GoogleError::INVALID_ARGUMENT,
                    absl::StrCat("Unknown acl item: ", acl.item_case()));
  }
}

}  // namespace asylo

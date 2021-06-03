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

#include <string>
#include <utility>
#include <vector>

#include <google/protobuf/repeated_field.h>
#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_format.h"
#include "absl/strings/str_join.h"
#include "asylo/util/status.h"

namespace asylo {
namespace {

using google::protobuf::RepeatedPtrField;

// String used to separate individual explanations in an accumulation of
// explanation strings.
constexpr char kSeparator[] = "\n  ";

// Implements the core logic of EvaluateIdentityAcl. This function is invoked
// recursively by its leaf functions so it must be forward-declared.
StatusOr<bool> EvaluateIdentityAclImpl(
    const std::vector<EnclaveIdentity> &identities,
    const IdentityAclPredicate &acl, const IdentityExpectationMatcher &matcher,
    std::string *explanation);

// Uses |matcher| to evaluate |predicates| and returns true if any predicates
// are fulfilled by |identities|.
StatusOr<bool> EvaluateAclOrPredicateGroup(
    const std::vector<EnclaveIdentity> &identities,
    const RepeatedPtrField<IdentityAclPredicate> &predicates,
    const IdentityExpectationMatcher &matcher, std::string *explanation) {
  // Collect explanation strings from all predicate matches. Either all of the
  // predicates fail, in which case all of the explanation strings are returned,
  // or at least one of the predicates succeed, in which case no explanation is
  // returned.
  std::vector<std::string> explanations;
  for (const IdentityAclPredicate &predicate : predicates) {
    std::string local_explanation;
    const StatusOr<bool> result = EvaluateIdentityAclImpl(
        identities, predicate, matcher, &local_explanation);
    if (!result.ok()) {
      return result;
    }

    if (result.value()) {
      return true;
    }

    if (!local_explanation.empty()) {
      explanations.push_back(std::move(local_explanation));
    }
  }

  // The OR predicate was not satisfied. Return an accumulation of the
  // explanation strings.
  if (explanation != nullptr) {
    *explanation = absl::StrJoin(explanations, kSeparator);
  }

  return false;
}

// Uses |matcher| to evaluate |predicates| and returns true if all predicates
// are fulfilled by |identities|.
StatusOr<bool> EvaluateAclAndPredicateGroup(
    const std::vector<EnclaveIdentity> &identities,
    const RepeatedPtrField<IdentityAclPredicate> &predicates,
    const IdentityExpectationMatcher &matcher, std::string *explanation) {
  // Collect explanation strings from all predicate matches.
  std::vector<std::string> explanations;
  bool match_result = true;
  for (const IdentityAclPredicate &predicate : predicates) {
    std::string local_explanation;
    const StatusOr<bool> result = EvaluateIdentityAclImpl(
        identities, predicate, matcher, &local_explanation);
    if (!result.ok()) {
      return result;
    }

    match_result &= result.value();

    if (!local_explanation.empty()) {
      explanations.push_back(std::move(local_explanation));
    }
  }

  // Return without setting |explanation| if the AND predicate was satisfied.
  if (match_result) {
    return true;
  }

  // The AND predicated was not satisfied. Return an accumulation of the
  // explanation strings.
  if (explanation != nullptr) {
    *explanation = absl::StrJoin(explanations, kSeparator);
  }

  return false;
}

// Uses |matcher| to evaluate |predicates| and returns true if no predicates are
// fulfilled by |identities|. |predicates| must have exactly one element.
StatusOr<bool> EvaluateAclNotPredicateGroup(
    const std::vector<EnclaveIdentity> &identities,
    const RepeatedPtrField<IdentityAclPredicate> &predicates,
    const IdentityExpectationMatcher &matcher, std::string *explanation) {
  if (predicates.size() != 1) {
    return absl::InvalidArgumentError(
        "NOT predicate groups must have exactly one element");
  }

  // Don't pass an explanation parameter to this call because the NOT group
  // takes the inverse of the result.
  const StatusOr<bool> result = EvaluateIdentityAclImpl(
      identities, predicates[0], matcher, /*explanation=*/nullptr);
  if (!result.ok()) {
    return result;
  }

  if (result.value() && explanation != nullptr) {
    *explanation = "NOT predicate was satisfied when it should not have been";
  }

  return !result.value();
}

// Uses |matcher| to evaluate whether |acl_group| is fulfilled by |identities|.
StatusOr<bool> EvaluateAclPredicateGroup(
    const std::vector<EnclaveIdentity> &identities,
    const IdentityAclGroup &acl_group,
    const IdentityExpectationMatcher &matcher, std::string *explanation) {
  const RepeatedPtrField<IdentityAclPredicate> &predicates =
      acl_group.predicates();

  if (predicates.empty()) {
    return absl::InvalidArgumentError("ACL predicate groups cannot be empty");
  }

  switch (acl_group.type()) {
    case IdentityAclGroup::OR:
      return EvaluateAclOrPredicateGroup(identities, predicates, matcher,
                                         explanation);
    case IdentityAclGroup::AND:
      return EvaluateAclAndPredicateGroup(identities, predicates, matcher,
                                          explanation);
    case IdentityAclGroup::NOT:
      return EvaluateAclNotPredicateGroup(identities, predicates, matcher,
                                          explanation);
    default:
      return absl::InvalidArgumentError(
          absl::StrCat("Unknown acl_group type: ", acl_group.type()));
  }
}

// Uses |matcher| to evaluate |expectation| and returns true if any |identities|
// match it.
StatusOr<bool> EvaluateAclExpectation(
    const std::vector<EnclaveIdentity> &identities,
    const EnclaveIdentityExpectation &expectation,
    const IdentityExpectationMatcher &matcher, std::string *explanation) {
  std::vector<std::string> explanations;
  for (const EnclaveIdentity &identity : identities) {
    std::string local_explanation;
    const StatusOr<bool> result =
        matcher.MatchAndExplain(identity, expectation, &local_explanation);
    if (!result.ok()) {
      return result;
    }

    if (result.value()) {
      return true;
    }

    if (!local_explanation.empty()) {
      explanations.push_back(std::move(local_explanation));
    }
  }

  // No identities satisfied the predicates. Return an accumulation of the
  // explanation strings.
  if (explanation != nullptr) {
    *explanation = absl::StrJoin(explanations, kSeparator);
  }

  return false;
}

StatusOr<bool> EvaluateIdentityAclImpl(
    const std::vector<EnclaveIdentity> &identities,
    const IdentityAclPredicate &acl, const IdentityExpectationMatcher &matcher,
    std::string *explanation) {
  switch (acl.item_case()) {
    case IdentityAclPredicate::kAclGroup:
      return EvaluateAclPredicateGroup(identities, acl.acl_group(), matcher,
                                       explanation);
    case IdentityAclPredicate::kExpectation:
      return EvaluateAclExpectation(identities, acl.expectation(), matcher,
                                    explanation);
    case IdentityAclPredicate::ITEM_NOT_SET:
      return absl::InvalidArgumentError(
          "Invalid ACL predicate: must be either a group or an expectation.");
    default:
      return absl::InvalidArgumentError(
          absl::StrCat("Unknown acl item: ", acl.item_case()));
  }
}

}  // namespace

StatusOr<bool> EvaluateIdentityAcl(
    const std::vector<EnclaveIdentity> &identities,
    const IdentityAclPredicate &acl, const IdentityExpectationMatcher &matcher,
    std::string *explanation) {
  auto result = EvaluateIdentityAclImpl(identities, acl, matcher, explanation);
  if (result.ok() && explanation != nullptr && !explanation->empty()) {
    *explanation =
        absl::StrCat("ACL failed to match:", kSeparator, *explanation);
  }
  return result;
}

}  // namespace asylo

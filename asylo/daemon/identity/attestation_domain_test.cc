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

#include "asylo/daemon/identity/attestation_domain.h"

#include <string>
#include <vector>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "asylo/test/util/status_matchers.h"

namespace asylo {
namespace {

constexpr int kLoops = 10;

using ::testing::Each;
using ::testing::Eq;
using ::testing::SizeIs;

TEST(AttestationDomainTest, AttestationDomainHasCorrectSize) {
  EXPECT_THAT(GetAttestationDomain(),
              IsOkAndHolds(SizeIs(kAttestationDomainNameSize)));
}

TEST(AttestationDomainTest, AttestationDomainIsDeterministic) {
  std::vector<std::string> results;
  results.reserve(kLoops);
  for (int i = 0; i < kLoops; ++i) {
    std::string attestation_domain;
    ASYLO_ASSERT_OK_AND_ASSIGN(attestation_domain, GetAttestationDomain());
    results.push_back(attestation_domain);
  }

  EXPECT_THAT(results, Each(Eq(results[0])));
}

}  // namespace
}  // namespace asylo

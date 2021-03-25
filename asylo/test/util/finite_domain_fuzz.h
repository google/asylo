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

#ifndef ASYLO_TEST_UTIL_FINITE_DOMAIN_FUZZ_H_
#define ASYLO_TEST_UTIL_FINITE_DOMAIN_FUZZ_H_

#include <gmock/gmock.h>
#include "absl/random/random.h"
#include "absl/types/optional.h"

namespace asylo {

using ::testing::MakePolymorphicMatcher;
using ::testing::PolymorphicMatcher;

// Custom matcher for testing that a predefined domain maps exactly to
// a predefined range.
template <typename Domain, typename Range>
class FiniteDomainMatcher {
 public:
  void DescribeTo(std::ostream* os) const {
    *os << "function maps given input to output";
  }
  void DescribeNegationTo(std::ostream* os) const {
    *os << "function maps every given input to something other than the "
           "given output";
  }
  bool MatchAndExplain(
      const absl::optional<std::vector<std::pair<Domain, Range>>>& input,
      ::testing::MatchResultListener* result_listener) const {
    if (!input) {
      *result_listener << "No input given";
      return false;
    }
    bool success(true);
    for (auto pair : *input) {
      auto in = pair.first;
      auto out = pair.second;
      auto actual = f_(in);
      if (actual != out) {
        *result_listener << "Input was: " << in << ", Expected" << out
                         << ", Actual" << actual;
        success = false;
        break;
      }
    }
    return success;
  }
  explicit FiniteDomainMatcher(const std::function<Range(Domain)>& f) : f_(f) {}

 private:
  const std::function<Range(Domain)> f_;
};

template <typename Domain, typename Range>
PolymorphicMatcher<FiniteDomainMatcher<Domain, Range>> IsFiniteRestrictionOf(
    const std::function<Range(Domain)>& f) {
  return MakePolymorphicMatcher(FiniteDomainMatcher<Domain, Range>(f));
}

template <typename Domain, typename Range>
PolymorphicMatcher<FiniteDomainMatcher<Domain, Range>> IsFiniteRestrictionOf(
    const std::function<Range(Domain, bool)>& f) {
  std::function<Range(Domain)> bound =
      std::bind(f, std::placeholders::_1, false);
  return MakePolymorphicMatcher(FiniteDomainMatcher<Domain, Range>(bound));
}

template <typename T, typename U>
absl::optional<std::vector<std::pair<T, U>>> zip(const std::vector<T>& ts,
                                                 const std::vector<U>& us) {
  if (ts.size() != us.size()) {
    return absl::nullopt;
  }
  std::vector<std::pair<T, U>> pairs;
  int result_size = us.size();
  for (int i = 0; i < result_size; i++) {
    pairs.push_back(std::make_pair(ts[i], us[i]));
  }
  return pairs;
}

template <typename T>
absl::optional<std::vector<std::pair<int, T>>> FuzzFiniteFunction(
    const std::vector<int>& input, const std::vector<T>& output,
    int iter_bound) {
  auto all_cases = zip(input, output);
  if (!all_cases) {
    return all_cases;
  }
  // Test that elements not in defined range return nullopt
  auto begin = input.begin();
  auto end = input.end();

  absl::BitGen bit_gen;
  // Every number 0 through iter_bound which is not defined input
  for (int i = 0; i < iter_bound; i++) {
    if (find(begin, end, i) == end) {
      all_cases->push_back(std::make_pair(i, absl::nullopt));
    }
    int rand_int =
        absl::Uniform<int>(absl::IntervalClosed, bit_gen, INT_MIN, INT_MAX);
    if (find(begin, end, rand_int) == end) {
      all_cases->push_back(std::make_pair(rand_int, absl::nullopt));
    }
  }
  return all_cases;
}

absl::optional<std::vector<std::pair<int64_t, absl::optional<int64_t>>>>
FuzzBitsetTranslationFunction(
    const std::vector<int64_t>& input,
    const std::vector<absl::optional<int64_t>>& output, int iter_bound);

}  // namespace asylo

#endif  // ASYLO_TEST_UTIL_FINITE_DOMAIN_FUZZ_H_

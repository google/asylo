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

#include "asylo/test/util/finite_domain_fuzz.h"

#include <utility>

#include <gmock/gmock.h>
#include "absl/random/random.h"
#include "absl/strings/str_format.h"
#include "absl/types/optional.h"
#include "asylo/util/logging.h"

namespace asylo {

// An integer with exactly one randomly chosen bit set. It will never
// pick most significant bit, as overflow behavior is sometimes
// surprising.
//
// Bitsets in signed integers require careful attention to the
// representational limits of ints. The range of an int is
// [-2^(sizeof(int) * 8 - 1), 2^(sizeof(int) * 8 - 1) - 1]. Therefore
// the amount of positive flags values is sizeof(int) * 8 - 2 to avoid
// signed integer overflow.
int random_flag(absl::BitGen& bit_gen) {
  // Pick a random bit index
  int index = absl::Uniform<int>(absl::IntervalClosed, bit_gen, 0,
                                 (sizeof(int) * 8) - 2);
  return 1 << index;
}

absl::optional<std::vector<std::pair<int64_t, absl::optional<int64_t>>>>
FuzzBitsetTranslationFunction(
    const std::vector<int64_t> &input,
    const std::vector<absl::optional<int64_t>> &output, int iter_bound) {
  auto all_cases_pairs = zip(input, output);
  if (!all_cases_pairs) {
    return all_cases_pairs;
  }
  std::map<int64_t, absl::optional<int64_t>> all_cases(all_cases_pairs->begin(),
                                                       all_cases_pairs->end());
  all_cases[0] = 0;

  absl::BitGen bit_gen;
  // Grab multiple random flags at the same time
  for (int i = 0; i < iter_bound; i++) {
    // Test multiple flags in the defined domain
    int in = 0;
    absl::optional<int> out = 0;
    for (int j = 0; j < input.size(); j++) {
      if (absl::Bernoulli(bit_gen, 0.5)) {
        in |= input[j];
        *out |= *output[j];
      }
      auto insert_result = all_cases.insert({in, out});
      CHECK(insert_result.second || insert_result.first->second == out)
          << "Input " << in << " is mapped to both "
          << *insert_result.first->second << " and " << *out << ".";
    }
    // Test multiple flags in and outside the defined domain
    in = 0;
    out = 0;
    for (int j = 0; j < sizeof(int64_t) * 8 / 8; j++) {
      int flag = random_flag(bit_gen);
      auto found = std::find(input.begin(), input.end(), flag);
      size_t index = found - input.begin();
      // If flag is not in input, then OR it in without a translated
      // output counterpart.
      if (found == input.end()) {
        in |= flag;
        // A single invalid input bit means the output is not valid.
        out = absl::nullopt;
      } else {
        in |= input[index];
        if (out) {
          out = *out | *output[index];
        }
      }
    }
    auto insert_result = all_cases.insert({in, out});
    CHECK(insert_result.second || insert_result.first->second == out)
        << "Input " << in << " is mapped to both "
        << *insert_result.first->second << " and " << *out << ".";
  }
  return std::vector<std::pair<int64_t, absl::optional<int64_t>>>{
      all_cases.begin(), all_cases.end()};
}

}  // namespace asylo

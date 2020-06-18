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

#include <gmock/gmock.h>
#include "absl/types/optional.h"

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
int random_flag() {
  // Pick a random bit index
  int index = rand()%(sizeof(int) * 8 - 1);
  return 1 << index;
}

absl::optional<std::vector<std::pair<int64_t, int64_t>>>
FuzzBitsetTranslationFunction(const std::vector<int64_t>& input,
                              const std::vector<int64_t>& output,
                              int iter_bound) {
  auto all_cases = zip(input, output);
  if (!all_cases) {
    return all_cases;
  }
  all_cases->push_back(std::make_pair(0, 0));

  // Grab multiple random flags at the same time
  size_t size = input.size();
  auto begin = input.begin();
  auto end = input.end();
  for (int i = 0; i < iter_bound; i++) {
    // Test multiple flags in the defined domain
    int in = 0;
    int out = 0;
    for (int j = 0; j < size; j++) {
      if (rand()%2) {
        in |= input[j];
        out |= output[j];
      }
      all_cases->push_back(std::make_pair(in, out));
    }

    // Test multiple flags in and outside the defined domain
    in = 0;
    out = 0;
    for (int j = 0; j < sizeof(int64_t) * 8; j++) {
      int flag = random_flag();
      auto found = std::find(begin, end, flag);
      size_t index = found - begin;
      // If flag is not in input, then OR it in without a translated
      // output counterpart.
      if (found == end) {
        in |= flag;
      } else {
        in |= input[index];
        out |= output[index];
      }
    }
    all_cases->push_back(std::make_pair(in, out));
  }
  return all_cases;
}

}  // namespace asylo

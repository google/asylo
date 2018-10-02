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

// A program to attempt to perform some calculations based on the Collatz
// conjecture. This program exists so that the ElfReader test has an example ELF
// file to read. This program is not intended to be run as part of any actual
// component or test of Asylo.
//
// If you do run this program, you should know that it is not expected to
// terminate naturally for at least 5,000 years (or possible ever, if the
// Collatz conjecture is false), so you may want to grab a cup of coffee while
// you wait.

#include <cstdint>
#include <iostream>
#include <limits>

namespace {

// The largest value of N (a uint64_t) for which the calculation 3 * N + 1 does
// not overflow.
constexpr uint64_t kMaxOddBeforeOverflow =
    std::numeric_limits<uint64_t>::max() / 3;

// If |number| is odd, returns 3 * number + 1. Otherwise, returns number / 2. If
// the calculation would overflow, retunrs 0.
uint64_t NextHailstoneNumber(uint64_t number) {
  if (number % 2 == 1) {
    if (number <= kMaxOddBeforeOverflow) {
      return 3 * number + 1;
    } else {
      return 0;
    }
  } else {
    return number / 2;
  }
}

}  // namespace

int main() {
  uint64_t start_number;
  uint64_t current_number;
  uint64_t num_steps_to_one;

  for (start_number = 1; start_number != 0; ++start_number) {
    num_steps_to_one = 0;

    for (current_number = start_number; current_number > 1;
         current_number = NextHailstoneNumber(current_number)) {
      ++num_steps_to_one;
    }

    if (current_number == 1) {
      std::cout << start_number << " takes " << num_steps_to_one
                << " iterations to reach 1" << std::endl;
    } else {
      std::cerr << "Overflow would have occurred in iterating from "
                << start_number << std::endl;
    }
  }

  return 0;
}

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

#ifndef ASYLO_TEST_UTIL_STATUSOR_TEST_UTIL_H_
#define ASYLO_TEST_UTIL_STATUSOR_TEST_UTIL_H_

#include <ostream>

#include <gtest/gtest.h>
#include "asylo/util/statusor.h"

namespace asylo {

// Implements the PrintTo() method for asylo::StatusOr<T>. This method is
// used by gtest to print asylo::StatusOr<T> objects for debugging. The
// implementation relies on gtest for printing values of T when a
// asylo::StatusOr<T> object is OK and contains a value.
template <typename T>
void PrintTo(const StatusOr<T> &statusor, std::ostream *os) {
  if (!statusor.ok()) {
    *os << statusor.status();
  } else {
    *os << ::testing::PrintToString(statusor.ValueOrDie());
  }
}

}  // namespace asylo

#endif  // ASYLO_TEST_UTIL_STATUSOR_TEST_UTIL_H_

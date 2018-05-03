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

// This file implements bit-wise AND, equality, and inequality operations
// for BitVector128 protobuf.

#include "asylo/identity/util/bit_vector_128_util.h"

#include <google/protobuf/util/message_differencer.h>
#include "asylo/identity/util/bit_vector_128.pb.h"

namespace asylo {

BitVector128 operator&(const BitVector128 &left, const BitVector128 &right) {
  BitVector128 result;

  result.set_low(left.low() & right.low());

  result.set_high(left.high() & right.high());

  return result;
}

bool operator==(const BitVector128 &left, const BitVector128 &right) {
  return ::google::protobuf::util::MessageDifferencer::Equivalent(left, right);
}

bool operator!=(const BitVector128 &left, const BitVector128 &right) {
  return (!(left == right));
}

}  // namespace asylo

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
// for Attributes protobuf.

#include "asylo/identity/sgx/attributes_util.h"

#include <google/protobuf/util/message_differencer.h>
#include "asylo/identity/sgx/attributes.pb.h"

namespace asylo {
namespace sgx {

Attributes operator&(const Attributes &left, const Attributes &right) {
  Attributes result;
  result.set_flags(left.flags() & right.flags());
  result.set_xfrm(left.xfrm() & right.xfrm());
  return result;
}

bool operator==(const Attributes &left, const Attributes &right) {
  return ::google::protobuf::util::MessageDifferencer::Equivalent(left, right);
}

bool operator!=(const Attributes &left, const Attributes &right) {
  return (!(left == right));
}

}  // namespace sgx
}  // namespace asylo

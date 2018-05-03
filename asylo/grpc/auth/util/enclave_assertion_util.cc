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

#include "asylo/grpc/auth/util/enclave_assertion_util.h"

#include <cstdint>
#include <cstdlib>

namespace asylo {

void CopyAssertionDescriptions(
    const std::vector<AssertionDescription> &src,
    assertion_description_array *dest) {
  assertion_description_array_init(/*count=*/src.size(), dest);
  for (size_t i = 0; i < src.size(); ++i) {
    assertion_description_array_assign_at(
        /*index=*/i,
        static_cast<int32_t>(src[i].identity_type()),
        src[i].authority_type().data(),
        src[i].authority_type().size(),
        dest);
  }
}

}  // namespace asylo

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

#ifndef ASYLO_PLATFORM_PRIMITIVES_SGX_SGX_ERROR_SPACE_H_
#define ASYLO_PLATFORM_PRIMITIVES_SGX_SGX_ERROR_SPACE_H_

#include "asylo/util/status.h"
#include "include/sgx_error.h"

namespace asylo {
namespace error {

// Implementation of the ErrorSpace interface for the sgx_status_t enum.
class SgxErrorSpace : public ErrorSpaceImplementationHelper<SgxErrorSpace> {
 public:
  using code_type = sgx_status_t;

  SgxErrorSpace(const SgxErrorSpace &) = delete;
  SgxErrorSpace &operator=(const SgxErrorSpace &) = delete;

  // Returns a singleton instance of SgxErrorSpace.
  static ErrorSpace const *GetInstance();

 private:
  SgxErrorSpace();
};

// Returns a singleton instance of the ErrorSpace implementation corresponding
// to the sgx_status_t enum.
ErrorSpace const *GetErrorSpace(ErrorSpaceAdlTag<sgx_status_t> tag);

}  // namespace error
}  // namespace asylo

#endif  // ASYLO_PLATFORM_PRIMITIVES_SGX_SGX_ERROR_SPACE_H_

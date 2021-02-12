/*
 * Copyright 2021 Asylo authors
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
 */

#include "asylo/platform/primitives/sgx/sgx_errors.h"

#include "absl/strings/string_view.h"
#include "asylo/platform/primitives/sgx/sgx_error_space.h"
#include "asylo/util/status.h"
#include "include/sgx_error.h"

namespace asylo {

Status SgxError(sgx_status_t sgx_status, absl::string_view message) {
  return Status(sgx_status, message);
}

sgx_status_t GetSgxErrorCode(const Status &status) {
  if (status.error_space() == error::SgxErrorSpace::GetInstance()) {
    return static_cast<sgx_status_t>(status.raw_code());
  }
  return SGX_SUCCESS;
}

}  // namespace asylo

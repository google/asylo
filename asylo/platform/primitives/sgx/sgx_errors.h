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

#ifndef ASYLO_PLATFORM_PRIMITIVES_SGX_SGX_ERRORS_H_
#define ASYLO_PLATFORM_PRIMITIVES_SGX_SGX_ERRORS_H_

#include <string>

#include "absl/strings/string_view.h"
#include "asylo/util/status.h"
#include "include/sgx_error.h"

namespace asylo {

// Returns a human-readable description of an SGX status.
std::string DescribeSgxStatus(sgx_status_t sgx_status);

// Returns a Status representing an SGX error. If |sgx_status| is SGX_SUCCESS,
// SgxError() returns an OK status.
//
// Callers should not rely on how SgxError() embeds error information in the
// returned Status. Instead, callers can use GetSgxErrorCode() to inspect a
// Status for SGX error information.
//
// However, callers may rely on stability in the mapping between SGX error codes
// and absl::StatusCodes.
Status SgxError(sgx_status_t sgx_status, absl::string_view message);

// Returns the SGX error code that a Status represents, or SGX_SUCCESS if the
// Status does not represent an SGX error.
sgx_status_t GetSgxErrorCode(const Status &status);

}  // namespace asylo

#endif  // ASYLO_PLATFORM_PRIMITIVES_SGX_SGX_ERRORS_H_

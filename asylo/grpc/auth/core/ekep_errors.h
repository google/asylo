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

#ifndef ASYLO_GRPC_AUTH_CORE_EKEP_ERRORS_H_
#define ASYLO_GRPC_AUTH_CORE_EKEP_ERRORS_H_

#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "asylo/grpc/auth/core/handshake.pb.h"
#include "asylo/util/status.h"

namespace asylo {

// Returns a Status representing an EKEP abort error.
//
// Callers should not rely on how EkepError() embeds error information in the
// returned Status. Instead, callers can use GetEkepErrorCode() to inspect a
// Status for EKEP error information.
//
// However, callers may rely on stability in the mapping between EKEP abort
// error codes and absl::StatusCodes.
Status EkepError(Abort_ErrorCode code, absl::string_view message);

// Returns the EKEP error code that a Status represents, or absl::nullopt if the
// Status does not represent an EKEP error.
absl::optional<Abort_ErrorCode> GetEkepErrorCode(const Status &status);

}  // namespace asylo

#endif  // ASYLO_GRPC_AUTH_CORE_EKEP_ERRORS_H_

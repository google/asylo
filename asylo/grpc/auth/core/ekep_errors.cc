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

#include "asylo/grpc/auth/core/ekep_errors.h"

#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "asylo/grpc/auth/core/ekep_error_space.h"
#include "asylo/grpc/auth/core/handshake.pb.h"
#include "asylo/util/status.h"

namespace asylo {

Status EkepError(Abort_ErrorCode code, absl::string_view message) {
  return Status(code, message);
}

absl::optional<Abort_ErrorCode> GetEkepErrorCode(const Status &status) {
  if (status.error_space() == EkepErrorSpace::GetInstance()) {
    return static_cast<Abort_ErrorCode>(status.raw_code());
  }
  return absl::nullopt;
}

}  // namespace asylo

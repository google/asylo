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

#include <string>

#include "absl/status/status.h"
#include "absl/strings/cord.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "asylo/grpc/auth/core/handshake.pb.h"
#include "asylo/util/status.h"
#include "asylo/util/status_helpers.h"

namespace asylo {

Status EkepError(Abort_ErrorCode code, absl::string_view message) {
  Status status = absl::InternalError(message);
  Abort abort;
  abort.set_code(code);
  SetProtoPayload(abort, status);
  return status;
}

absl::optional<Abort_ErrorCode> GetEkepErrorCode(const Status &status) {
  absl::optional<Abort> abort = GetProtoPayload<Abort>(status);
  if (!abort.has_value()) {
    return absl::nullopt;
  }
  return abort->code();
}

}  // namespace asylo

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

#ifndef ASYLO_GRPC_AUTH_CORE_EKEP_ERROR_MATCHERS_H_
#define ASYLO_GRPC_AUTH_CORE_EKEP_ERROR_MATCHERS_H_

#include "asylo/grpc/auth/core/handshake.pb.h"
#include "asylo/test/util/status_matchers.h"

namespace asylo {

// Matches a Status-like object that contains the given EKEP abort code.
PolymorphicStatusMatcherType EkepErrorIs(Abort_ErrorCode code);

}  // namespace asylo

#endif  // ASYLO_GRPC_AUTH_CORE_EKEP_ERROR_MATCHERS_H_

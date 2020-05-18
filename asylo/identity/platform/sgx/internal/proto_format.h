/*
 *
 * Copyright 2018 Asylo authors
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

#ifndef ASYLO_IDENTITY_PLATFORM_SGX_INTERNAL_PROTO_FORMAT_H_
#define ASYLO_IDENTITY_PLATFORM_SGX_INTERNAL_PROTO_FORMAT_H_

#include <string>

#include "asylo/identity/platform/sgx/code_identity.pb.h"

namespace asylo {
namespace sgx {

// Returns a formatted string containing a human-understandable representation
// of the given proto. The string is the same as the one returned by
// google::protobuf::Message::DebugString(), but with the following changes to improve
// readability:
//   * All Sha256HashProto.hash() fields are hex-encoded.
//   * All Attributes messages are presented as lists of ATTRIBUTES bit names.
//   * All CpuSvn.value() fields are hex-encoded.
std::string FormatProto(const google::protobuf::Message &message);

}  // namespace sgx
}  // namespace asylo

#endif  // ASYLO_IDENTITY_PLATFORM_SGX_INTERNAL_PROTO_FORMAT_H_

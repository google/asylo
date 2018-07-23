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

#ifndef ASYLO_GRPC_AUTH_CORE_EKEP_ERROR_SPACE_H_
#define ASYLO_GRPC_AUTH_CORE_EKEP_ERROR_SPACE_H_

#include "asylo/grpc/auth/core/handshake.pb.h"
#include "asylo/util/status.h"

namespace asylo {
namespace error {

// Returns a singleton instance of the ErrorSpace implementation corresponding
// to the asylo::Abort_ErrorCode enum.
ErrorSpace const *GetErrorSpace(ErrorSpaceAdlTag<Abort_ErrorCode> tag);

}  // namespace error

// Implementation of the ErrorSpace interface for the Abort_ErrorCode enum used
// in the Enclave Key Exchange Protocol.
class EkepErrorSpace
    : public asylo::error::ErrorSpaceImplementationHelper<EkepErrorSpace> {
 public:
  using code_type = Abort_ErrorCode;

  EkepErrorSpace(const EkepErrorSpace &other) = delete;
  EkepErrorSpace &operator=(const EkepErrorSpace &other) = delete;
  virtual ~EkepErrorSpace() = default;

  // Returns a singleton instance of EkepErrorSpace.
  static const ErrorSpace *GetInstance();

 private:
  EkepErrorSpace();
};

}  // namespace asylo

#endif  // ASYLO_GRPC_AUTH_CORE_EKEP_ERROR_SPACE_H_

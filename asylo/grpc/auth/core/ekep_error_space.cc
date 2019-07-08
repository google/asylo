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

#include "asylo/grpc/auth/core/ekep_error_space.h"

namespace asylo {
namespace error {

ErrorSpace const *GetErrorSpace(ErrorSpaceAdlTag<Abort_ErrorCode> tag) {
  return EkepErrorSpace::GetInstance();
}

}  // namespace error

const asylo::error::ErrorSpace *EkepErrorSpace::GetInstance() {
  static const asylo::error::ErrorSpace *instance = new EkepErrorSpace();
  return instance;
}

EkepErrorSpace::EkepErrorSpace()
    : asylo::error::ErrorSpaceImplementationHelper<EkepErrorSpace>(
          "::asylo::error::EkepErrorSpace") {
  // EKEP Abort errors are propagated via protocol messages. They should not be
  // used outside of the core EKEP implementation. Consequently, each Abort
  // error code is mapped to the INTERNAL code from the canonical error space.
  AddTranslationMapEntry(Abort::BAD_MESSAGE, "Bad message received from peer",
                         asylo::error::GoogleError::INTERNAL);
  AddTranslationMapEntry(Abort::DESERIALIZATION_FAILED,
                         "Frame deserialization failed",
                         asylo::error::GoogleError::INTERNAL);
  AddTranslationMapEntry(Abort::BAD_PROTOCOL_VERSION, "Bad protocol version",
                         asylo::error::GoogleError::INTERNAL);
  AddTranslationMapEntry(Abort::BAD_HANDSHAKE_CIPHER, "Bad ciphersuite",
                         asylo::error::GoogleError::INTERNAL);
  AddTranslationMapEntry(Abort::BAD_RECORD_PROTOCOL, "Bad record protocol",
                         asylo::error::GoogleError::INTERNAL);
  AddTranslationMapEntry(Abort::BAD_AUTHENTICATOR, "Bad authenticator",
                         asylo::error::GoogleError::INTERNAL);
  AddTranslationMapEntry(Abort::BAD_ASSERTION_TYPE, "Bad assertion type",
                         asylo::error::GoogleError::INTERNAL);
  AddTranslationMapEntry(Abort::BAD_ASSERTION, "Bad assertion",
                         asylo::error::GoogleError::INTERNAL);
  AddTranslationMapEntry(Abort::PROTOCOL_ERROR, "Protocol error",
                         asylo::error::GoogleError::INTERNAL);
  AddTranslationMapEntry(Abort::INTERNAL_ERROR, "Internal error",
                         asylo::error::GoogleError::INTERNAL);
}

}  // namespace asylo

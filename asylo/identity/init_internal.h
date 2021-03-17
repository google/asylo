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

#ifndef ASYLO_IDENTITY_INIT_INTERNAL_H_
#define ASYLO_IDENTITY_INIT_INTERNAL_H_

#include <string>

#include "absl/status/status.h"
#include "asylo/util/logging.h"
#include "asylo/util/status.h"

namespace asylo {
namespace internal {

// Attempts to initialize |authority| with |config|, if |authority| is not
// already initialized. Returns an ok status if the authority is successfully
// initialized at the end of the call. Logs any initialization errors that
// occur.
template <class IteratorT>
Status TryInitialize(const std::string &config, IteratorT authority_it) {
  if (authority_it->IsInitialized()) {
    return absl::OkStatus();
  }

  Status status = authority_it->Initialize(config);
  if (!status.ok()) {
    LOG(ERROR) << status;
  }

  return status;
}

}  // namespace internal
}  // namespace asylo

#endif  // ASYLO_IDENTITY_INIT_INTERNAL_H_

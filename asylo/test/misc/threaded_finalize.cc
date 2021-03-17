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

#include <pthread.h>
#include <unistd.h>

#include "absl/status/status.h"
#include "asylo/enclave.pb.h"
#include "asylo/trusted_application.h"
#include "asylo/util/status.h"

namespace asylo {

void *finalizer_function(void *arg) { return arg; }

void *sleeping_finalizer_function(void *arg) {
  constexpr uint kSleepSeconds = 5;
  sleep(kSleepSeconds);
  return arg;
}

// An enclave that uses threads in its finalize function.
class ThreadedFinalize : public TrustedApplication {
 public:
  Status Finalize(const EnclaveFinal &input) override {
    pthread_t thread;
    int ret = pthread_create(&thread, nullptr, finalizer_function, nullptr);
    if (ret != 0) {
      return absl::InternalError("Unable to pthread_create");
    }

    ret = pthread_join(thread, nullptr);
    if (ret != 0) {
      return absl::InternalError("Unable to pthread_join");
    }

    ret =
        pthread_create(&thread, nullptr, sleeping_finalizer_function, nullptr);
    if (ret != 0) {
      return absl::InternalError("Unable to pthread_create");
    }

    ret = pthread_detach(thread);
    if (ret != 0) {
      return absl::InternalError("Unable to pthread_detach");
    }

    return absl::OkStatus();
  }
};

TrustedApplication *BuildTrustedApplication() { return new ThreadedFinalize(); }

}  // namespace asylo

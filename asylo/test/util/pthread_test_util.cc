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

#include "asylo/test/util/pthread_test_util.h"

#include <openssl/mem.h>
#include <pthread.h>

#include <cstdint>
#include <cstdio>
#include <memory>

#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "asylo/util/status_macros.h"

namespace asylo {

void BusyWork() {
  constexpr int kBufferSize = 4096;

  // OPENSSL_cleanse is a good candidate for an expensive operation because it
  // performs a loop that is not performance-optimized in any way (for security
  // reasons).
  uint8_t buf[kBufferSize];
  OPENSSL_cleanse(buf, kBufferSize);
}

Heartbeat::Heartbeat(int periodms):periodms_(periodms), canceled_(false) {}

Status Heartbeat::Create() {
    int ret = pthread_create(&thread_, nullptr, Heartbeat::run, this);
    if (ret != 0) {
      return absl::InternalError(
          absl::StrCat("Failed to create heartbeat thread: ", ret));
    }
    return OkStatus();
  }

void* Heartbeat::run(void* arg) {
  Heartbeat* self = reinterpret_cast<Heartbeat*>(arg);
  while (!self->canceled_) {
    LOG(INFO) << "heartbeat";
    usleep(self->periodms_);
  }
  return nullptr;
}

void Heartbeat::Stop() {
  canceled_ = true;
  pthread_join(thread_, nullptr);
}

StatusOr<std::unique_ptr<Heartbeat>> LaunchHeartbeat(int periodms) {
  auto heartbeat = absl::make_unique<Heartbeat>(periodms);
  ASYLO_RETURN_IF_ERROR(heartbeat->Create());
  return StatusOr<std::unique_ptr<Heartbeat>>(std::move(heartbeat));
}


Status LaunchThreads(const int numThreads, void *(*start_routine)(void *),
                     void *arg, std::vector<pthread_t> *threads) {
  for (int i = 0; i < numThreads; ++i) {
    pthread_t new_thread;
    int ret = pthread_create(&new_thread, nullptr, start_routine, arg);
    if (ret != 0) {
      return absl::InternalError(
          absl::StrCat("Failed to create thread: ", ret));
    }
    threads->emplace_back(new_thread);
  }

  return absl::OkStatus();
}

Status JoinThreads(const std::vector<pthread_t> &threads) {
  for (int i = 0; i < threads.size(); ++i) {
    int ret = pthread_join(threads[i], nullptr);
    if (ret != 0) {
      return absl::InternalError(absl::StrCat("Failed to join thread: ", ret));
    }
  }

  return absl::OkStatus();
}

Status CheckInRange(const int value, absl::string_view debug_name,
                    const int min_allowed, const int max_allowed) {
  if (value < min_allowed || value > max_allowed) {
    return absl::FailedPreconditionError(
        absl::StrCat("illegal value of ", debug_name, ": currently ", value,
                     "; must be in range ", min_allowed, "-", max_allowed));
  }
  return absl::OkStatus();
}

}  // namespace asylo

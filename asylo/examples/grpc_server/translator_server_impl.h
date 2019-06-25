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

#ifndef ASYLO_EXAMPLES_GRPC_SERVER_TRANSLATOR_SERVER_IMPL_H_
#define ASYLO_EXAMPLES_GRPC_SERVER_TRANSLATOR_SERVER_IMPL_H_

#include <string>

#include "absl/base/thread_annotations.h"
#include "absl/container/flat_hash_map.h"
#include "absl/synchronization/mutex.h"
#include "absl/synchronization/notification.h"
#include "asylo/examples/grpc_server/translator_server.grpc.pb.h"
#include "include/grpcpp/grpcpp.h"
#include "include/grpcpp/server.h"

namespace examples {
namespace grpc_server {

class TranslatorServerImpl final : public Translator::Service {
 public:
  explicit TranslatorServerImpl(absl::Notification *shutdown_requested);

 private:
  ::grpc::Status GetTranslation(::grpc::ServerContext *context,
                                const GetTranslationRequest *query,
                                GetTranslationResponse *response) override;

  ::grpc::Status Shutdown(::grpc::ServerContext *context,
                          const ShutdownRequest *query,
                          ShutdownResponse *response)
      LOCKS_EXCLUDED(shutdown_requested_mutex_) override;

  // A map from words to their translations.
  absl::flat_hash_map<std::string, std::string> translation_map_;

  // A mutex to guard shutdown_requested_, in order to ensure that it only gets
  // notified once.
  absl::Mutex shutdown_requested_mutex_;

  // A flag to set to trigger the shutdown of the enclave.
  absl::Notification *shutdown_requested_ GUARDED_BY(shutdown_requested_mutex_);
};

}  // namespace grpc_server
}  // namespace examples

#endif  // ASYLO_EXAMPLES_GRPC_SERVER_TRANSLATOR_SERVER_IMPL_H_

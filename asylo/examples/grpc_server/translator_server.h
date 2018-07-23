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

#ifndef ASYLO_EXAMPLES_GRPC_SERVER_TRANSLATOR_SERVER_H_
#define ASYLO_EXAMPLES_GRPC_SERVER_TRANSLATOR_SERVER_H_

#include <unordered_map>

#include "grpc_server/translator_server.grpc.pb.h"
#include "include/grpcpp/grpcpp.h"
#include "include/grpcpp/server.h"

namespace examples {
namespace grpc_server {

class TranslatorServer final : public Translator::Service {
 public:
  TranslatorServer();

 private:
  ::grpc::Status GetTranslation(::grpc::ServerContext *context,
                                const GetTranslationRequest *query,
                                GetTranslationResponse *response) override;

  // A map from words to their translations.
  std::unordered_map<std::string, std::string> translation_map_;
};

}  // namespace grpc_server
}  // namespace examples

#endif  // ASYLO_EXAMPLES_GRPC_SERVER_TRANSLATOR_SERVER_H_

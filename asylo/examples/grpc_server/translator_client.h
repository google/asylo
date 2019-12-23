/*
 *
 * Copyright 2019 Asylo authors
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

#ifndef ASYLO_EXAMPLES_GRPC_SERVER_TRANSLATOR_CLIENT_H_
#define ASYLO_EXAMPLES_GRPC_SERVER_TRANSLATOR_CLIENT_H_

#include <memory>
#include <string>

#include "absl/strings/string_view.h"
#include "asylo/examples/grpc_server/translator_server.grpc.pb.h"
#include "asylo/examples/grpc_server/translator_server.pb.h"
#include "asylo/util/status.h"
#include "asylo/util/statusor.h"
#include "include/grpcpp/grpcpp.h"

namespace examples {
namespace grpc_server {

// A gRPC client connected to a TranslationServer. Can only be instantiated
// by the factory method TranslatorClient::Create.
class TranslatorClient {
 public:
  // Factory method that returns a client connected to a TranslatorServer
  // at |address|. In case of error, returns a non-OK status.
  static asylo::StatusOr<std::unique_ptr<TranslatorClient>> Create(
      absl::string_view address);

  // Non-copyable, non-movable.
  TranslatorClient(const TranslatorClient &other) = delete;
  TranslatorClient &operator=(const TranslatorClient &other) = delete;
  TranslatorClient(TranslatorClient &&other) = delete;
  TranslatorClient &operator=(TranslatorClient &&other) = delete;

  // Makes a GetTranslation RPC for |word_to_translate| to the server and
  // returns the translated word on success, or a non-OK Status if the RPC
  // fails.
  asylo::StatusOr<std::string> GrpcGetTranslation(
      absl::string_view word_to_translate);

 private:
  explicit TranslatorClient(std::unique_ptr<Translator::Stub> stub)
      : stub_(std::move(stub)) {}

  std::unique_ptr<Translator::Stub> stub_;
};

}  // namespace grpc_server
}  // namespace examples

#endif  // ASYLO_EXAMPLES_GRPC_SERVER_TRANSLATOR_CLIENT_H_

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

#ifndef ASYLO_TEST_GRPC_MESSENGER_SERVER_IMPL_H_
#define ASYLO_TEST_GRPC_MESSENGER_SERVER_IMPL_H_

#include <type_traits>

#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "asylo/test/grpc/service.grpc.pb.h"
#include "include/grpcpp/grpcpp.h"

namespace asylo {
namespace test {

template <typename T>
class MessengerServer : public T::Service {
 public:
  static std::string ResponseString(absl::string_view name) {
    return absl::StrCat("Hello ", name, ", I am ", T::service_full_name());
  }

 private:
  ::grpc::Status Hello(::grpc::ServerContext *context,
                       const HelloRequest *request,
                       HelloResponse *response) override {
    static_assert(
        std::is_same<T, Messenger1>::value ||
            std::is_same<T, Messenger2>::value ||
            std::is_same<T, Messenger3>::value,
        "Template parameter T must be Messenger1, Messenger2, or Messenger3");

    if (request->name().empty()) {
      return ::grpc::Status(::grpc::StatusCode::INVALID_ARGUMENT,
                            "Name cannot be empty");
    }
    response->set_message(ResponseString(request->name()));
    return ::grpc::Status::OK;
  }
};

using MessengerServer1 = MessengerServer<Messenger1>;
using MessengerServer2 = MessengerServer<Messenger2>;
using MessengerServer3 = MessengerServer<Messenger3>;

}  // namespace test
}  // namespace asylo

#endif  // ASYLO_TEST_GRPC_MESSENGER_SERVER_IMPL_H_

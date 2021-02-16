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

#ifndef ASYLO_TEST_GRPC_MESSENGER_CLIENT_IMPL_H_
#define ASYLO_TEST_GRPC_MESSENGER_CLIENT_IMPL_H_

#include <memory>
#include <string>
#include <type_traits>

#include "asylo/util/logging.h"
#include "asylo/test/grpc/service.grpc.pb.h"
#include "asylo/util/status.h"
#include "asylo/util/status_helpers.h"
#include "asylo/util/statusor.h"
#include "include/grpcpp/grpcpp.h"

namespace asylo {
namespace test {

template <typename T>
class MessengerClient {
 public:
  static_assert(
      std::is_same<T, Messenger1>::value ||
          std::is_same<T, Messenger2>::value ||
          std::is_same<T, Messenger3>::value,
      "Template parameter T must be Messenger1, Messenger2, or Messenger3");

  MessengerClient(const std::shared_ptr<::grpc::ChannelInterface> &channel)
      : stub_{T::NewStub(channel, ::grpc::StubOptions())} {}

  StatusOr<std::string> Hello(const std::string &name) {
    ::grpc::ClientContext client_context;

    HelloRequest request;
    request.set_name(name);

    HelloResponse response;

    // Send the request to the server. This is a blocking call.
    ::grpc::Status grpc_status =
        stub_->Hello(&client_context, request, &response);
    if (!grpc_status.ok()) {
      return ConvertStatus<asylo::Status>(grpc_status);
    }
    LOG(INFO) << "Response from server: " << response.message();

    return response.message();
  }

 private:
  std::unique_ptr<typename T::Stub> stub_;
};

using MessengerClient1 = MessengerClient<Messenger1>;
using MessengerClient2 = MessengerClient<Messenger2>;
using MessengerClient3 = MessengerClient<Messenger3>;

}  // namespace test
}  // namespace asylo

#endif  // ASYLO_TEST_GRPC_MESSENGER_CLIENT_IMPL_H_

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

#include <memory>
#include <string>

#include "absl/time/time.h"
#include "asylo/enclave.pb.h"
#include "asylo/grpc/auth/enclave_channel_credentials.h"
#include "asylo/grpc/auth/sgx_local_credentials_options.h"
#include "asylo/test/grpc/client_enclave.pb.h"
#include "asylo/test/grpc/messenger_client_impl.h"
#include "asylo/trusted_application.h"
#include "asylo/util/status.h"
#include "include/grpc/impl/codegen/gpr_types.h"
#include "include/grpc/support/time.h"

namespace asylo {

const int64_t kDeadlineMicros = absl::Seconds(10) / absl::Microseconds(1);

// An enclave that makes RPCs to a MessengerServer. Uses SGX local attestation
// to connect to an enclave hosting a MessengerServer.
class ClientEnclave : public TrustedApplication {
 public:
  Status Run(const EnclaveInput &input, EnclaveOutput *output) override {
    if (!input.HasExtension(server_address)) {
      return Status(error::GoogleError::INVALID_ARGUMENT,
                    "Input missing server_address extension");
    }
    if (!input.HasExtension(rpc_input)) {
      return Status(error::GoogleError::INVALID_ARGUMENT,
                    "Input missing rpc_input extension");
    }

    const std::string &address = input.GetExtension(server_address);

    std::shared_ptr<::grpc::ChannelCredentials> channel_credentials =
        EnclaveChannelCredentials(BidirectionalSgxLocalCredentialsOptions());

    // Connect a gRPC channel to the server specified in the input.
    std::shared_ptr<::grpc::Channel> channel =
        ::grpc::CreateChannel(address, channel_credentials);
    test::MessengerClient1 client(channel);
    gpr_timespec absolute_deadline =
        gpr_time_add(gpr_now(GPR_CLOCK_REALTIME),
                     gpr_time_from_micros(kDeadlineMicros, GPR_TIMESPAN));
    if (!channel->WaitForConnected(absolute_deadline)) {
      return Status(error::GoogleError::INTERNAL,
                    "Failed to connect to server");
    }

    // Make an RPC to the server and output the response.
    StatusOr<std::string> result = client.Hello(input.GetExtension(rpc_input));
    if (!result.ok()) {
      return result.status();
    }
    output->SetExtension(rpc_result, result.ValueOrDie());
    return Status::OkStatus();
  }
};

TrustedApplication *BuildTrustedApplication() { return new ClientEnclave(); }

}  // namespace asylo

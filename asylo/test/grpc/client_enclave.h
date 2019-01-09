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

#ifndef ASYLO_TEST_GRPC_CLIENT_ENCLAVE_H_
#define ASYLO_TEST_GRPC_CLIENT_ENCLAVE_H_

#include "asylo/enclave.pb.h"
#include "asylo/trusted_application.h"
#include "asylo/util/status.h"

namespace asylo {

// An enclave that makes RPCs to a MessengerServer.
class ClientEnclave : public TrustedApplication {
 public:
  // This method expects a ClientEnclaveInput proto extension in |input|. Makes
  // an RPC to the MessengerServer running at the address specified in |input|.
  // It uses the credentials configuration and connection deadline specified in
  // |input| to form the channel. The RPC result is returned through a
  // |rpc_result| extension in |output|.
  Status Run(const EnclaveInput &input, EnclaveOutput *output) override;
};

}  // namespace asylo

#endif  // ASYLO_TEST_GRPC_CLIENT_ENCLAVE_H_

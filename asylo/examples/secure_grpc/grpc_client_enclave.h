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

#ifndef ASYLO_EXAMPLES_SECURE_GRPC_GRPC_CLIENT_ENCLAVE_H_
#define ASYLO_EXAMPLES_SECURE_GRPC_GRPC_CLIENT_ENCLAVE_H_

#include <memory>
#include <string>

#include "asylo/enclave.pb.h"
#include "asylo/trusted_application.h"
#include "asylo/util/status.h"

namespace examples {
namespace secure_grpc {

// An enclave that makes RPCs to a MessengerServer.
class GrpcClientEnclave : public asylo::TrustedApplication {
 public:
  // This method expects a GrpcClientEnclaveInput proto extension in |input|.
  //
  // Makes an RPC to the TranslatorServer running at the address specified in
  // |input|.  It uses the connection deadline specified in |input| to form the
  // channel. The RPC result is returned through a |rpc_result| extension in
  // |output|.
  asylo::Status Run(const asylo::EnclaveInput &input,
                    asylo::EnclaveOutput *output) override;
};

}  // namespace secure_grpc
}  // namespace examples

#endif  // ASYLO_EXAMPLES_SECURE_GRPC_GRPC_CLIENT_ENCLAVE_H_

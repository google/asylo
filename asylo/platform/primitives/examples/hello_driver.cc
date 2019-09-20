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

#include <iostream>
#include <string>

#include "absl/flags/parse.h"
#include "asylo/platform/primitives/examples/hello_enclave.h"
#include "asylo/platform/primitives/extent.h"
#include "asylo/platform/primitives/test/test_backend.h"
#include "asylo/platform/primitives/untrusted_primitives.h"
#include "asylo/platform/primitives/util/dispatch_table.h"
#include "asylo/platform/primitives/util/message.h"

namespace asylo {
namespace primitives {

// When the enclave asks for it, send "Hello".
Status hello_handler(std::shared_ptr<Client> client, void *context,
                     MessageReader *in, MessageWriter *out) {
  ASYLO_RETURN_IF_READER_NOT_EMPTY(*in);

  // Push our message on to the MessageWriter to pass to the enclave
  out->PushString("Hello");
  return Status::OkStatus();
}

Status call_enclave() {
  // Trusted code must exit the enclave to interact with untrusted
  // components like the host operating system. In the Asylo
  // primitives model this is accomplished via "exit handlers," where
  // an exit handler is a callback installed by the client to
  // implement an untrusted service. In this example, the client loads the
  // enclave with an empty table of exit handlers and then adds a trivial
  // callback function "exit_handler" to service the exit type specified by the
  // selector "kExitHandler."
  std::shared_ptr<Client> client =
      test::TestBackend::Get()->LoadTestEnclaveOrDie(
          /*enclave_name=*/"hello_test", absl::make_unique<DispatchTable>());

  auto status = client->exit_call_provider()->RegisterExitHandler(
      kExternalHelloHandler, ExitHandler{hello_handler});

  MessageReader out;
  status = client->EnclaveCall(kHelloEnclaveSelector, nullptr, &out);
  if (status.ok()) {
    if (out.size() != 1) {
      std::cerr << "Incorrect output parameters received" << std::endl;
    } else {
      std::cerr << out.next().As<char>() << std::endl;
    }
  } else {
    std::cerr << status.ToString() << std::endl;
  }
  return Status::OkStatus();
}

}  // namespace primitives
}  // namespace asylo

int main(int argc, char *argv[]) {
  absl::ParseCommandLine(argc, argv);
  auto status = ::asylo::primitives::call_enclave();
  std::cout << status.ToString() << std::endl;
  return 0;
}

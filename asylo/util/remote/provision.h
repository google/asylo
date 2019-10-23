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

#ifndef ASYLO_UTIL_REMOTE_PROVISION_H_
#define ASYLO_UTIL_REMOTE_PROVISION_H_

#include <cstdint>
#include <memory>
#include <string>

#include "absl/strings/string_view.h"
#include "asylo/util/statusor.h"

namespace asylo {

// Interface to provision remote proxy server process for the remote backend.
// When remote proxy client load an enclave, it must locate or launch a process
// where |RemoteProxyServer| would reside. An instance of |RemoteProvision|
// class would do that. Note that it must outlive the client, to make sure
// |Finalize| is not called too early, when RemoteProvision object is
// destructed. Specific implementation is provided by Instantiate call below.
class RemoteProvision {
 public:
  virtual ~RemoteProvision() = default;

  // Locates or launches remote proxy server process to load the actual Enclave.
  // Parameters:
  // - client_port - port opened by the remote proxy client, which proxy server
  //   will need to connect to.
  // - enclave_path - path to the enclave
  // Returns path to the enclave which will be accessible by the proxy server
  //   (same as enclave_path, if the server runs on the same machine), or status
  //   in case of any error.
  //
  // This action is provision-specific; two distinct examples are provided with
  // asylo/util/remote:local_provision and asylo/util/remote:remote_provision.
  virtual StatusOr<std::string> Provision(int32_t client_port,
                                          absl::string_view enclave_path) = 0;

  // Finalizes the remote proxy server process one the loaded enclave is
  // terminated (or fails to load). It should be safe to call Finalize more than
  // once: Finalize is expected to be called when the remote client shuts down,
  // but if something goes wrong, it might still be called by |RemoteProvision|
  // implementation destructor.
  virtual void Finalize() = 0;

  // Generates an instance of specific RemoteProvision implementation.
  // Current model mandates identical implementation to be used by all
  // remote clients in the application, and creates a new instance to be
  // owned by the client, when it loads.
  static std::unique_ptr<RemoteProvision> Instantiate();
};

}  // namespace asylo

#endif  // ASYLO_UTIL_REMOTE_PROVISION_H_

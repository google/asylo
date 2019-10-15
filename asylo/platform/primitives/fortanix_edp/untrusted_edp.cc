/*
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
 */

#include "asylo/platform/primitives/fortanix_edp/untrusted_edp.h"

#include <unistd.h>

#include <cstddef>
#include <cstdlib>
#include <memory>
#include <utility>

#include "absl/base/call_once.h"
#include "absl/memory/memory.h"
#include "absl/strings/str_cat.h"
#include "asylo/platform/primitives/extent.h"
#include "asylo/platform/primitives/primitive_status.h"
#include "asylo/platform/primitives/primitives.h"
#include "asylo/platform/primitives/untrusted_primitives.h"
#include "asylo/platform/primitives/util/message.h"
#include "asylo/platform/primitives/util/status_conversions.h"
#include "asylo/util/cleanup.h"
#include "asylo/util/status.h"
#include "asylo/util/status_macros.h"
#include "asylo/util/statusor.h"

namespace asylo {
namespace primitives {

#ifdef _CFG_EDP_
namespace {

  extern "C" uint64_t fortanix_edp_load_enclave(const char* path, void** enclave, unsigned char* err, size_t err_size);

  extern "C" void fortanix_edp_free_enclave(void* enclave);

  extern "C" uint64_t fortanix_edp_enclave_call(
      void* enclave,
      uint64_t selector,
      const unsigned char* input,
      size_t input_size,
      unsigned char** output,
      size_t* output_size,
      unsigned char* err,
      size_t err_size);

  extern "C" void fortanix_edp_free_output_buffer(unsigned char* output, size_t output_size);

} // namespace
#else
namespace {

  uint64_t fortanix_edp_load_enclave(const char* path, void** enclave, unsigned char* err, size_t err_size) {
    std::cout << "\nYou need to specify --config=edp when compiling with bazel\n\n";
    return 1;
  }

  void fortanix_edp_free_enclave(void* enclave) { }

  uint64_t fortanix_edp_enclave_call(
      void* enclave,
      uint64_t selector,
      const unsigned char* input,
      size_t input_size,
      unsigned char** output,
      size_t* output_size,
      unsigned char* err,
      size_t err_size) {
    return 1;
  }

  void fortanix_edp_free_output_buffer(unsigned char* output, size_t output_size) { }

} // namespace
#endif // _CFG_EDP_

FortanixEdpEnclaveClient::~FortanixEdpEnclaveClient() {
  fortanix_edp_free_enclave(enclave_);
}

StatusOr<std::shared_ptr<Client>> FortanixEdpBackend::Load(
    const absl::string_view enclave_name,
    const std::string &enclave_path,
    const EnclaveConfig &config,
    std::unique_ptr<Client::ExitCallProvider> exit_call_provider) {

  std::shared_ptr<FortanixEdpEnclaveClient> client(
      new FortanixEdpEnclaveClient(enclave_name, std::move(exit_call_provider)));
  ASYLO_RETURN_IF_ERROR(client->RegisterExitHandlers());

  void* enclave = nullptr;
  unsigned char err[4096] = { 0 };
  uint64_t r = fortanix_edp_load_enclave(enclave_path.c_str(), &enclave, err, sizeof(err) - 1);
  if (r != 0) {
    return Status(error::GoogleError::INTERNAL, "call to fortanix_edp_load_enclave failed");
  }
  client->enclave_ = enclave;

  return client;
}

Status FortanixEdpEnclaveClient::Destroy() {
  return Status::OkStatus();
}

Status FortanixEdpEnclaveClient::EnclaveCallInternal(uint64_t selector,
                                                     MessageWriter *input,
                                                     MessageReader *output) {
  // Ensure client is properly initialized.
  if (!enclave_) {
    return Status{error::GoogleError::FAILED_PRECONDITION,
                  "Enclave client closed or uninitialized."};
  }

  size_t input_size = 0;
  void *input_buffer = nullptr;

  Cleanup clean_up([input_buffer] {
    if (input_buffer) {
      free(input_buffer);
    }
  });

  if (input) {
    input_size = input->MessageSize();
    if (input_size > 0) {
      input_buffer = malloc(input_size);
      input->Serialize(input_buffer);
    }
  }
  size_t output_size = 0;
  unsigned char* output_buffer = nullptr;
  unsigned char err[4096] = { 0 };

  uint64_t r = fortanix_edp_enclave_call(enclave_, selector,
                                         (unsigned char*) input_buffer, input_size,
                                         &output_buffer, &output_size,
                                         err, sizeof(err) - 1);

  if (output_buffer) {
    output->Deserialize(output_buffer, output_size);
    fortanix_edp_free_output_buffer(output_buffer, output_size);
  }
  if (r != 0) {
    return Status{error::GoogleError::INTERNAL, (char*) err};
  }
  return Status::OkStatus();
}

bool FortanixEdpEnclaveClient::IsClosed() const {
  return enclave_ == nullptr;
}

}  // namespace primitives
}  // namespace asylo

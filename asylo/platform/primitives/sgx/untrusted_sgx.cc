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

#include "asylo/platform/primitives/sgx/untrusted_sgx.h"

#include <unistd.h>
#include <cstdlib>

#include "asylo/platform/primitives/sgx/sgx_error_space.h"
#include "asylo/platform/primitives/untrusted_primitives.h"
#include "asylo/util/elf_reader.h"
#include "asylo/util/file_mapping.h"
#include "asylo/util/status.h"
#include "asylo/util/status_macros.h"
#include "asylo/util/statusor.h"
#include "include/sgx_urts.h"

namespace asylo {
namespace primitives {

namespace {

constexpr absl::string_view kCallingProcessBinaryFile = "/proc/self/exe";

constexpr int kMaxEnclaveCreateAttempts = 5;

}  // namespace

SgxEnclaveClient::~SgxEnclaveClient() = default;

StatusOr<std::shared_ptr<Client>> SgxBackend::Load(
    void *base_address, absl::string_view enclave_path, size_t enclave_size,
    const EnclaveConfig &config, bool debug,
    std::unique_ptr<Client::ExitCallProvider> exit_call_provider) {
  std::shared_ptr<SgxEnclaveClient> client(
      new SgxEnclaveClient(std::move(exit_call_provider)));
  client->base_address_ = base_address;

  int updated;
  sgx_status_t status;
  for (int i = 0; i < kMaxEnclaveCreateAttempts; ++i) {
    status = sgx_create_enclave_with_utility_and_address(
        std::string(enclave_path).c_str(), debug, &client->token_, &updated,
        &client->id_, /*misc_attr=*/nullptr, &client->base_address_,
        enclave_size, config.enable_fork());

    LOG_IF(WARNING, status != SGX_SUCCESS)
        << "Failed to create an enclave, attempt=" << i
        << ", status=" << status;
    if (status != SGX_INTERNAL_ERROR_ENCLAVE_CREATE_INTERRUPTED) {
      break;
    }
  }

  if (status != SGX_SUCCESS) {
    return Status(status, "Failed to create an enclave");
  }

  client->size_ = sgx_enclave_size(client->id_);
  return client;
}

StatusOr<std::shared_ptr<Client>> SgxEmbeddedBackend::Load(
    void *base_address, absl::string_view section_name, size_t enclave_size,
    const EnclaveConfig &config, bool debug,
    std::unique_ptr<Client::ExitCallProvider> exit_call_provider) {
  std::shared_ptr<SgxEnclaveClient> client(
      new SgxEnclaveClient(std::move(exit_call_provider)));
  client->base_address_ = base_address;

  FileMapping self_binary_mapping;
  ASYLO_ASSIGN_OR_RETURN(self_binary_mapping, FileMapping::CreateFromFile(
                                                  kCallingProcessBinaryFile));

  ElfReader self_binary_reader;
  ASYLO_ASSIGN_OR_RETURN(self_binary_reader, ElfReader::CreateFromSpan(
                                                 self_binary_mapping.buffer()));

  absl::Span<const uint8_t> enclave_buffer;
  ASYLO_ASSIGN_OR_RETURN(enclave_buffer, self_binary_reader.GetSectionData(
                                             std::string(section_name)));

  int updated;
  sgx_status_t status;
  for (int i = 0; i < kMaxEnclaveCreateAttempts; ++i) {
    status = sgx_create_enclave_from_buffer(
        const_cast<uint8_t *>(enclave_buffer.data()), enclave_buffer.size(),
        debug, &client->token_, &updated, &client->id_, /*misc_attr=*/nullptr,
        &client->base_address_, enclave_size, config.enable_fork());

    if (status != SGX_INTERNAL_ERROR_ENCLAVE_CREATE_INTERRUPTED) {
      break;
    }
  }

  client->size_ = sgx_enclave_size(client->id_);

  if (status != SGX_SUCCESS) {
    return Status(status, "Failed to create an enclave");
  }

  return client;
}

Status SgxEnclaveClient::Destroy() {
  sgx_status_t status = sgx_destroy_enclave(id_);
  if (status != SGX_SUCCESS) {
    return Status(status, "Failed to destroy enclave");
  }
  return Status::OkStatus();
}

sgx_enclave_id_t SgxEnclaveClient::GetEnclaveId() const { return id_; }

size_t SgxEnclaveClient::GetEnclaveSize() const { return size_; }

void *SgxEnclaveClient::GetBaseAddress() const { return base_address_; }

void SgxEnclaveClient::GetLaunchToken(sgx_launch_token_t *token) const {
  memcpy(token, &token_, sizeof(token_));
}

bool SgxEnclaveClient::IsClosed() const {
  abort();
}

Status SgxEnclaveClient::EnclaveCallInternal(uint64_t selector,
                                             UntrustedParameterStack *params) {
  abort();
}

}  // namespace primitives
}  // namespace asylo

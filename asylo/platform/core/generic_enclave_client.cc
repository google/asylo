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

#include "asylo/platform/core/generic_enclave_client.h"

#include <cstddef>
#include <memory>

#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "asylo/enclave.pb.h"  // IWYU pragma: export
#include "asylo/platform/core/entry_selectors.h"
#include "asylo/platform/host_call/untrusted/host_call_handlers_initializer.h"
#include "asylo/platform/primitives/extent.h"
#include "asylo/platform/primitives/primitives.h"
#include "asylo/platform/primitives/util/message.h"
#include "asylo/util/status.h"
#include "asylo/util/status_helpers.h"
#include "asylo/util/status_macros.h"

namespace asylo {

std::unique_ptr<GenericEnclaveClient> GenericEnclaveClient::Create(
    const absl::string_view name,
    const std::shared_ptr<primitives::Client> primitive_client) {
  auto client =
      std::unique_ptr<GenericEnclaveClient>(new GenericEnclaveClient(name));
  client->primitive_client_ = primitive_client;
  return client;
}

Status GenericEnclaveClient::Initialize(const char *name, size_t name_len,
                                        const char *input, size_t input_len,
                                        std::unique_ptr<char[]> *output,
                                        size_t *output_len) {
  primitives::MessageWriter in;
  in.PushByReference(primitives::Extent{input, input_len});
  in.PushByReference(primitives::Extent{name, name_len});
  primitives::MessageReader out;

  host_call::AddHostCallHandlersToExitCallProvider(
      primitive_client_->exit_call_provider());

  ASYLO_RETURN_IF_ERROR(
      primitive_client_->EnclaveCall(kSelectorAsyloInit, &in, &out));
  ASYLO_RETURN_IF_INCORRECT_READER_ARGUMENTS(out, 1);
  auto output_extent = out.next();
  *output_len = output_extent.size();
  output->reset(new char[*output_len]);
  memcpy(output->get(), output_extent.As<char>(), *output_len);
  return absl::OkStatus();
}

Status GenericEnclaveClient::Run(const char *input, size_t input_len,
                                 std::unique_ptr<char[]> *output,
                                 size_t *output_len) {
  primitives::MessageWriter in;
  in.PushByReference(primitives::Extent{input, input_len});
  primitives::MessageReader out;
  ASYLO_RETURN_IF_ERROR(
      primitive_client_->EnclaveCall(kSelectorAsyloRun, &in, &out));
  ASYLO_RETURN_IF_INCORRECT_READER_ARGUMENTS(out, 1);
  auto output_extent = out.next();
  *output_len = output_extent.size();
  output->reset(new char[*output_len]);
  memcpy(output->get(), output_extent.As<char>(), *output_len);
  return absl::OkStatus();
}

Status GenericEnclaveClient::Finalize(const char *input, size_t input_len,
                                      std::unique_ptr<char[]> *output,
                                      size_t *output_len) {
  primitives::MessageWriter in;
  in.PushByReference(primitives::Extent{input, input_len});
  primitives::MessageReader out;
  ASYLO_RETURN_IF_ERROR(
      primitive_client_->EnclaveCall(kSelectorAsyloFini, &in, &out));
  ASYLO_RETURN_IF_INCORRECT_READER_ARGUMENTS(out, 1);
  auto output_extent = out.next();
  *output_len = output_extent.size();
  output->reset(new char[*output_len]);
  memcpy(output->get(), output_extent.As<char>(), *output_len);
  return absl::OkStatus();
}

Status GenericEnclaveClient::EnterAndInitialize(const EnclaveConfig &config) {
  std::string buf;
  if (!config.SerializeToString(&buf)) {
    return absl::InvalidArgumentError("Failed to serialize EnclaveConfig");
  }

  std::unique_ptr<char[]> output;
  size_t output_len = 0;
  std::string enclave_name(get_name());
  ASYLO_RETURN_IF_ERROR(Initialize(enclave_name.c_str(),
                                   enclave_name.size() + 1, buf.data(),
                                   buf.size(), &output, &output_len));

  // Enclave entry-point was successfully invoked. |output| is guaranteed to
  // have a value.
  StatusProto status_proto;
  if (!status_proto.ParseFromArray(output.get(), output_len)) {
    return absl::InternalError("Failed to deserialize StatusProto");
  }

  return StatusFromProto(status_proto);
}

Status GenericEnclaveClient::EnterAndRun(const EnclaveInput &input,
                                         EnclaveOutput *output) {
  std::string buf;
  if (!input.SerializeToString(&buf)) {
    return absl::InvalidArgumentError("Failed to serialize EnclaveInput");
  }

  std::unique_ptr<char[]> output_buf;
  size_t output_len = 0;
  ASYLO_RETURN_IF_ERROR(Run(buf.data(), buf.size(), &output_buf, &output_len));

  // Enclave entry-point was successfully invoked. |output_buf| is guaranteed to
  // have a value.
  EnclaveOutput local_output;
  local_output.ParseFromArray(output_buf.get(), output_len);

  // Set the output parameter if necessary.
  if (output) {
    *output = local_output;
  }

  return StatusFromProto(local_output.status());
}

Status GenericEnclaveClient::EnterAndFinalize(const EnclaveFinal &final_input) {
  std::string buf;
  if (!final_input.SerializeToString(&buf)) {
    return absl::InvalidArgumentError("Failed to serialize EnclaveFinal");
  }

  std::unique_ptr<char[]> output;
  size_t output_len = 0;

  ASYLO_RETURN_IF_ERROR(Finalize(buf.data(), buf.size(), &output, &output_len));

  // Enclave entry-point was successfully invoked. |output| is guaranteed to
  // have a value.
  StatusProto status_proto;
  status_proto.ParseFromArray(output.get(), output_len);

  return StatusFromProto(status_proto);
}

Status GenericEnclaveClient::DestroyEnclave() {
  return primitive_client_->Destroy();
}

}  // namespace asylo

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

#include "asylo/examples/remote/bouncing_circles/circle_client.h"

#include <cstdint>
#include <memory>
#include <string>
#include <tuple>
#include <vector>

#include <gtest/gtest.h>
#include "absl/flags/flag.h"
#include "absl/flags/parse.h"
#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/strings/str_split.h"
#include "absl/strings/string_view.h"
#include "asylo/client.h"
#include "asylo/enclave.pb.h"
#include "asylo/examples/remote/bouncing_circles/circles.pb.h"
#include "asylo/util/logging.h"
#include "asylo/platform/primitives/sgx/loader.pb.h"
#include "asylo/util/path.h"
#include "asylo/util/remote/provision.h"
#include "asylo/util/remote/remote_loader.pb.h"
#include "asylo/util/remote/remote_proxy_config.h"
#include "asylo/util/status_macros.h"

ABSL_FLAG(std::string, enclave_binary_paths, "",
          "Comma-separated list of paths of the enclave binaries to launch");

namespace asylo {
namespace {

class CircleStatusImpl : public CircleStatus {
 public:
  // Factory method creates the circle and connects it to enclave.
  static StatusOr<std::unique_ptr<CircleStatus>> Create(
      size_t id, absl::string_view enclave_prefix, int32_t width,
      int32_t height);
  ~CircleStatusImpl() override;

  std::tuple<int32_t, int32_t, int32_t, std::string> Update() override {
    EnclaveInput input;
    input.MutableExtension(bouncing_circles::enclave_update_position_input);
    EnclaveOutput output;
    const auto enclave_status = client_->EnterAndRun(input, &output);
    CHECK(enclave_status.ok()) << enclave_status;
    auto update_output =
        output.GetExtension(bouncing_circles::enclave_update_position_output);
    return std::tuple<int32_t, int32_t, int32_t, std::string>(
        update_output.x(), update_output.y(), update_output.radius(),
        update_output.color());
  }

  static void InitializeGlobal(size_t n, absl::string_view enclave_prefix,
                               int32_t width, int32_t height) {
    if (!circles_) {
      circles_ = new std::vector<std::unique_ptr<CircleStatus>>();
    }
    if (!circles_->empty()) {
      return;
    }
    for (size_t id = 0; id < n; ++id) {
      auto client_result =
          CircleStatusImpl::Create(id, enclave_prefix, width, height);
      CHECK(client_result.ok()) << client_result.status();
      circles_->emplace_back(std::move(client_result.value()));
    }
  }

  static std::vector<std::unique_ptr<CircleStatus>> *circles() {
    return circles_;
  }

 private:
  // Private constructor, to be called by factory method only.
  CircleStatusImpl() = default;

  // Loads a proxy client to access an instance of a circle enclave
  // remotely. The name of the enclave binary to load is composed as
  // concat('enclave_prefix', id).
  // Returns status on failure.
  StatusOr<EnclaveClient *> LoadEnclave(size_t id,
                                        absl::string_view enclave_prefix);

  EnclaveManager *manager_ = nullptr;
  EnclaveClient *client_ = nullptr;

  static std::vector<std::unique_ptr<CircleStatus>> *circles_;
};

std::vector<std::unique_ptr<CircleStatus>> *CircleStatusImpl::circles_ =
    nullptr;

CircleStatusImpl::~CircleStatusImpl() {
  if (client_) {
    EnclaveFinal empty_final_input;
    const auto status =
        manager_->DestroyEnclave(client_, empty_final_input, false);
    LOG_IF(ERROR, !status.ok())
        << "Failed to destroy enclave, status=" << status;
  }
}

StatusOr<std::unique_ptr<CircleStatus>> CircleStatusImpl::Create(
    size_t id, absl::string_view enclave_prefix, int32_t width,
    int32_t height) {
  auto circle = absl::WrapUnique(new CircleStatusImpl());
  ASYLO_ASSIGN_OR_RETURN(circle->client_,
                         circle->LoadEnclave(id, enclave_prefix));
  EnclaveInput input;
  auto setup_input =
      input.MutableExtension(bouncing_circles::enclave_setup_input);
  setup_input->set_width(width);
  setup_input->set_height(height);
  EnclaveOutput output;
  ASYLO_RETURN_IF_ERROR(circle->client_->EnterAndRun(input, &output));
  return circle;
}

StatusOr<EnclaveClient *> CircleStatusImpl::LoadEnclave(
    size_t id, absl::string_view enclave_prefix) {
  ASYLO_ASSIGN_OR_RETURN(manager_, EnclaveManager::Instance());

  const std::string enclave_name = absl::StrCat(enclave_prefix, id);
  if (manager_->GetClient(enclave_name) != nullptr) {
    return Status(absl::StatusCode::kAlreadyExists,
                  absl::StrCat("Enclave already loaded: ", enclave_name));
  }

  const std::vector<std::string> enclave_binaries =
      absl::StrSplit(absl::GetFlag(FLAGS_enclave_binary_paths), ',');
  CHECK_LT(id, enclave_binaries.size());
  const std::string enclave_binary = enclave_binaries[id];

  EnclaveLoadConfig load_config;
  load_config.set_name(enclave_name);

  std::unique_ptr<RemoteProxyClientConfig> proxy_config;
  ASYLO_ASSIGN_OR_RETURN(proxy_config,
                         RemoteProxyClientConfig::DefaultsWithProvision(
                             RemoteProvision::Instantiate()));

  auto remote_config = load_config.MutableExtension(remote_load_config);
  remote_config->set_remote_proxy_config(
      reinterpret_cast<uintptr_t>(proxy_config.release()));

  SgxLoadConfig *sgx_config = remote_config->mutable_sgx_load_config();
  sgx_config->set_debug(true);
  auto file_enclave_config = sgx_config->mutable_file_enclave_config();
  file_enclave_config->set_enclave_path(enclave_binary);

  ASYLO_RETURN_IF_ERROR(manager_->LoadEnclave(load_config));
  return manager_->GetClient(enclave_name);
}

}  // namespace

void CircleStatus::InitializeGlobal(size_t n, absl::string_view enclave_prefix,
                                    int32_t width, int32_t height) {
  EnclaveManager::Configure(EnclaveManagerOptions());
  CircleStatusImpl::InitializeGlobal(n, enclave_prefix, width, height);
}

std::vector<std::unique_ptr<CircleStatus>> *CircleStatus::circles() {
  return CircleStatusImpl::circles();
}

}  // namespace asylo

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

#include <cstdint>
#include <utility>

#include <gtest/gtest.h>
#include "absl/types/span.h"
#include "asylo/client.h"
#include "asylo/enclave.pb.h"
#include "gflags/gflags.h"
#include "asylo/test/util/status_matchers.h"
#include "asylo/util/elf_reader.h"
#include "asylo/util/file_mapping.h"

DEFINE_string(enclave_section, "", "The ELF section the enclave is located in");

namespace asylo {
namespace {

constexpr char kEnclaveName[] = "enclave";

TEST(EmbeddedEnclaveTest, EnclaveLoadsAndRuns) {
  // Map /proc/self/exe into memory.
  auto create_from_file_result = FileMapping::CreateFromFile("/proc/self/exe");
  ASSERT_THAT(create_from_file_result, IsOk());
  FileMapping enclave_parent_file =
      std::move(create_from_file_result).ValueOrDie();

  // Create an ElfReader for /proc/self/exe.
  auto create_from_span_result =
      ElfReader::CreateFromSpan(enclave_parent_file.buffer());
  ASSERT_THAT(create_from_span_result, IsOk());
  ElfReader parent_file_reader =
      std::move(create_from_span_result).ValueOrDie();

  // Retrieve the data from FLAGS_enclave_section.
  auto get_section_data_result =
      parent_file_reader.GetSectionData(FLAGS_enclave_section);
  ASSERT_THAT(get_section_data_result, IsOk());
  absl::Span<const uint8_t> const_enclave_buffer =
      get_section_data_result.ValueOrDie();
  absl::Span<uint8_t> enclave_buffer(
      const_cast<uint8_t *>(const_enclave_buffer.data()),
      const_enclave_buffer.size());

  // Retrieve the EnclaveManager.
  EnclaveManager::Configure(EnclaveManagerOptions());
  auto manager_result = EnclaveManager::Instance();
  ASSERT_THAT(manager_result, IsOk());
  EnclaveManager *manager = manager_result.ValueOrDie();

  // Load the enclave.
  SGXLoader loader(enclave_buffer, /*debug=*/true);
  EnclaveConfig config;
  ASSERT_THAT(manager->LoadEnclave(kEnclaveName, loader, config), IsOk());
  EnclaveClient *client = manager->GetClient(kEnclaveName);

  // Enter the enclave with a no-op.
  EnclaveInput input;
  EnclaveOutput output;
  EXPECT_THAT(client->EnterAndRun(input, &output), IsOk());

  // Destroy the enclave.
  EnclaveFinal final_input;
  EXPECT_THAT(manager->DestroyEnclave(client, final_input), IsOk());
}

}  // namespace
}  // namespace asylo

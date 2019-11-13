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

#include <stdio.h>
#include <sys/socket.h>

#include <string>
#include <thread>

#include <gtest/gtest.h>
#include "asylo/platform/storage/utils/fd_closer.h"
#include "asylo/test/misc/block_enclave_entries_test.pb.h"
#include "asylo/test/util/enclave_test.h"
#include "asylo/test/util/status_matchers.h"
#include "asylo/util/status.h"
#include "asylo/util/status_macros.h"

namespace asylo {
namespace {

using ::testing::Not;

// Enters the enclave and blocks/unblocks enclave entries.
void EnterEnclaveToBlockEntries(EnclaveClient *client,
                                const EnclaveInput &enclave_input) {
  EXPECT_THAT(client->EnterAndRun(enclave_input, /*output=*/nullptr), IsOk());
}

class BlockEnclaveEntriesTest : public EnclaveTest {};

// Tests blocking/unblocking enclave entries.
TEST_F(BlockEnclaveEntriesTest, BlockUnblock) {
  // Create a socketpair used for communication between the block thread when
  // it's inside the enclave and the check thread when it's outside the enclave.
  int socket_pair[2];
  ASSERT_EQ(socketpair(AF_LOCAL, SOCK_STREAM, /*protocol=*/0, socket_pair), 0);
  int block_socket = socket_pair[0];
  int check_socket = socket_pair[1];

  platform::storage::FdCloser block_socket_closer(block_socket);
  platform::storage::FdCloser check_socket_closer(check_socket);

  EnclaveInput enclave_input;
  enclave_input.MutableExtension(block_enclave_entries_test_input)
      ->set_thread_type(BlockEnclaveEntriesTestInput::BLOCK);
  enclave_input.MutableExtension(block_enclave_entries_test_input)
      ->set_socket(block_socket);

  // First initialize the thread that enters the enclave and blocks enclave
  // entries.
  std::thread block_thread(EnterEnclaveToBlockEntries, client_, enclave_input);

  // Waits till the BLOCK thread finishes blocking and writes to socket.
  char buf[64];
  int rc = read(check_socket, buf, sizeof(buf));
  ASSERT_GT(rc, 0);
  buf[rc] = '\0';
  ASSERT_THAT(buf, testing::StrEq("Enclave entries blocked"));

  enclave_input.MutableExtension(block_enclave_entries_test_input)
      ->set_thread_type(BlockEnclaveEntriesTestInput::CHECK);

  EXPECT_THAT(client_->EnterAndRun(enclave_input, /*output=*/nullptr),
              IsOk());

  block_thread.join();
}

}  // namespace
}  // namespace asylo

/*
 *
 * Copyright 2017 Asylo authors
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

#include <gtest/gtest.h>
#include "asylo/test/util/enclave_test.h"

namespace asylo {
namespace {

class ExhaustSgxTcsTest : public EnclaveTest {};

TEST_F(ExhaustSgxTcsTest, ExhaustTCSsSIGILLorSIGSEGV) {
  auto test_exit = [] (int exit_status) {
      return WIFSIGNALED(exit_status) && (WTERMSIG(exit_status) == SIGILL ||
                                          WTERMSIG(exit_status) == SIGSEGV);
  };
  EXPECT_EXIT(client_->EnterAndRun({}, nullptr), test_exit, "");
}

}  // namespace
}  // namespace asylo

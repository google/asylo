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

#include "asylo/test/util/test_flags.h"

#include <cstdlib>

#include "absl/flags/flag.h"

namespace asylo {
namespace {

std::string GetTestTempDirEnvironment() {
  char *env_dir = getenv("TEST_TMPDIR");
  if (env_dir != nullptr && env_dir[0] != '\0') {
    return env_dir;
  }

  return "/tmp/";
}

}  // namespace
}  // namespace asylo

ABSL_FLAG(std::string, test_tmpdir, asylo::GetTestTempDirEnvironment(),
          "Location for all temporary test files.");

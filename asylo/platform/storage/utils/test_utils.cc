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

#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <cstring>
#include <string>

#include <gtest/gtest.h>
#include "absl/flags/flag.h"
#include "absl/strings/str_cat.h"
#include "asylo/util/logging.h"
#include "asylo/test/util/test_flags.h"

namespace asylo {

int CreateEmptyTempFileOrDie(absl::string_view basename) {
  std::string path =
      absl::StrCat(absl::GetFlag(FLAGS_test_tmpdir), "/", basename);
  int err = unlink(path.c_str());
  CHECK(err == 0 || errno == ENOENT) << strerror(errno);
  int fd = open(path.c_str(), O_CREAT | O_EXCL | O_RDWR, S_IRUSR | S_IWUSR);
  CHECK_NE(fd, -1) << "Could not create temporary file " << path << ": "
                   << strerror(errno);
  return fd;
}

}  // namespace asylo

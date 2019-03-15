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

#include "asylo/test/util/exec_tester.h"

#include <fcntl.h>
#include <libgen.h>  // dirname()
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <cstdlib>
#include <cstring>
#include <sstream>
#include <thread>

#include <gtest/gtest.h>
#include "absl/strings/str_cat.h"
#include "absl/strings/str_split.h"
#include "absl/strings/string_view.h"

namespace asylo {
namespace experimental {

ExecTester::ExecTester(const std::vector<std::string> &args, int fd_to_check)
    : args_(args), fd_to_check_(fd_to_check) {
  // Make sure we can actually execute the file.
  if (::access(args[0].c_str(), X_OK)) {
    std::cerr << "Cannot access file: " << args[0] << "\nError (" << errno
              << "): " << strerror(errno) << std::endl;
    abort();
  }
}

std::string ExecTester::BuildSiblingPath(const std::string &path,
                                         const std::string &file_name) {
  char *path_dup = strdup(path.c_str());
  absl::string_view path_dirname(dirname(path_dup));

  // If path_dirname is "/", then we don't want to add a "/" between
  // path_dirname and file_name.
  std::string result =
      absl::StrCat(path_dirname, (path_dirname == "/" ? "" : "/"), file_name);

  free(path_dup);
  return result;
}

bool ExecTester::Run(const std::string &input, int *status) {
  bool result = false;
  RunWithAsserts(input, &result, status);
  return FinalCheck(result);
}

void ExecTester::DoExec(int read_stdin, int write_stdin, int read_fd_to_check,
                        int write_fd_to_check) {
  if (read_stdin >= 0) {
    ASSERT_NE(-1, dup2(read_stdin, STDIN_FILENO)) << strerror(errno);
    close(write_stdin);
  }
  // Make writes to fd_to_check_ from the subprocess write to the pipe.
  ASSERT_NE(-1, dup2(write_fd_to_check, fd_to_check_)) << strerror(errno);
  // Only the host process needs to read from the pipe.
  close(read_fd_to_check);

  // No malloc allowed between fork/exec. We can get deadlocked.
  char **argv =
      static_cast<char **>(alloca(sizeof(char *) * (args_.size() + 1)));
  for (int i = 0; i < args_.size(); ++i) {
    argv[i] = const_cast<char *>(args_[i].c_str());
  }
  argv[args_.size()] = nullptr;

  int res = execve(argv[0], argv, nullptr);
  ASSERT_NE(-1, res) << "Exec failed: " << argv[0] << " " << strerror(errno);
}

void ExecTester::RunWithAsserts(const std::string &input, bool *result,
                                int *status) {
  ASSERT_NE(nullptr, result);
  ASSERT_NE(nullptr, status);

  // Use -1 to mean "no file descriptor".
  int stdin_pipe[2] = {-1, STDIN_FILENO};
  int fd_to_check_pipe[2];
  ASSERT_EQ(0, pipe(fd_to_check_pipe))
      << "Could not establish pipe for subprocess output: " << strerror(errno);
  ASSERT_TRUE(input.empty() || !pipe(stdin_pipe))
      << "Could not establish pipe for subprocess input: " << strerror(errno);
  constexpr int kReadEnd = 0;
  constexpr int kWriteEnd = 1;
  int read_stdin = stdin_pipe[kReadEnd];
  int write_stdin = stdin_pipe[kWriteEnd];
  int read_fd_to_check = fd_to_check_pipe[kReadEnd];
  int write_fd_to_check = fd_to_check_pipe[kWriteEnd];

  pid_t pid = fork();

  ASSERT_NE(-1, pid);
  if (pid == 0) {  // Subprocess
    DoExec(read_stdin, write_stdin, read_fd_to_check, write_fd_to_check);
  } else {  // Host process
    close(write_fd_to_check);
    close(read_stdin);

    // Write the input string to stdin if available.
    if (!input.empty()) {
      ASSERT_NE(write(write_stdin, input.c_str(), input.size()), -1);
      fsync(write_stdin);
    }

    // Make the read end of the pipe non-blocking.
    int flags = fcntl(read_fd_to_check, F_GETFL, 0);
    fcntl(read_fd_to_check, F_SETFL, flags | O_NONBLOCK);

    ReadCheckLoop(pid, read_fd_to_check, result, status);
  }
}

void ExecTester::ReadCheckLoop(pid_t pid, int fd, bool *result, int *status) {
  ASSERT_NE(nullptr, status);

  bool conjunction = true;
  char buffer[1024];
  std::stringstream linebuf;

  // Read and check all subprocess output to |fd| until the subprocess
  // terminates.
  while (true) {
    std::this_thread::yield();
    int changed_pid = waitpid(pid, status, WNOHANG);
    ASSERT_NE(-1, changed_pid)
        << "Wait on subprocess status failed: " << strerror(errno);

    CheckFD(fd, buffer, &linebuf, &conjunction);

    if (changed_pid && (WIFEXITED(*status) || WIFSIGNALED(*status))) {
      *result = conjunction;
      return;
    }
  }
}

void ExecTester::CheckFD(int fd, absl::Span<char> buffer,
                         std::stringstream *linebuf, bool *result) {
  ASSERT_FALSE(buffer.empty());
  ASSERT_NE(nullptr, linebuf);

  ssize_t numread = read(fd, buffer.data(), buffer.size());

  if (numread == -1) {
    // Nothing to read.
    ASSERT_EQ(errno, EAGAIN) << "Read from fd " << fd << " failed (" << errno
                             << "): " << strerror(errno);
    return;
  } else if (numread == 0) {  // The fd is closed. Test the rest of the line.
    std::string line = linebuf->str();
    if (!line.empty()) {
      linebuf->str("");
      *result &= CheckLine(line);
    }
    return;
  }

  // Test each line we see in this buffer before moving on.
  std::vector<absl::string_view> lines =
      absl::StrSplit(absl::string_view(buffer.data(), numread), '\n');
  for (int i = 0; i < lines.size() - 1; ++i) {
    linebuf->write(lines[i].data(), lines[i].size());
    *result &= CheckLine(linebuf->str());
    linebuf->str("");
  }
  ASSERT_GT(lines.size(), 0);
  linebuf->write(lines.back().data(), lines.back().size());
}

}  // namespace experimental
}  // namespace asylo

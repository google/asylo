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

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cstring>
#include <sstream>

#include <gtest/gtest.h>
#include "asylo/test/util/exec_tester.h"

namespace asylo {

ExecTester::ExecTester(const std::vector<std::string> &args) : args_(args) {
  // Make sure we can actually execute the file.
  if (::access(args[0].c_str(), X_OK)) {
    std::cerr << "Cannot access file: " << args[0] << "\nError (" << errno
              << "): " << strerror(errno) << std::endl;
    abort();
  }
}

// NOTE: Only works on POSIX file systems because of '/' and absolute paths.
std::string ExecTester::BuildPath(const std::string &path, const std::string &file_name) {
  // If the base path is empty, or
  // if file_name is an absolute path, just return file_name.
  if (path.empty() || (!file_name.empty() && file_name[0] == '/')) {
    return file_name;
  }

  // If path ends in '/', we treat it as a directory.
  // Otherwise we have to check if path is a directory to either chop off the
  // file name or add a '/' at the end.
  std::string arg0base = path;

  if (arg0base[arg0base.size() - 1] != '/') {
    // If path is a directory, add '/', otherwise, remove name until last '/'.
    struct stat statbuf;
    if (!::stat(path.c_str(), &statbuf) && S_ISDIR(statbuf.st_mode)) {
      arg0base += "/";
    } else {
      // Chop to last '/'.
      std::string::size_type pos = arg0base.rfind('/');
      if (pos == std::string::npos) {
        arg0base.clear();
      } else {
        arg0base.resize(pos + 1);
      }
    }
  }
  return arg0base + file_name;
}

bool ExecTester::Run(int *status, const std::string &input) {
  bool result = false;
  RunWithAsserts(input, &result, status);
  return FinalCheck(result);
}

void ExecTester::DoExec(int read_stdin, int write_stdin, int read_stdout,
                        int write_stdout) {
  if (read_stdin >= 0) {
    ASSERT_NE(-1, dup2(read_stdin, STDIN_FILENO)) << strerror(errno);
    close(write_stdin);
  }
  // Make STDOUT from the subprocess write to the pipe.
  ASSERT_NE(-1, dup2(write_stdout, STDOUT_FILENO)) << strerror(errno);
  // Only the host process needs to read from the pipe.
  close(read_stdout);

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

  int stdin_pipe[2] = {-1, 0};  // Use -1 to mean "no file descriptor".
  int stdout_pipe[2];
  ASSERT_EQ(0, pipe(stdout_pipe))
      << "Could not establish pipe for subprocess output.";
  ASSERT_TRUE(input.empty() || !pipe(stdin_pipe))
      << "Could not establish pipe for subprocess input.";
  constexpr int kReadEnd = 0;
  constexpr int kWriteEnd = 1;
  int read_stdin = stdin_pipe[kReadEnd];
  int write_stdin = stdin_pipe[kWriteEnd];
  int read_stdout = stdout_pipe[kReadEnd];
  int write_stdout = stdout_pipe[kWriteEnd];

  pid_t pid = fork();

  ASSERT_NE(-1, pid);
  if (pid == 0) {  // Subprocess
    DoExec(read_stdin, write_stdin, read_stdout, write_stdout);
  } else {  // Host process
    close(write_stdout);
    close(read_stdin);

    // Write the input string to stdin if available.
    if (!input.empty()) {
      ASSERT_NE(write(write_stdin, input.c_str(), input.size()), -1);
      fsync(write_stdin);
    }

    // Make the read end of the pipe non-blocking.
    int flags = fcntl(read_stdout, F_GETFL, 0);
    fcntl(read_stdout, F_SETFL, flags | O_NONBLOCK);

    ReadCheckLoop(pid, read_stdout, result, status);
  }
}

void ExecTester::ReadCheckLoop(pid_t pid, int stdout, bool *result,
                               int *status) {
  ASSERT_NE(nullptr, status);

  bool conjunction = true;
  char buf[1024];
  std::stringstream linebuf;

  // Read and check all subprocess output to stdout until it terminates.
  while (1) {
    __builtin_ia32_pause();
    int changed_pid = waitpid(pid, status, WNOHANG);
    ASSERT_NE(-1, changed_pid)
        << "Wait on subprocess status failed " << strerror(errno);

    CheckFD(buf, sizeof(buf), &linebuf, stdout, &conjunction);

    if (changed_pid && (WIFEXITED(*status) || WIFSIGNALED(*status))) {
      *result = conjunction;
      return;
    }
  }
}

void ExecTester::CheckFD(char *buf, size_t bufsize, std::stringstream *linebuf,
                         int fd, bool *result) {
  ASSERT_NE(nullptr, buf);
  ASSERT_LT(0, bufsize);
  ASSERT_NE(nullptr, linebuf);

  ssize_t numread = read(fd, buf, bufsize);

  if (numread == -1) {
    // Nothing to read.
    ASSERT_EQ(errno, EAGAIN) << "Read from fd " << fd << " failed (" << errno
                             << "): " << strerror(errno);
    return;
  } else if (numread == 0) {  // The fd is closed. Test the rest of the line.
    std::string line = linebuf->str();
    if (!line.empty()) {
      linebuf->str("");
      *result &= TestLine(line);
    }
    return;
  }

  // Test each line we see in this buffer before moving on.
  char *bufptr = buf;
  int unconsumed = numread, line_size = 0;
  while (unconsumed > 0) {
    bufptr = &bufptr[line_size];
    // We populate an entire line before testing.
    const char *line_end = strchr(bufptr, '\n');
    if (line_end) {
      line_size = (line_end - bufptr) + 1;
      ASSERT_LE(line_size, bufsize);

      unconsumed -= line_size;
      linebuf->write(bufptr, line_size - 1);  // Don't include the \n character.
      std::string line = linebuf->str();
      linebuf->str("");  // Reset the line buffer.
      *result &= TestLine(line);
    } else {  // No new line. Copy rest of buffer.
      linebuf->write(bufptr, unconsumed);
      unconsumed = 0;
    }
  }
}
}  // namespace asylo

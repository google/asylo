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

#ifndef ASYLO_TEST_UTIL_EXEC_TESTER_H_
#define ASYLO_TEST_UTIL_EXEC_TESTER_H_

#include <iostream>
#include <sstream>
#include <string>
#include <vector>

namespace asylo {

// Executes a subprocess and monitors both its output to stdout and
// its exit code.
class ExecTester {
 public:
  ExecTester(const std::vector<std::string> &args);
  virtual ~ExecTester() {}

  // Forks and execs the subprocess with arguments as specified by args_.
  // Redirects the subprocess's stdin from |input| if non-empty.
  // Validates the subprocess's stdout contents by TestLine and FinalCheck.
  // Stores the process status in `status` after exit or signal termination.
  // Returns: The logical and of all TestLine results on the subprocess's
  //          output to stdout.
  bool Run(int *status, const std::string &input = "");

  // Returns `file_name` qualified with the directory specified by `path`.
  // This is needed for execve to find the correct binary.
  static std::string BuildPath(const std::string &path, const std::string &file_name);

 protected:
  // Run a predicate on all lines of STDOUT output from the subprocess.
  virtual bool TestLine(const std::string &line) { return true; }

  // Do any aggregate testing on the result of all line testing.
  virtual bool FinalCheck(bool accumulated) { return accumulated; }

  // ASSERT_* statements expect a void return type.
  void RunWithAsserts(const std::string &input, bool *result, int *status);

  // Redirects subprocess stdin/stdout to pipe's read/write end respectively,
  // and execs args_.
  void DoExec(int read_stdin, int write_stdin, int read_stdout,
              int write_stdout);

  // Read contents of fd into buf and run TestLine on each line, as written in
  // linebuf. Any unfinished line (buf tail not terminated by '\n') will be
  // stored in linebuf. Accumulates line test results in result.
  void CheckFD(char *buf, size_t bufsize, std::stringstream *linebuf, int fd,
               bool *result);

  // Waits on pid, reads and checks its output. Sets the pid's termination
  // status and the result of the conjunction of the output checks.
  void ReadCheckLoop(pid_t pid, int stdout, bool *result, int *status);

 protected:
  std::vector<std::string> args_;
};

}  // namespace asylo

#endif  // ASYLO_TEST_UTIL_EXEC_TESTER_H_

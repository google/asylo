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

#include "asylo/util/logging.h"

#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <sstream>
#include <string>

namespace asylo {

#ifdef __ASYLO__
constexpr bool kInsideEnclave = true;
#else   // __ASYLO__
constexpr bool kInsideEnclave = false;
#endif  // __ASYLO__

constexpr char kDefaultDirectory[] = "/tmp/";

namespace {

// The logging directory, specified at the time the enclave is initialized.
std::string *log_file_directory = nullptr;

// The log filename set according to program binary name (untrusted log) or
// enclave name (enclave log).
std::string *log_basename = nullptr;

// The VLOG level, only VLOG with level equal to or below this level is logged,
// specified at the time the enclave is initialized.
int vlog_level = 0;

// A flag to ensure that LOG(FATAL) doesn't lead to an infinite loop of
// failures.
thread_local bool log_panic = false;

const char *GetBasename(const char *file_path) {
  const char *slash = strrchr(file_path, '/');
  return slash ? slash + 1 : file_path;
}

// Builds a valid file name from a string.
const std::string BuildFilename(std::string filename) {
  for (size_t i = 0; i < filename.size(); ++i) {
    if (isalnum(filename[i]) == 0 && filename[i] != '-') {
      filename[i] = '_';
    }
  }
  return filename;
}

bool set_log_basename(const std::string &filename) {
  if (log_basename || filename.empty()) {
    return false;
  }
  log_basename = new std::string(filename);
  return true;
}

const std::string get_log_basename() {
  if (!log_basename || log_basename->empty()) {
    return kInsideEnclave ? "enclave_log" : "untrusted_log";
  }
  return *log_basename;
}

}  // namespace

bool set_log_directory(const std::string &log_directory) {
  std::string tmp_directory = log_directory;
  if (tmp_directory.empty()) {
    tmp_directory = kDefaultDirectory;
  }
  if (log_file_directory || !EnsureDirectory(tmp_directory.c_str())) {
    return false;
  }
  if (tmp_directory.back() == '/') {
    log_file_directory = new std::string(tmp_directory);
  } else {
    log_file_directory = new std::string(tmp_directory + "/");
  }
  return true;
}

const std::string get_log_directory() {
  if (!log_file_directory) {
    return kDefaultDirectory;
  }
  return *log_file_directory;
}

void set_vlog_level(int level) { vlog_level = level; }

int get_vlog_level() { return vlog_level; }

bool EnsureDirectory(const char *path) {
  struct stat dirStat;
  if (stat(path, &dirStat)) {
    if (errno != ENOENT) {
      return false;
    }
    if (mkdir(path, 0766)) {
      return false;
    }
  } else if (!S_ISDIR(dirStat.st_mode)) {
    return false;
  }
  return true;
}

bool InitLogging(const char *directory, const char *file_name, int level) {
  set_vlog_level(level);
  std::string log_directory = directory ? std::string(directory) : "";
  if (!set_log_directory(log_directory)) {
    return false;
  }
  const char *binary_name = GetBasename(file_name);
  std::string filename = binary_name;
  if (kInsideEnclave) {
    filename = BuildFilename(filename);
  }
  if (!filename.empty() && !set_log_basename(filename)) {
    return false;
  }
  std::string log_path = get_log_directory() + get_log_basename();
  if (access(log_path.c_str(), F_OK) == 0 &&
      access(log_path.c_str(), W_OK) != 0) {
    return false;
  }
  return true;
}

LogMessage::LogMessage(const char *file, int line) { Init(file, line, INFO); }

LogMessage::LogMessage(const char *file, int line, LogSeverity severity) {
  Init(file, line, severity);
}

LogMessage::LogMessage(const char *file, int line, const std::string &result) {
  Init(file, line, FATAL);
  stream() << "Check failed: " << result << " ";
}

static constexpr const char *LogSeverityNames[5] = {"INFO", "WARNING", "ERROR",
                                                    "FATAL", "QFATAL"};

void LogMessage::Init(const char *file, int line, LogSeverity severity) {
  // Disallow recursive fatal messages.
  if (log_panic) {
    abort();
  }
  severity_ = severity;
  if (severity_ == FATAL || severity_ == QFATAL) {
    log_panic = true;
  }

  const char *filename = GetBasename(file);

  // Write a prefix into the log message, including local date/time, severity
  // level, filename, and line number.
  struct timespec time_stamp;
  clock_gettime(CLOCK_REALTIME, &time_stamp);

  constexpr int kTimeMessageSize = 22;
  struct tm datetime;
  memset(&datetime, 0, sizeof(datetime));
  if (localtime_r(&time_stamp.tv_sec, &datetime)) {
    char buffer[kTimeMessageSize];
    strftime(buffer, kTimeMessageSize, "%Y-%m-%d %H:%M:%S  ", &datetime);
    stream() << buffer;
  } else {
    // localtime_r returns error. Attach the errno message.
    stream() << "Failed to get time:" << strerror(errno) << "  ";
  }
  stream() << LogSeverityNames[severity_] << "  " << filename << " : " << line
           << " : ";
}

LogMessage::~LogMessage() {
  std::string message_text = stream_.str();
  SendToLog(message_text);
}

LogMessageFatal::~LogMessageFatal() {
  std::string message_text = stream_.str();
  SendToLog(message_text);
  // if FATAL occurs, abort enclave.
  if (severity_ == FATAL) {
    abort();
  }
  _exit(1);
}

void LogMessage::SendToLog(const std::string &message_text) {
  std::string log_path = get_log_directory() + get_log_basename();

  FILE *file = fopen(log_path.c_str(), "ab");
  if (file) {
    if (fprintf(file, "%s", message_text.c_str()) > 0) {
      if (message_text.back() != '\n') {
        fprintf(file, "\n");
      }
    } else {
      fprintf(stderr, "Failed to write to log file : %s!\n", log_path.c_str());
    }
    fclose(file);
  } else {
    fprintf(stderr, "Failed to open log file : %s!\n", log_path.c_str());
  }
  if (severity_ >= ERROR) {
    fprintf(stderr, "%s\n", message_text.c_str());
    fflush(stderr);
  }
  printf("%s\n", message_text.c_str());
  fflush(stdout);
}

CheckOpMessageBuilder::CheckOpMessageBuilder(const char *exprtext)
    : stream_(new std::ostringstream) {
  *stream_ << exprtext << " (";
}

CheckOpMessageBuilder::~CheckOpMessageBuilder() { delete stream_; }

std::ostream *CheckOpMessageBuilder::ForVar2() {
  *stream_ << " vs. ";
  return stream_;
}

std::string *CheckOpMessageBuilder::NewString() {
  *stream_ << ")";
  return new std::string(stream_->str());
}

template <>
void MakeCheckOpValueString(std::ostream *os, const char &v) {
  if (v >= 32 && v <= 126) {
    (*os) << "'" << v << "'";
  } else {
    (*os) << "char value " << static_cast<int16_t>(v);
  }
}

template <>
void MakeCheckOpValueString(std::ostream *os, const signed char &v) {
  if (v >= 32 && v <= 126) {
    (*os) << "'" << v << "'";
  } else {
    (*os) << "signed char value " << static_cast<int16_t>(v);
  }
}

template <>
void MakeCheckOpValueString(std::ostream *os, const unsigned char &v) {
  if (v >= 32 && v <= 126) {
    (*os) << "'" << v << "'";
  } else {
    (*os) << "unsigned char value " << static_cast<uint16_t>(v);
  }
}

template <>
void MakeCheckOpValueString(std::ostream *os, const std::nullptr_t &v) {
  (*os) << "nullptr";
}

}  // namespace asylo

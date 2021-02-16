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

#ifndef ASYLO_UTIL_LOGGING_H_
#define ASYLO_UTIL_LOGGING_H_

#include <cstdint>
#include <cstdlib>
#include <memory>
#include <sstream>
#include <string>

#include "absl/base/attributes.h"
#include "absl/base/optimization.h"

/// \cond Internal
#define COMPACT_ASYLO_LOG_INFO ::asylo::LogMessage(__FILE__, __LINE__)
#define COMPACT_ASYLO_LOG_WARNING \
  ::asylo::LogMessage(__FILE__, __LINE__, WARNING)
#define COMPACT_ASYLO_LOG_ERROR ::asylo::LogMessage(__FILE__, __LINE__, ERROR)
#define COMPACT_ASYLO_LOG_FATAL \
  ::asylo::LogMessageFatal(__FILE__, __LINE__, FATAL)
#define COMPACT_ASYLO_LOG_QFATAL \
  ::asylo::LogMessageFatal(__FILE__, __LINE__, QFATAL)

#ifdef NDEBUG
#define COMPACT_ASYLO_LOG_DFATAL COMPACT_ASYLO_LOG_ERROR
#else
#define COMPACT_ASYLO_LOG_DFATAL COMPACT_ASYLO_LOG_FATAL
#endif
/// \endcond

/// Creates a message and logs it to file.
///
/// `LOG(severity)` returns a stream object that can be written to with the `<<`
/// operator. Log messages are emitted with terminating newlines.
/// Example:
///
/// ```
/// LOG(INFO) << "Found" << num_cookies << " cookies";
/// ```
///
/// \param severity The severity of the log message, one of `LogSeverity`. The
///        FATAL severity will end the program after the log is emitted.
#define LOG(severity) COMPACT_ASYLO_LOG_##severity.stream()

/// A command to LOG only if a condition is true. If the condition is false,
/// nothing is logged.
/// Example:
///
/// ```
/// LOG_IF(INFO, num_cookies > 10) << "Got lots of cookies";
/// ```
///
/// \param severity The severity of the log message, one of `LogSeverity`. The
///        FATAL severity will end the program after the log is emitted.
/// \param condition The condition that determines whether to log the message.
#define LOG_IF(severity, condition) \
  !(condition) ? (void)0 : asylo::LogMessageVoidify() & LOG(severity)

/// A `LOG` command with an associated verbosity level. The verbosity threshold
/// may be configured at runtime with `set_vlog_level` and `InitLogging`.
///
/// `VLOG` statements are logged at `INFO` severity if they are logged at all.
/// The numeric levels are on a different scale than the severity levels.
/// Example:
///
/// ```
/// VLOG(1) << "Print when VLOG level is set to be 1 or higher";
/// ```
///
/// \param level The numeric level that determines whether to log the message.
#define VLOG(level) LOG_IF(INFO, (level) <= get_vlog_level())

/// Ends the program with a fatal error if the specified condition is
/// false.
///
/// Example:
///
/// ```
/// CHECK(!cheese.empty()) << "Out of Cheese";
/// ```
///
/// Might produce a message like:
///
/// `Check_failed: !cheese.empty() Out of Cheese`
#define CHECK(condition) \
  LOG_IF(FATAL, !(condition)) << "Check failed: " #condition " "

/// Severity level definitions. These represent the four severity levels INFO
/// through FATAL.
enum LogSeverity { INFO, WARNING, ERROR, FATAL, QFATAL };

namespace asylo {

/// \cond Internal
/// This formats a value for a failing CHECK_XX statement.  Ordinarily,
/// it uses the definition for `operator<<`, with a few special cases below.
template <typename T>
inline void MakeCheckOpValueString(std::ostream *os, const T &v) {
  (*os) << v;
}

// Overrides for char types provide readable values for unprintable
// characters.
template <>
void MakeCheckOpValueString(std::ostream *os, const char &v);
template <>
void MakeCheckOpValueString(std::ostream *os, const signed char &v);
template <>
void MakeCheckOpValueString(std::ostream *os, const unsigned char &v);
/// \endcond

// We need an explicit specialization for `std::nullptr_t`.
template <>
void MakeCheckOpValueString(std::ostream *os, const std::nullptr_t &p);

/// A helper class for formatting "expr (V1 vs. V2)" in a CHECK_XX
/// statement.  See MakeCheckOpString for sample usage.
class CheckOpMessageBuilder {
 public:
  /// Constructs an object to format a CheckOp message. This constructor
  /// initializes the message first with `exprtext` followed by " (".
  ///
  /// \param exprtext A string representation of the code in `file` at `line`.
  explicit CheckOpMessageBuilder(const char *exprtext);

  /// Deletes "stream_".
  ~CheckOpMessageBuilder();

  /// Gets the output stream for the first argument of the message.
  ///
  /// \return The current stream message.
  std::ostream *ForVar1() { return stream_; }

  /// Gets the output stream for writing the argument of the message. This
  /// writes " vs. " to the stream first.
  ///
  /// \return The current stream message.
  std::ostream *ForVar2();

  /// Gets the built string contents. The stream is finished with an added ")".
  ///
  /// \return The current stream message.
  std::string *NewString();

 private:
  std::ostringstream *stream_;
};

/// \cond Internal
template <typename T1, typename T2>
std::string *MakeCheckOpString(const T1 &v1, const T2 &v2,
                               const char *exprtext) {
  CheckOpMessageBuilder comb(exprtext);
  MakeCheckOpValueString(comb.ForVar1(), v1);
  MakeCheckOpValueString(comb.ForVar2(), v2);
  return comb.NewString();
}

// Helper functions for CHECK_OP macro.
// The (int, int) specialization works around the issue that the compiler
// will not instantiate the template version of the function on values of
// unnamed enum type - see comment below.
//
/// \param name An identifier that is the name of the comparison, such as
///        Check_EQ or Check_NE.
/// \param op The comparison operator, such as == or !=.
#define DEFINE_CHECK_OP_IMPL(name, op)                                   \
  template <typename T1, typename T2>                                    \
  inline std::string *name##Impl(const T1 &v1, const T2 &v2,             \
                                 const char *exprtext) {                 \
    if (ABSL_PREDICT_TRUE(v1 op v2)) return nullptr;                     \
    return MakeCheckOpString(v1, v2, exprtext);                          \
  }                                                                      \
  inline std::string *name##Impl(int v1, int v2, const char *exprtext) { \
    return name##Impl<int, int>(v1, v2, exprtext);                       \
  }

// We use the full name Check_EQ, Check_NE, etc.
//
// This is to prevent conflicts when the file including logging.h provides its
// own #defines for the simpler names EQ, NE, etc. This happens if, for
// example, those are used as token names in a yacc grammar.
DEFINE_CHECK_OP_IMPL(Check_EQ, ==)
DEFINE_CHECK_OP_IMPL(Check_NE, !=)
DEFINE_CHECK_OP_IMPL(Check_LE, <=)
DEFINE_CHECK_OP_IMPL(Check_LT, <)
DEFINE_CHECK_OP_IMPL(Check_GE, >=)
DEFINE_CHECK_OP_IMPL(Check_GT, >)
#undef DEFINE_CHECK_OP_IMPL
/// \endcond

/// \cond Internal
// Function is overloaded for integral types to allow static const
// integrals declared in classes and not defined to be used as arguments to
// CHECK* macros. It's not encouraged though.
template <typename T>
inline const T &GetReferenceableValue(const T &t) {
  return t;
}
inline char GetReferenceableValue(char t) { return t; }
inline uint8_t GetReferenceableValue(uint8_t t) { return t; }
inline int8_t GetReferenceableValue(int8_t t) { return t; }
inline int16_t GetReferenceableValue(int16_t t) { return t; }
inline uint16_t GetReferenceableValue(uint16_t t) { return t; }
inline int32_t GetReferenceableValue(int32_t t) { return t; }
inline uint32_t GetReferenceableValue(uint32_t t) { return t; }
inline int64_t GetReferenceableValue(int64_t t) { return t; }
inline uint64_t GetReferenceableValue(uint64_t t) { return t; }
/// \endcond

/// Compares `val1` and `val2` with `op`, and does `log` if false.
///
/// \param name An identifier that is the name of the comparison, such as
///        Check_EQ or Check_NE.
/// \param op The comparison operator, such as == or !=.
/// \param val1 The first variable to be compared.
/// \param val2 The second variable to be compared.
/// \param log The log action to be performed if the comparison returns false.
#define CHECK_OP_LOG(name, op, val1, val2, log)                               \
  while (std::unique_ptr<std::string> _result = std::unique_ptr<std::string>( \
             asylo::name##Impl(asylo::GetReferenceableValue(val1),            \
                               asylo::GetReferenceableValue(val2),            \
                               #val1 " " #op " " #val2)))                     \
  log(__FILE__, __LINE__, *_result).stream()

/// Compares `val1` and `val2` with `op`, and produces a LOG(FATAL) if false.
///
/// \param name An identifier that is the name of the comparison, such as
///        Check_EQ or Check_NE.
/// \param op The comparison operator, such as == or !=.
/// \param val1 The first variable to be compared.
/// \param val2 The second variable to be compared.
#define CHECK_OP(name, op, val1, val2) \
  CHECK_OP_LOG(name, op, val1, val2, asylo::LogMessageFatal)

/// Produces a LOG(FATAL) unless `val1` equals `val2`.
#define CHECK_EQ(val1, val2) CHECK_OP(Check_EQ, ==, val1, val2)
/// Produces a LOG(FATAL) unless `val1` does not equal to `val2`.
#define CHECK_NE(val1, val2) CHECK_OP(Check_NE, !=, val1, val2)
/// Produces a LOG(FATAL) unless `val1` is less than or equal to `val2`.
#define CHECK_LE(val1, val2) CHECK_OP(Check_LE, <=, val1, val2)
/// Produces a LOG(FATAL) unless `val1` is less than `val2`.
#define CHECK_LT(val1, val2) CHECK_OP(Check_LT, <, val1, val2)
/// Produces a LOG(FATAL) unless `val1` is greater than or equal to `val2`.
#define CHECK_GE(val1, val2) CHECK_OP(Check_GE, >=, val1, val2)
/// Produces a LOG(FATAL) unless `val1` is greater than `val2`.
#define CHECK_GT(val1, val2) CHECK_OP(Check_GT, >, val1, val2)

/// Checks that the argument is not null, and returns it.
///
/// Unlike other `CHECK` macros, this one returns its input, so it can be used
/// in initializers. Outside initializers, prefer `CHECK`.
///
/// `CHECK_NOTNULL` works for both raw pointers and (compatible) smart pointers
/// including `std::unique_ptr` and `std::shared_ptr`.
///
/// For smart pointers `CHECK_NOTNULL` returns a reference to its argument,
/// preserving the value category (i.e., an rvalue reference for an
/// rvalue argument, and an lvalue reference otherwise).  For pre-C++11
/// compilers that's not possible, so as a best available approximation
/// a reference-to-const will be returned if the argument is an rvalue.
///
/// \param val The value being compared.
#define CHECK_NOTNULL(val) \
  asylo::CheckNotNull(__FILE__, __LINE__, "'" #val "' Must be non NULL", (val))

/// Sets the verbosity threshold for VLOG. A VLOG command with a level greater
/// than this will be ignored.
///
/// \param level The verbosity threshold for VLOG to be set. A VLOG command with
///        level less than or equal to this will be logged.
void set_vlog_level(int level);

/// Gets the verbosity threshold for VLOG. A VLOG command with a level greater
/// than this will be ignored.
///
/// \return The current verbosity threshold for VLOG.
int get_vlog_level();

/// Sets the log directory, as specified when this enclave is initialized. This
/// is only set once. Any request to reset it will return false.
///
/// \param log_directory The log file directory.
/// \return True if and only if the log directory is set successfully.
bool set_log_directory(const std::string &log_directory);

/// Gets the log directory that was specified when this enclave is initialized.
///
/// \return The directory where the log files will be.
const std::string get_log_directory();

/// Checks the log directory to make sure it's accessible, and creates it if it
/// does not exist.
///
/// \param path The directory to be checked.
bool EnsureDirectory(const char *path);

/// Initializes minimal logging library.
///
/// For untrusted logging, the program name specified by argv0 will be used as
/// log filename; For enclave logging, the enclave name will be used as log
/// filename (any slashes or dots will be removed). This method is called during
/// enclave initialization. For untrusted logging, this should be called in
/// main().
///
/// \param directory The log file directory.
/// \param file_name The name of the log file.
/// \param level The verbosity threshold for VLOG commands. A VLOG command with
///        a level equal to or lower than it will be logged.
bool InitLogging(const char *directory, const char *file_name, int level);

/// Class representing a log message created by a log macro.
class LogMessage {
 public:
  /// Constructs a new message with `INFO` severity.
  ///
  /// \param file The source file that produced the log.
  /// \param line The source code line that produced the log.
  LogMessage(const char *file, int line);

  /// Constructs a new message with the specified severity.
  ///
  /// \param file The source file that produced the log.
  /// \param line The source code line that produced the log.
  /// \param severity The severity level of the log.
  LogMessage(const char *file, int line, LogSeverity severity);

  /// Constructs a log message with additional text that is provided by CHECK
  /// macros.
  ///
  /// \param file The source file that produced the log.
  /// \param line The source code line that produced the log.
  /// \param result The result message when check fails.
  LogMessage(const char *file, int line, const std::string &result);

  /// The destructor flushes the message.
  ~LogMessage();

  /// Gets a reference to the underlying string stream.
  ///
  /// \return A reference to the underlying string stream.
  std::ostringstream &stream() { return stream_; }

 protected:
  // Sends the message to print.
  void SendToLog(const std::string &message_text);

  LogSeverity severity_;

  // stream_ reads all the input messages into a stringstream, then it's
  // converted into a string in the destructor for printing.
  std::ostringstream stream_;

 private:
  void Init(const char *file, int line, LogSeverity severity);

  LogMessage(const LogMessage &) = delete;
  void operator=(const LogMessage &) = delete;
};

/// This class is used just to take an `ostream` type and make it a `void` type
/// to satisify the ternary operator in `LOG_IF`.
/// `operand&` is used because it has precedence lower than `<<` but higher than
/// `:?`
class LogMessageVoidify {
 public:
  void operator&(const std::ostream &) {}
};

/// A LogSeverity FATAL (or QFATAL) version of LogMessage that the compiler can
/// interpret as noreturn.
class LogMessageFatal : public LogMessage {
 public:
  /// The destructor flushes the message and does not return.
  ABSL_ATTRIBUTE_NORETURN ~LogMessageFatal();

  /// Constructs a new message with FATAL severity.
  ///
  /// \param file The source file that produced the log.
  /// \param line The source code line that produced the log.
  /// \param severity The severity for the message (FATAL or QFATAL).
  LogMessageFatal(const char *file, int line, LogSeverity severity)
      : LogMessage(file, line, severity) {}

  /// Constructs a message with FATAL severity for use by CHECK macros.
  ///
  /// \param file The source file that produced the log.
  /// \param line The source code line that produced the log.
  /// \param result The result message when check fails.
  LogMessageFatal(const char *file, int line, const std::string &result)
      : LogMessage(file, line, result) {}
};

/// Logs a message if the given value of type `T` is null, and then forwards the
/// value.
///
/// In C++11, all cases can be handled by a single function. Since the value
/// category of the argument is preserved (also for rvalue references),
/// member initializer lists like the one below will compile correctly:
///
/// ```
///   Foo()
///     : x_(CHECK_NOTNULL(MethodReturningUniquePtr())) {}
/// ```
///
/// \param file The source file that produced the log.
/// \param line The source code line that produced the log.
/// \param exprtext A string representation of the code in `file` at `line`.
/// \param t The parameter being checked for null.
template <typename T>
T CheckNotNull(const char *file, int line, const char *exprtext, T &&t) {
  if (ABSL_PREDICT_FALSE(!t)) {
    LogMessage(file, line, std::string(exprtext));
  }
  return std::forward<T>(t);
}

}  // namespace asylo

#endif  // ASYLO_UTIL_LOGGING_H_

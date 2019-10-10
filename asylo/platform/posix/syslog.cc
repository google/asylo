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

#include <stdarg.h>
#include <sys/syslog.h>

#include <cstdio>
#include <memory>

#include "asylo/platform/host_call/trusted/host_calls.h"

extern "C" {

void openlog(const char *ident, int option, int facility) {
  enc_untrusted_openlog(ident, option, facility);
}

void syslog(int priority, const char *format, ...) {
  va_list args;
  va_start(args, format);
  // Get the size of the formatted string.
  int size = vsnprintf(nullptr, 0, format, args);
  va_end(args);

  // reset the arg to the input.
  va_start(args, format);
  // Create a buffer with the same size as the formatted string.
  std::unique_ptr<char[]> buffer(new char[size]);
  // Reads the formatted string to the buffer.
  vsnprintf(buffer.get(), size, format, args);
  va_end(args);
  enc_untrusted_syslog(priority, buffer.get(), size);
}

}  // extern "C"

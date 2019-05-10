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

#include "asylo/test/misc/exception.h"

namespace asylo {

TestException::TestException(int code, const std::string &message)
    : code_(code), message_(message) {}

TestException::TestException(const TestException &other)
    : code_(other.code_), message_(other.message_) {}

TestException &TestException::operator=(const TestException &other) {
  code_ = other.code_;
  message_ = other.message_;
  return *this;
}

}  // namespace asylo

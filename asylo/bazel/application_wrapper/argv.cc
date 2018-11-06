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

#include "asylo/bazel/application_wrapper/argv.h"

namespace asylo {

Argv::Argv() { InitializeArgvCStr(); }

Argv::Argv(const Argv &other) : argv_(other.argv_) { InitializeArgvCStr(); }

Argv &Argv::operator=(const Argv &other) {
  argv_ = other.argv_;
  InitializeArgvCStr();
  return *this;
}

void Argv::WriteArgvToRepeatedStringField(
    int argc, const char *const *argv,
    google::protobuf::RepeatedPtrField<std::string> *field) {
  for (int i = 0; i < argc; ++i) {
    *field->Add() = argv[i];
  }
}

int Argv::argc() const { return argv_.size(); }

char **Argv::argv() { return argv_c_str_.data(); }

void Argv::InitializeArgvCStr() {
  argv_c_str_.clear();
  argv_c_str_.reserve(argv_.size() + 1);
  for (std::string &argument : argv_) {
    argv_c_str_.push_back(&argument[0]);
  }
  argv_c_str_.push_back(nullptr);
}

}  // namespace asylo

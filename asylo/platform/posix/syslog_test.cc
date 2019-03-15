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

#include <sys/syslog.h>
#include <syslog.h>

#include <functional>
#include <string>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

namespace asylo {
namespace {

void LogNoScope(int priority, const std::string &s) {
  syslog(priority, "%s", s.c_str());
}

void LogScope(int priority, const std::string &s) {
  std::string new_string(s);
  syslog(priority, "%s", new_string.c_str());
}

std::function<void(int, const std::string &)> GetLoggerFuncInScope() {
  return [](int priority, const std::string &s) {
    std::string new_string(s);
    syslog(priority, "%s", new_string.c_str());
  };
}

std::function<void(int, const std::string &)> GetLoggerFuncOutScope() {
  return [](int priority, const std::string &s) {
    syslog(priority, "%s", s.c_str());
  };
}

TEST(AsyloLambdaTest, LambdaScopedTest) {
  GetLoggerFuncInScope()(LOG_INFO, "This is a message");
}

TEST(AsyloLambdaTest, NoLambdaScopeTest) {
  LogScope(LOG_INFO, "This is a message");
}

TEST(AsyloLambdaTest, NoLambdaNoScopeTest) {
  LogNoScope(LOG_INFO, "This is a message");
}

TEST(AsyloLambdaTest, LambdaNoScopedTest) {
  GetLoggerFuncOutScope()(LOG_INFO, "This is a message");
}

}  // namespace
}  // namespace asylo

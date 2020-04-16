/*
 *
 * Copyright 2020 Asylo authors
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

#include "asylo/util/proto_flag.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "absl/flags/flag.h"
#include "absl/flags/parse.h"
#include "asylo/enclave.pb.h"
#include "asylo/util/proto_parse_util.h"
#include "asylo/test/util/proto_matchers.h"

ABSL_FLAG(asylo::EnvironmentVariable, my_test_flag, {}, "A flag to test");

namespace asylo {
namespace {

constexpr char kTestFlag[] = R"pb(name: "foo" value: "bar")pb";

TEST(ProtoFlagTest, Parse) {
  EnvironmentVariable expected = ParseTextProtoOrDie(kTestFlag);
  EXPECT_THAT(absl::GetFlag(FLAGS_my_test_flag), EqualsProto(expected));
}

}  // namespace
}  // namespace asylo

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

#include "asylo/identity/provisioning/sgx/internal/signed_tcb_info_from_json.h"

#include <string>

#include "google/protobuf/struct.pb.h"
#include <google/protobuf/text_format.h>
#include <google/protobuf/util/json_util.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "absl/status/status.h"
#include "asylo/identity/provisioning/sgx/internal/sgx_pcs_client.pb.h"
#include "asylo/test/util/proto_matchers.h"
#include "asylo/test/util/status_matchers.h"
#include "asylo/util/error_codes.h"
#include "asylo/util/status.h"

namespace asylo {
namespace sgx {
namespace {

const char kExpectedSignedTcbInfoProto[] = R"proto(
  tcb_info_json: "{\"version\":1,\"issueDate\":\"2019-04-05T19:34:50Z\","
                 "\"nextUpdate\":\"2019-05-05T19:34:50Z\",\"fmspc\":\"00"
                 "906ea10000\",\"pceId\":\"0000\",\"tcbLevels\":[{\"tcb"
                 "\":{\"sgxtcbcomp01svn\":5,\"sgxtcbcomp02svn\":5,\"sgxt"
                 "cbcomp03svn\":2,\"sgxtcbcomp04svn\":4,\"sgxtcbcomp05sv"
                 "n\":1,\"sgxtcbcomp06svn\":128,\"sgxtcbcomp07svn\":1,\""
                 "sgxtcbcomp08svn\":0,\"sgxtcbcomp09svn\":0,\"sgxtcbcomp"
                 "10svn\":0,\"sgxtcbcomp11svn\":0,\"sgxtcbcomp12svn\":0,"
                 "\"sgxtcbcomp13svn\":0,\"sgxtcbcomp14svn\":0,\"sgxtcbco"
                 "mp15svn\":0,\"sgxtcbcomp16svn\":0,\"pcesvn\":7},\"stat"
                 "us\":\"UpToDate\"},{\"tcb\":{\"sgxtcbcomp01svn\":5,\"s"
                 "gxtcbcomp02svn\":5,\"sgxtcbcomp03svn\":2,\"sgxtcbcomp0"
                 "4svn\":4,\"sgxtcbcomp05svn\":1,\"sgxtcbcomp06svn\":128"
                 ",\"sgxtcbcomp07svn\":1,\"sgxtcbcomp08svn\":0,\"sgxtcbc"
                 "omp09svn\":0,\"sgxtcbcomp10svn\":0,\"sgxtcbcomp11svn\""
                 ":0,\"sgxtcbcomp12svn\":0,\"sgxtcbcomp13svn\":0,\"sgxtc"
                 "bcomp14svn\":0,\"sgxtcbcomp15svn\":0,\"sgxtcbcomp16svn"
                 "\":0,\"pcesvn\":6},\"status\":\"OutOfDate\"},{\"tcb\":"
                 "{\"sgxtcbcomp01svn\":5,\"sgxtcbcomp02svn\":5,\"sgxtcbc"
                 "omp03svn\":2,\"sgxtcbcomp04svn\":4,\"sgxtcbcomp05svn\""
                 ":1,\"sgxtcbcomp06svn\":128,\"sgxtcbcomp07svn\":0,\"sgx"
                 "tcbcomp08svn\":0,\"sgxtcbcomp09svn\":0,\"sgxtcbcomp10s"
                 "vn\":0,\"sgxtcbcomp11svn\":0,\"sgxtcbcomp12svn\":0,\"s"
                 "gxtcbcomp13svn\":0,\"sgxtcbcomp14svn\":0,\"sgxtcbcomp1"
                 "5svn\":0,\"sgxtcbcomp16svn\":0,\"pcesvn\":7},\"status"
                 "\":\"ConfigurationNeeded\"},{\"tcb\":{\"sgxtcbcomp01sv"
                 "n\":5,\"sgxtcbcomp02svn\":5,\"sgxtcbcomp03svn\":2,\"sg"
                 "xtcbcomp04svn\":4,\"sgxtcbcomp05svn\":1,\"sgxtcbcomp06"
                 "svn\":128,\"sgxtcbcomp07svn\":0,\"sgxtcbcomp08svn\":0,"
                 "\"sgxtcbcomp09svn\":0,\"sgxtcbcomp10svn\":0,\"sgxtcbco"
                 "mp11svn\":0,\"sgxtcbcomp12svn\":0,\"sgxtcbcomp13svn\":"
                 "0,\"sgxtcbcomp14svn\":0,\"sgxtcbcomp15svn\":0,\"sgxtcb"
                 "comp16svn\":0,\"pcesvn\":6},\"status\":\"OutOfDate\"},"
                 "{\"tcb\":{\"sgxtcbcomp01svn\":4,\"sgxtcbcomp02svn\":4,"
                 "\"sgxtcbcomp03svn\":2,\"sgxtcbcomp04svn\":4,\"sgxtcbco"
                 "mp05svn\":1,\"sgxtcbcomp06svn\":128,\"sgxtcbcomp07svn"
                 "\":0,\"sgxtcbcomp08svn\":0,\"sgxtcbcomp09svn\":0,\"sgx"
                 "tcbcomp10svn\":0,\"sgxtcbcomp11svn\":0,\"sgxtcbcomp12s"
                 "vn\":0,\"sgxtcbcomp13svn\":0,\"sgxtcbcomp14svn\":0,\"s"
                 "gxtcbcomp15svn\":0,\"sgxtcbcomp16svn\":0,\"pcesvn\":5}"
                 ",\"status\":\"OutOfDate\"},{\"tcb\":{\"sgxtcbcomp01svn"
                 "\":2,\"sgxtcbcomp02svn\":2,\"sgxtcbcomp03svn\":2,\"sgx"
                 "tcbcomp04svn\":4,\"sgxtcbcomp05svn\":1,\"sgxtcbcomp06s"
                 "vn\":128,\"sgxtcbcomp07svn\":0,\"sgxtcbcomp08svn\":0,"
                 "\"sgxtcbcomp09svn\":0,\"sgxtcbcomp10svn\":0,\"sgxtcbco"
                 "mp11svn\":0,\"sgxtcbcomp12svn\":0,\"sgxtcbcomp13svn\":"
                 "0,\"sgxtcbcomp14svn\":0,\"sgxtcbcomp15svn\":0,\"sgxtcb"
                 "comp16svn\":0,\"pcesvn\":4},\"status\":\"OutOfDate\"}]"
                 "}"
  signature: "\x8b\xda\x15\xb3\x9d\x65\x1a\x0c\xa1\xd0\xc4\x89\x26\x37\x74"
             "\x82\x1d\x4f\x3e\x01\xfc\x52\xed\x4f\x4a\x54\xad\x46\x06\x2e"
             "\x60\x31\x95\x4a\x01\xe1\x2e\xf5\x71\xd1\x3a\xfe\x13\xea\xc7"
             "\x9b\xd2\x21\x8b\xec\xe1\xfb\xea\x64\x4b\x1c\xfc\x59\xd6\xbb"
             "\xe2\x81\x33\x0e"
)proto";

constexpr char kValidSignedTcbInfoJson[] =
    "{\"tcbInfo\":{\"version\":1,\"issueDate\":\"2019-04-05T19:34:50Z\",\"n"
    "extUpdate\":\"2019-05-05T19:34:50Z\",\"fmspc\":\"00906ea10000\",\"pceI"
    "d\":\"0000\",\"tcbLevels\":[{\"tcb\":{\"sgxtcbcomp01svn\":5,\"sgxtcbco"
    "mp02svn\":5,\"sgxtcbcomp03svn\":2,\"sgxtcbcomp04svn\":4,\"sgxtcbcomp05"
    "svn\":1,\"sgxtcbcomp06svn\":128,\"sgxtcbcomp07svn\":1,\"sgxtcbcomp08sv"
    "n\":0,\"sgxtcbcomp09svn\":0,\"sgxtcbcomp10svn\":0,\"sgxtcbcomp11svn\":"
    "0,\"sgxtcbcomp12svn\":0,\"sgxtcbcomp13svn\":0,\"sgxtcbcomp14svn\":0,\""
    "sgxtcbcomp15svn\":0,\"sgxtcbcomp16svn\":0,\"pcesvn\":7},\"status\":\"U"
    "pToDate\"},{\"tcb\":{\"sgxtcbcomp01svn\":5,\"sgxtcbcomp02svn\":5,\"sgx"
    "tcbcomp03svn\":2,\"sgxtcbcomp04svn\":4,\"sgxtcbcomp05svn\":1,\"sgxtcbc"
    "omp06svn\":128,\"sgxtcbcomp07svn\":1,\"sgxtcbcomp08svn\":0,\"sgxtcbcom"
    "p09svn\":0,\"sgxtcbcomp10svn\":0,\"sgxtcbcomp11svn\":0,\"sgxtcbcomp12s"
    "vn\":0,\"sgxtcbcomp13svn\":0,\"sgxtcbcomp14svn\":0,\"sgxtcbcomp15svn\""
    ":0,\"sgxtcbcomp16svn\":0,\"pcesvn\":6},\"status\":\"OutOfDate\"},{\"tc"
    "b\":{\"sgxtcbcomp01svn\":5,\"sgxtcbcomp02svn\":5,\"sgxtcbcomp03svn\":2"
    ",\"sgxtcbcomp04svn\":4,\"sgxtcbcomp05svn\":1,\"sgxtcbcomp06svn\":128,"
    "\"sgxtcbcomp07svn\":0,\"sgxtcbcomp08svn\":0,\"sgxtcbcomp09svn\":0,\"sg"
    "xtcbcomp10svn\":0,\"sgxtcbcomp11svn\":0,\"sgxtcbcomp12svn\":0,\"sgxtcb"
    "comp13svn\":0,\"sgxtcbcomp14svn\":0,\"sgxtcbcomp15svn\":0,\"sgxtcbcomp"
    "16svn\":0,\"pcesvn\":7},\"status\":\"ConfigurationNeeded\"},{\"tcb\":{"
    "\"sgxtcbcomp01svn\":5,\"sgxtcbcomp02svn\":5,\"sgxtcbcomp03svn\":2,\"sg"
    "xtcbcomp04svn\":4,\"sgxtcbcomp05svn\":1,\"sgxtcbcomp06svn\":128,\"sgxt"
    "cbcomp07svn\":0,\"sgxtcbcomp08svn\":0,\"sgxtcbcomp09svn\":0,\"sgxtcbco"
    "mp10svn\":0,\"sgxtcbcomp11svn\":0,\"sgxtcbcomp12svn\":0,\"sgxtcbcomp13"
    "svn\":0,\"sgxtcbcomp14svn\":0,\"sgxtcbcomp15svn\":0,\"sgxtcbcomp16svn"
    "\":0,\"pcesvn\":6},\"status\":\"OutOfDate\"},{\"tcb\":{\"sgxtcbcomp01s"
    "vn\":4,\"sgxtcbcomp02svn\":4,\"sgxtcbcomp03svn\":2,\"sgxtcbcomp04svn\""
    ":4,\"sgxtcbcomp05svn\":1,\"sgxtcbcomp06svn\":128,\"sgxtcbcomp07svn\":0"
    ",\"sgxtcbcomp08svn\":0,\"sgxtcbcomp09svn\":0,\"sgxtcbcomp10svn\":0,\"s"
    "gxtcbcomp11svn\":0,\"sgxtcbcomp12svn\":0,\"sgxtcbcomp13svn\":0,\"sgxtc"
    "bcomp14svn\":0,\"sgxtcbcomp15svn\":0,\"sgxtcbcomp16svn\":0,\"pcesvn\":"
    "5},\"status\":\"OutOfDate\"},{\"tcb\":{\"sgxtcbcomp01svn\":2,\"sgxtcbc"
    "omp02svn\":2,\"sgxtcbcomp03svn\":2,\"sgxtcbcomp04svn\":4,\"sgxtcbcomp0"
    "5svn\":1,\"sgxtcbcomp06svn\":128,\"sgxtcbcomp07svn\":0,\"sgxtcbcomp08s"
    "vn\":0,\"sgxtcbcomp09svn\":0,\"sgxtcbcomp10svn\":0,\"sgxtcbcomp11svn\""
    ":0,\"sgxtcbcomp12svn\":0,\"sgxtcbcomp13svn\":0,\"sgxtcbcomp14svn\":0,"
    "\"sgxtcbcomp15svn\":0,\"sgxtcbcomp16svn\":0,\"pcesvn\":4},\"status\":"
    "\"OutOfDate\"}]},\"signature\":\"8bda15b39d651a0ca1d0c489263774821d4f3"
    "e01fc52ed4f4a54ad46062e6031954a01e12ef571d13afe13eac79bd2218bece1fbea6"
    "44b1cfc59d6bbe281330e\"}";

const char kValidSignedTcbInfoSigFirstJson[] =
    "{\"signature\":\"8bda15b39d651a0ca1d0c489263774821d4f3e01fc52ed4f4a54a"
    "d46062e6031954a01e12ef571d13afe13eac79bd2218bece1fbea644b1cfc59d6bbe28"
    "1330e\",\"tcbInfo\":{\"version\":1,\"issueDate\":\"2019-04-05T19:34:50"
    "Z\",\"nextUpdate\":\"2019-05-05T19:34:50Z\",\"fmspc\":\"00906ea10000\""
    ",\"pceId\":\"0000\",\"tcbLevels\":[{\"tcb\":{\"sgxtcbcomp01svn\":5,\"s"
    "gxtcbcomp02svn\":5,\"sgxtcbcomp03svn\":2,\"sgxtcbcomp04svn\":4,\"sgxtc"
    "bcomp05svn\":1,\"sgxtcbcomp06svn\":128,\"sgxtcbcomp07svn\":1,\"sgxtcbc"
    "omp08svn\":0,\"sgxtcbcomp09svn\":0,\"sgxtcbcomp10svn\":0,\"sgxtcbcomp1"
    "1svn\":0,\"sgxtcbcomp12svn\":0,\"sgxtcbcomp13svn\":0,\"sgxtcbcomp14svn"
    "\":0,\"sgxtcbcomp15svn\":0,\"sgxtcbcomp16svn\":0,\"pcesvn\":7},\"statu"
    "s\":\"UpToDate\"},{\"tcb\":{\"sgxtcbcomp01svn\":5,\"sgxtcbcomp02svn\":"
    "5,\"sgxtcbcomp03svn\":2,\"sgxtcbcomp04svn\":4,\"sgxtcbcomp05svn\":1,\""
    "sgxtcbcomp06svn\":128,\"sgxtcbcomp07svn\":1,\"sgxtcbcomp08svn\":0,\"sg"
    "xtcbcomp09svn\":0,\"sgxtcbcomp10svn\":0,\"sgxtcbcomp11svn\":0,\"sgxtcb"
    "comp12svn\":0,\"sgxtcbcomp13svn\":0,\"sgxtcbcomp14svn\":0,\"sgxtcbcomp"
    "15svn\":0,\"sgxtcbcomp16svn\":0,\"pcesvn\":6},\"status\":\"OutOfDate\""
    "},{\"tcb\":{\"sgxtcbcomp01svn\":5,\"sgxtcbcomp02svn\":5,\"sgxtcbcomp03"
    "svn\":2,\"sgxtcbcomp04svn\":4,\"sgxtcbcomp05svn\":1,\"sgxtcbcomp06svn"
    "\":128,\"sgxtcbcomp07svn\":0,\"sgxtcbcomp08svn\":0,\"sgxtcbcomp09svn\""
    ":0,\"sgxtcbcomp10svn\":0,\"sgxtcbcomp11svn\":0,\"sgxtcbcomp12svn\":0,"
    "\"sgxtcbcomp13svn\":0,\"sgxtcbcomp14svn\":0,\"sgxtcbcomp15svn\":0,\"sg"
    "xtcbcomp16svn\":0,\"pcesvn\":7},\"status\":\"ConfigurationNeeded\"},{"
    "\"tcb\":{\"sgxtcbcomp01svn\":5,\"sgxtcbcomp02svn\":5,\"sgxtcbcomp03svn"
    "\":2,\"sgxtcbcomp04svn\":4,\"sgxtcbcomp05svn\":1,\"sgxtcbcomp06svn\":1"
    "28,\"sgxtcbcomp07svn\":0,\"sgxtcbcomp08svn\":0,\"sgxtcbcomp09svn\":0,"
    "\"sgxtcbcomp10svn\":0,\"sgxtcbcomp11svn\":0,\"sgxtcbcomp12svn\":0,\"sg"
    "xtcbcomp13svn\":0,\"sgxtcbcomp14svn\":0,\"sgxtcbcomp15svn\":0,\"sgxtcb"
    "comp16svn\":0,\"pcesvn\":6},\"status\":\"OutOfDate\"},{\"tcb\":{\"sgxt"
    "cbcomp01svn\":4,\"sgxtcbcomp02svn\":4,\"sgxtcbcomp03svn\":2,\"sgxtcbco"
    "mp04svn\":4,\"sgxtcbcomp05svn\":1,\"sgxtcbcomp06svn\":128,\"sgxtcbcomp"
    "07svn\":0,\"sgxtcbcomp08svn\":0,\"sgxtcbcomp09svn\":0,\"sgxtcbcomp10sv"
    "n\":0,\"sgxtcbcomp11svn\":0,\"sgxtcbcomp12svn\":0,\"sgxtcbcomp13svn\":"
    "0,\"sgxtcbcomp14svn\":0,\"sgxtcbcomp15svn\":0,\"sgxtcbcomp16svn\":0,\""
    "pcesvn\":5},\"status\":\"OutOfDate\"},{\"tcb\":{\"sgxtcbcomp01svn\":2,"
    "\"sgxtcbcomp02svn\":2,\"sgxtcbcomp03svn\":2,\"sgxtcbcomp04svn\":4,\"sg"
    "xtcbcomp05svn\":1,\"sgxtcbcomp06svn\":128,\"sgxtcbcomp07svn\":0,\"sgxt"
    "cbcomp08svn\":0,\"sgxtcbcomp09svn\":0,\"sgxtcbcomp10svn\":0,\"sgxtcbco"
    "mp11svn\":0,\"sgxtcbcomp12svn\":0,\"sgxtcbcomp13svn\":0,\"sgxtcbcomp14"
    "svn\":0,\"sgxtcbcomp15svn\":0,\"sgxtcbcomp16svn\":0,\"pcesvn\":4},\"st"
    "atus\":\"OutOfDate\"}]}}";

const char kValidSignedTcbInfoWhitespaceJson[] =
    "{\"tcbInfo\":    {\"version\":1,\"issueDate\":\"2019-04-05T19:34:50Z\""
    ",\"nextUpdate\":\"2019-05-05T19:34:50Z\",\"fmspc\":\"00906ea10000\",\""
    "pceId\":\"0000\",\"tcbLevels\":[{\"tcb\":{\"sgxtcbcomp01svn\":5,\"sgxt"
    "cbcomp02svn\":5,\"sgxtcbcomp03svn\":2,\"sgxtcbcomp04svn\":4,\"sgxtcbco"
    "mp05svn\":1,\"sgxtcbcomp06svn\":128,\"sgxtcbcomp07svn\":1,\"sgxtcbcomp"
    "08svn\":0,\"sgxtcbcomp09svn\":0,\"sgxtcbcomp10svn\":0,\"sgxtcbcomp11sv"
    "n\":0,\"sgxtcbcomp12svn\":0,\"sgxtcbcomp13svn\":0,\"sgxtcbcomp14svn\":"
    "0,\"sgxtcbcomp15svn\":0,\"sgxtcbcomp16svn\":0,\"pcesvn\":7},\"status\""
    ":\"UpToDate\"},{\"tcb\":{\"sgxtcbcomp01svn\":5,\"sgxtcbcomp02svn\":5,"
    "\"sgxtcbcomp03svn\":2,\"sgxtcbcomp04svn\":4,\"sgxtcbcomp05svn\":1,\"sg"
    "xtcbcomp06svn\":128,\"sgxtcbcomp07svn\":1,\"sgxtcbcomp08svn\":0,\"sgxt"
    "cbcomp09svn\":0,\"sgxtcbcomp10svn\":0,\"sgxtcbcomp11svn\":0,\"sgxtcbco"
    "mp12svn\":0,\"sgxtcbcomp13svn\":0,\"sgxtcbcomp14svn\":0,\"sgxtcbcomp15"
    "svn\":0,\"sgxtcbcomp16svn\":0,\"pcesvn\":6},\"status\":\"OutOfDate\"},"
    "{\"tcb\":{\"sgxtcbcomp01svn\":5,\"sgxtcbcomp02svn\":5,\"sgxtcbcomp03sv"
    "n\":2,\"sgxtcbcomp04svn\":4,\"sgxtcbcomp05svn\":1,\"sgxtcbcomp06svn\":"
    "128,\"sgxtcbcomp07svn\":0,\"sgxtcbcomp08svn\":0,\"sgxtcbcomp09svn\":0,"
    "\"sgxtcbcomp10svn\":0,\"sgxtcbcomp11svn\":0,\"sgxtcbcomp12svn\":0,\"sg"
    "xtcbcomp13svn\":0,\"sgxtcbcomp14svn\":0,\"sgxtcbcomp15svn\":0,\"sgxtcb"
    "comp16svn\":0,\"pcesvn\":7},\"status\":\"ConfigurationNeeded\"},{\"tcb"
    "\":{\"sgxtcbcomp01svn\":5,\"sgxtcbcomp02svn\":5,\"sgxtcbcomp03svn\":2,"
    "\"sgxtcbcomp04svn\":4,\"sgxtcbcomp05svn\":1,\"sgxtcbcomp06svn\":128,\""
    "sgxtcbcomp07svn\":0,\"sgxtcbcomp08svn\":0,\"sgxtcbcomp09svn\":0,\"sgxt"
    "cbcomp10svn\":0,\"sgxtcbcomp11svn\":0,\"sgxtcbcomp12svn\":0,\"sgxtcbco"
    "mp13svn\":0,\"sgxtcbcomp14svn\":0,\"sgxtcbcomp15svn\":0,\"sgxtcbcomp16"
    "svn\":0,\"pcesvn\":6},\"status\":\"OutOfDate\"},{\"tcb\":{\"sgxtcbcomp"
    "01svn\":4,\"sgxtcbcomp02svn\":4,\"sgxtcbcomp03svn\":2,\"sgxtcbcomp04sv"
    "n\":4,\"sgxtcbcomp05svn\":1,\"sgxtcbcomp06svn\":128,\"sgxtcbcomp07svn"
    "\":0,\"sgxtcbcomp08svn\":0,\"sgxtcbcomp09svn\":0,\"sgxtcbcomp10svn\":0"
    ",\"sgxtcbcomp11svn\":0,\"sgxtcbcomp12svn\":0,\"sgxtcbcomp13svn\":0,\"s"
    "gxtcbcomp14svn\":0,\"sgxtcbcomp15svn\":0,\"sgxtcbcomp16svn\":0,\"pcesv"
    "n\":5},\"status\":\"OutOfDate\"},{\"tcb\":{\"sgxtcbcomp01svn\":2,\"sgx"
    "tcbcomp02svn\":2,\"sgxtcbcomp03svn\":2,\"sgxtcbcomp04svn\":4,\"sgxtcbc"
    "omp05svn\":1,\"sgxtcbcomp06svn\":128,\"sgxtcbcomp07svn\":0,\"sgxtcbcom"
    "p08svn\":0,\"sgxtcbcomp09svn\":0,\"sgxtcbcomp10svn\":0,\"sgxtcbcomp11s"
    "vn\":0,\"sgxtcbcomp12svn\":0,\"sgxtcbcomp13svn\":0,\"sgxtcbcomp14svn\""
    ":0,\"sgxtcbcomp15svn\":0,\"sgxtcbcomp16svn\":0,\"pcesvn\":4},\"status"
    "\":\"OutOfDate\"}]},            \"signature\"    :         \"8bda15b39"
    "d651a0ca1d0c489263774821d4f3e01fc52ed4f4a54ad46062e6031954a01e12ef571d"
    "13afe13eac79bd2218bece1fbea644b1cfc59d6bbe281330e\"}";

const char kInvalidSignedTcbInfoExtraFieldsJson[] =
    "{\"tcbInfo\":{\"version\":1,\"issueDate\":\"2019-04-05T19:34:50Z\",\"n"
    "extUpdate\":\"2019-05-05T19:34:50Z\",\"fmspc\":\"00906ea10000\",\"pceI"
    "d\":\"0000\",\"tcbLevels\":[{\"tcb\":{\"sgxtcbcomp01svn\":5,\"sgxtcbco"
    "mp02svn\":5,\"sgxtcbcomp03svn\":2,\"sgxtcbcomp04svn\":4,\"sgxtcbcomp05"
    "svn\":1,\"sgxtcbcomp06svn\":128,\"sgxtcbcomp07svn\":1,\"sgxtcbcomp08sv"
    "n\":0,\"sgxtcbcomp09svn\":0,\"sgxtcbcomp10svn\":0,\"sgxtcbcomp11svn\":"
    "0,\"sgxtcbcomp12svn\":0,\"sgxtcbcomp13svn\":0,\"sgxtcbcomp14svn\":0,\""
    "sgxtcbcomp15svn\":0,\"sgxtcbcomp16svn\":0,\"pcesvn\":7},\"status\":\"U"
    "pToDate\"},{\"tcb\":{\"sgxtcbcomp01svn\":5,\"sgxtcbcomp02svn\":5,\"sgx"
    "tcbcomp03svn\":2,\"sgxtcbcomp04svn\":4,\"sgxtcbcomp05svn\":1,\"sgxtcbc"
    "omp06svn\":128,\"sgxtcbcomp07svn\":1,\"sgxtcbcomp08svn\":0,\"sgxtcbcom"
    "p09svn\":0,\"sgxtcbcomp10svn\":0,\"sgxtcbcomp11svn\":0,\"sgxtcbcomp12s"
    "vn\":0,\"sgxtcbcomp13svn\":0,\"sgxtcbcomp14svn\":0,\"sgxtcbcomp15svn\""
    ":0,\"sgxtcbcomp16svn\":0,\"pcesvn\":6},\"status\":\"OutOfDate\"},{\"tc"
    "b\":{\"sgxtcbcomp01svn\":5,\"sgxtcbcomp02svn\":5,\"sgxtcbcomp03svn\":2"
    ",\"sgxtcbcomp04svn\":4,\"sgxtcbcomp05svn\":1,\"sgxtcbcomp06svn\":128,"
    "\"sgxtcbcomp07svn\":0,\"sgxtcbcomp08svn\":0,\"sgxtcbcomp09svn\":0,\"sg"
    "xtcbcomp10svn\":0,\"sgxtcbcomp11svn\":0,\"sgxtcbcomp12svn\":0,\"sgxtcb"
    "comp13svn\":0,\"sgxtcbcomp14svn\":0,\"sgxtcbcomp15svn\":0,\"sgxtcbcomp"
    "16svn\":0,\"pcesvn\":7},\"status\":\"ConfigurationNeeded\"},{\"tcb\":{"
    "\"sgxtcbcomp01svn\":5,\"sgxtcbcomp02svn\":5,\"sgxtcbcomp03svn\":2,\"sg"
    "xtcbcomp04svn\":4,\"sgxtcbcomp05svn\":1,\"sgxtcbcomp06svn\":128,\"sgxt"
    "cbcomp07svn\":0,\"sgxtcbcomp08svn\":0,\"sgxtcbcomp09svn\":0,\"sgxtcbco"
    "mp10svn\":0,\"sgxtcbcomp11svn\":0,\"sgxtcbcomp12svn\":0,\"sgxtcbcomp13"
    "svn\":0,\"sgxtcbcomp14svn\":0,\"sgxtcbcomp15svn\":0,\"sgxtcbcomp16svn"
    "\":0,\"pcesvn\":6},\"status\":\"OutOfDate\"},{\"tcb\":{\"sgxtcbcomp01s"
    "vn\":4,\"sgxtcbcomp02svn\":4,\"sgxtcbcomp03svn\":2,\"sgxtcbcomp04svn\""
    ":4,\"sgxtcbcomp05svn\":1,\"sgxtcbcomp06svn\":128,\"sgxtcbcomp07svn\":0"
    ",\"sgxtcbcomp08svn\":0,\"sgxtcbcomp09svn\":0,\"sgxtcbcomp10svn\":0,\"s"
    "gxtcbcomp11svn\":0,\"sgxtcbcomp12svn\":0,\"sgxtcbcomp13svn\":0,\"sgxtc"
    "bcomp14svn\":0,\"sgxtcbcomp15svn\":0,\"sgxtcbcomp16svn\":0,\"pcesvn\":"
    "5},\"status\":\"OutOfDate\"},{\"tcb\":{\"sgxtcbcomp01svn\":2,\"sgxtcbc"
    "omp02svn\":2,\"sgxtcbcomp03svn\":2,\"sgxtcbcomp04svn\":4,\"sgxtcbcomp0"
    "5svn\":1,\"sgxtcbcomp06svn\":128,\"sgxtcbcomp07svn\":0,\"sgxtcbcomp08s"
    "vn\":0,\"sgxtcbcomp09svn\":0,\"sgxtcbcomp10svn\":0,\"sgxtcbcomp11svn\""
    ":0,\"sgxtcbcomp12svn\":0,\"sgxtcbcomp13svn\":0,\"sgxtcbcomp14svn\":0,"
    "\"sgxtcbcomp15svn\":0,\"sgxtcbcomp16svn\":0,\"pcesvn\":4},\"status\":"
    "\"OutOfDate\"}]},\"signature\":\"8bda15b39d651a0ca1d0c489263774821d4f3"
    "e01fc52ed4f4a54ad46062e6031954a01e12ef571d13afe13eac79bd2218bece1fbea6"
    "44b1cfc59d6bbe281330e\",\"extra_fields\":\"veryextra\"}";

// Returns a valid JSON string of a signed TCB info.
google::protobuf::Value CreateValidSignedTcbInfoFromJson() {
  google::protobuf::Value signed_tcb_info;
  ASYLO_CHECK_OK(Status(google::protobuf::util::JsonStringToMessage(
      kValidSignedTcbInfoJson, &signed_tcb_info)));
  return signed_tcb_info;
}

// Returns a string representation of |json|.
std::string JsonToString(const google::protobuf::Value &json) {
  std::string json_string;
  ASYLO_CHECK_OK(Status(google::protobuf::util::MessageToJsonString(json, &json_string)));
  return json_string;
}

TEST(SignedTcbInfoFromJsonTest, ImproperJsonFailsToParse) {
  EXPECT_THAT(SignedTcbInfoFromJson("} Wait a minute! This isn't proper JSON!"),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(SignedTcbInfoFromJsonTest, NonObjectJsonValueFailsToParse) {
  EXPECT_THAT(SignedTcbInfoFromJson("[\"An array, not an object\"]"),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(SignedTcbInfoFromJsonTest, ExtraFieldsFailsToParse) {
  EXPECT_THAT(SignedTcbInfoFromJson(kInvalidSignedTcbInfoExtraFieldsJson),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(SignedTcbInfoFromJsonTest, NonJsonObjectTcbInfoFieldFailsToParse) {
  google::protobuf::Value json = CreateValidSignedTcbInfoFromJson();
  json.mutable_struct_value()->mutable_fields()->at("tcbInfo").set_string_value(
      "Non JSON-object tcbInfo field");
  EXPECT_THAT(SignedTcbInfoFromJson(JsonToString(json)),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(SignedTcbInfoFromJsonTest, NonHexEncodedSignatureFailsToParse) {
  google::protobuf::Value json = CreateValidSignedTcbInfoFromJson();
  json.mutable_struct_value()
      ->mutable_fields()
      ->at("signature")
      .set_string_value("Non hex-encoded");
  EXPECT_THAT(SignedTcbInfoFromJson(JsonToString(json)),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(SignedTcbInfoFromJsonTest,
     SignedTcbInfoWithoutWhitespaceParsesSuccessfully) {
  SignedTcbInfo signed_tcb_info_proto;
  ASYLO_ASSERT_OK_AND_ASSIGN(signed_tcb_info_proto,
                             SignedTcbInfoFromJson(kValidSignedTcbInfoJson));
  SignedTcbInfo expected_signed_tcb_info_proto;
  ASSERT_TRUE(google::protobuf::TextFormat::ParseFromString(
      kExpectedSignedTcbInfoProto, &expected_signed_tcb_info_proto));
  EXPECT_THAT(signed_tcb_info_proto,
              EqualsProto(expected_signed_tcb_info_proto));
}

TEST(SignedTcbInfoFromJsonTest, SignedTcbInfoWithWhitespaceParsesSuccessfully) {
  SignedTcbInfo signed_tcb_info_proto;
  ASYLO_ASSERT_OK_AND_ASSIGN(
      signed_tcb_info_proto,
      SignedTcbInfoFromJson(kValidSignedTcbInfoWhitespaceJson));
  SignedTcbInfo expected_signed_tcb_info_proto;
  ASSERT_TRUE(google::protobuf::TextFormat::ParseFromString(
      kExpectedSignedTcbInfoProto, &expected_signed_tcb_info_proto));
  EXPECT_THAT(signed_tcb_info_proto,
              EqualsProto(expected_signed_tcb_info_proto));
}

TEST(SignedTcbInfoFromJsonTest,
     SignedTcbInfoWithSignatureFirstParsesSuccessfully) {
  SignedTcbInfo signed_tcb_info_proto;
  ASYLO_ASSERT_OK_AND_ASSIGN(
      signed_tcb_info_proto,
      SignedTcbInfoFromJson(kValidSignedTcbInfoSigFirstJson));
  SignedTcbInfo expected_signed_tcb_info_proto;
  ASSERT_TRUE(google::protobuf::TextFormat::ParseFromString(
      kExpectedSignedTcbInfoProto, &expected_signed_tcb_info_proto));
  EXPECT_THAT(signed_tcb_info_proto,
              EqualsProto(expected_signed_tcb_info_proto));
}

}  // namespace
}  // namespace sgx
}  // namespace asylo

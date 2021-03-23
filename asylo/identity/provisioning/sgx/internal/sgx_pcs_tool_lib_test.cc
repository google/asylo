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

#include "asylo/identity/provisioning/sgx/internal/sgx_pcs_tool_lib.h"

#include <fcntl.h>

#include <cstdlib>
#include <iterator>
#include <memory>

#include <google/protobuf/io/zero_copy_stream_impl.h>
#include <google/protobuf/text_format.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "absl/flags/flag.h"
#include "absl/flags/reflection.h"
#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "asylo/identity/attestation/sgx/internal/dcap_intel_architectural_enclave_path_setter.h"
#include "asylo/identity/provisioning/sgx/internal/platform_provisioning.h"
#include "asylo/identity/provisioning/sgx/internal/sgx_pcs_client.h"
#include "asylo/test/util/memory_matchers.h"
#include "asylo/test/util/proto_matchers.h"
#include "asylo/test/util/status_matchers.h"
#include "asylo/util/posix_error_matchers.h"
#include "asylo/util/proto_parse_util.h"

namespace asylo {
namespace sgx {
namespace {

using ::testing::Eq;
using ::testing::HasSubstr;
using ::testing::Ne;
using ::testing::NotNull;
using ::testing::Test;

constexpr char kValidPpidHex[] = "0f0e0d0c0b0a0908070605040302010f";
constexpr char kValidPpid[] =
    "\xf\xe\xd\xc\xb\xa\x9\x8\x7\x6\x5\x4\x3\x2\x1\xf";

constexpr char kValidCpuSvnHex[] = "0102030405060708090a0b0c0d0e0f01";
constexpr char kValidCpuSvn[] =
    "\x1\x2\x3\x4\x5\x6\x7\x8\x9\xa\xb\xc\xd\xe\xf\x1";

constexpr int kValidPceSvn = 1;

// A few generated test certs for filling data structures. The PEMs here must
// match the DER values in kDerCertProtos.
constexpr std::array<absl::string_view, 3> kPemCertProtos{
    R"proto(
      format: X509_PEM
      data: "-----BEGIN CERTIFICATE-----\n"
            "MIIBnjCCAWSgAwIBAgIUQkn1DMn0h71kvjtjXVtqNuTjdVcwCgYIKoZIzj0EAwIw\n"
            "RTELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoMGElu\n"
            "dGVybmV0IFdpZGdpdHMgUHR5IEx0ZDAgFw0yMDA2MjMyMzE2MzRaGA8yMTIwMDUz\n"
            "MDIzMTYzNFowRTELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAf\n"
            "BgNVBAoMGEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDA2MBAGByqGSM49AgEGBSuB\n"
            "BAAcAyIABOkNhLtsrAAghr83M5PJsvPAp0UtGa1PdCZDF+cuEHqZo1MwUTAdBgNV\n"
            "HQ4EFgQUMNe2jU0Hqx707RWLTePRvGvvQpswHwYDVR0jBBgwFoAUMNe2jU0Hqx70\n"
            "7RWLTePRvGvvQpswDwYDVR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDAgMoADAlAhEA\n"
            "1e31mxjI7uwuaP+U/VH20wIQdLFzKMUdt6hJgBanwETNQw==\n"
            "-----END CERTIFICATE-----\n"
    )proto",
    R"proto(
      format: X509_PEM
      data: "-----BEGIN CERTIFICATE-----\n"
            "MIIBnTCCAWSgAwIBAgIUWejuS5x7RqcYCPzECY8ThdkbB88wCgYIKoZIzj0EAwIw\n"
            "RTELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoMGElu\n"
            "dGVybmV0IFdpZGdpdHMgUHR5IEx0ZDAgFw0yMDA2MjMyMzI3MTVaGA8yMTIwMDUz\n"
            "MDIzMjcxNVowRTELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAf\n"
            "BgNVBAoMGEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDA2MBAGByqGSM49AgEGBSuB\n"
            "BAAcAyIABPosZ3ms9pXdj97/g1rxFSfZf07zSf/tIku7ge6ZcMYEo1MwUTAdBgNV\n"
            "HQ4EFgQUrFz8J8IulPUfsCbFvaB+vTqKAy8wHwYDVR0jBBgwFoAUrFz8J8IulPUf\n"
            "sCbFvaB+vTqKAy8wDwYDVR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDAgMnADAkAhAp\n"
            "alLWbPKrUHCGQg+rQbqIAhB7OaZHSZMERw/TNZ2QMY1v\n"
            "-----END CERTIFICATE-----\n"
    )proto",
    R"proto(
      format: X509_PEM
      data: "-----BEGIN CERTIFICATE-----\n"
            "MIIBnTCCAWSgAwIBAgIUexkD7Zv5O4SAVifZio+JWVqHjFswCgYIKoZIzj0EAwIw\n"
            "RTELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoMGElu\n"
            "dGVybmV0IFdpZGdpdHMgUHR5IEx0ZDAgFw0yMDA2MjMyMzI4MDZaGA8yMTIwMDUz\n"
            "MDIzMjgwNlowRTELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAf\n"
            "BgNVBAoMGEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDA2MBAGByqGSM49AgEGBSuB\n"
            "BAAcAyIABDd0Fboh4UVeDaOyQ/uHAz7MNxHiggm1VnIbAwQqfjv8o1MwUTAdBgNV\n"
            "HQ4EFgQUkUuhgC4puBVALZZP/PkT42GhDL8wHwYDVR0jBBgwFoAUkUuhgC4puBVA\n"
            "LZZP/PkT42GhDL8wDwYDVR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDAgMnADAkAhBe\n"
            "w1/AUZkDIcM8QmGXta0mAhARBFgqRaeBmlODffvRoSdI\n"
            "-----END CERTIFICATE-----\n"
    )proto",
};

// Must match the PEM values in kPemCertProtos.
constexpr std::array<absl::string_view, 3> kDerCertProtos = {
    R"proto(
      format: X509_DER
      data: "0\202\001\2360\202\001d\240\003\002\001\002\002\024BI\365\014\311\364\207\275d\276;c][j6\344\343uW0\n\006\010*\206H\316=\004\003\0020E1\0130\t\006\003U\004\006\023\002AU1\0230\021\006\003U\004\010\014\nSome-State1!0\037\006\003U\004\n\014\030Internet Widgits Pty Ltd0 \027\r200623231634Z\030\01721200530231634Z0E1\0130\t\006\003U\004\006\023\002AU1\0230\021\006\003U\004\010\014\nSome-State1!0\037\006\003U\004\n\014\030Internet Widgits Pty Ltd060\020\006\007*\206H\316=\002\001\006\005+\201\004\000\034\003\"\000\004\351\r\204\273l\254\000 \206\27773\223\311\262\363\300\247E-\031\255Ot&C\027\347.\020z\231\243S0Q0\035\006\003U\035\016\004\026\004\0240\327\266\215M\007\253\036\364\355\025\213M\343\321\274k\357B\2330\037\006\003U\035#\004\0300\026\200\0240\327\266\215M\007\253\036\364\355\025\213M\343\321\274k\357B\2330\017\006\003U\035\023\001\001\377\004\0050\003\001\001\3770\n\006\010*\206H\316=\004\003\002\003(\0000%\002\021\000\325\355\365\233\030\310\356\354.h\377\224\375Q\366\323\002\020t\261s(\305\035\267\250I\200\026\247\300D\315C"
    )proto",
    R"proto(
      format: X509_DER
      data: "0\202\001\2350\202\001d\240\003\002\001\002\002\024Y\350\356K\234{F\247\030\010\374\304\t\217\023\205\331\033\007\3170\n\006\010*\206H\316=\004\003\0020E1\0130\t\006\003U\004\006\023\002AU1\0230\021\006\003U\004\010\014\nSome-State1!0\037\006\003U\004\n\014\030Internet Widgits Pty Ltd0 \027\r200623232715Z\030\01721200530232715Z0E1\0130\t\006\003U\004\006\023\002AU1\0230\021\006\003U\004\010\014\nSome-State1!0\037\006\003U\004\n\014\030Internet Widgits Pty Ltd060\020\006\007*\206H\316=\002\001\006\005+\201\004\000\034\003\"\000\004\372,gy\254\366\225\335\217\336\377\203Z\361\025\'\331\177N\363I\377\355\"K\273\201\356\231p\306\004\243S0Q0\035\006\003U\035\016\004\026\004\024\254\\\374\'\302.\224\365\037\260&\305\275\240~\275:\212\003/0\037\006\003U\035#\004\0300\026\200\024\254\\\374\'\302.\224\365\037\260&\305\275\240~\275:\212\003/0\017\006\003U\035\023\001\001\377\004\0050\003\001\001\3770\n\006\010*\206H\316=\004\003\002\003\'\0000$\002\020)jR\326l\362\253Pp\206B\017\253A\272\210\002\020{9\246GI\223\004G\017\3235\235\2201\215o"
    )proto",
    R"proto(
      format: X509_DER
      data: "0\202\001\2350\202\001d\240\003\002\001\002\002\024{\031\003\355\233\371;\204\200V\'\331\212\217\211YZ\207\214[0\n\006\010*\206H\316=\004\003\0020E1\0130\t\006\003U\004\006\023\002AU1\0230\021\006\003U\004\010\014\nSome-State1!0\037\006\003U\004\n\014\030Internet Widgits Pty Ltd0 \027\r200623232806Z\030\01721200530232806Z0E1\0130\t\006\003U\004\006\023\002AU1\0230\021\006\003U\004\010\014\nSome-State1!0\037\006\003U\004\n\014\030Internet Widgits Pty Ltd060\020\006\007*\206H\316=\002\001\006\005+\201\004\000\034\003\"\000\0047t\025\272!\341E^\r\243\262C\373\207\003>\3147\021\342\202\t\265Vr\033\003\004*~;\374\243S0Q0\035\006\003U\035\016\004\026\004\024\221K\241\200.)\270\025@-\226O\374\371\023\343a\241\014\2770\037\006\003U\035#\004\0300\026\200\024\221K\241\200.)\270\025@-\226O\374\371\023\343a\241\014\2770\017\006\003U\035\023\001\001\377\004\0050\003\001\001\3770\n\006\010*\206H\316=\004\003\002\003\'\0000$\002\020^\303_\300Q\231\003!\303<Ba\227\265\255&\002\020\021\004X*E\247\201\232S\203}\373\321\241\'H"
    )proto",
};

// All of the test certs PEM encoded and concatenated.
constexpr absl::string_view kAllPems =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIBnjCCAWSgAwIBAgIUQkn1DMn0h71kvjtjXVtqNuTjdVcwCgYIKoZIzj0EAwIw\n"
    "RTELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoMGElu\n"
    "dGVybmV0IFdpZGdpdHMgUHR5IEx0ZDAgFw0yMDA2MjMyMzE2MzRaGA8yMTIwMDUz\n"
    "MDIzMTYzNFowRTELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAf\n"
    "BgNVBAoMGEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDA2MBAGByqGSM49AgEGBSuB\n"
    "BAAcAyIABOkNhLtsrAAghr83M5PJsvPAp0UtGa1PdCZDF+cuEHqZo1MwUTAdBgNV\n"
    "HQ4EFgQUMNe2jU0Hqx707RWLTePRvGvvQpswHwYDVR0jBBgwFoAUMNe2jU0Hqx70\n"
    "7RWLTePRvGvvQpswDwYDVR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDAgMoADAlAhEA\n"
    "1e31mxjI7uwuaP+U/VH20wIQdLFzKMUdt6hJgBanwETNQw==\n"
    "-----END CERTIFICATE-----\n"
    "-----BEGIN CERTIFICATE-----\n"
    "MIIBnTCCAWSgAwIBAgIUWejuS5x7RqcYCPzECY8ThdkbB88wCgYIKoZIzj0EAwIw\n"
    "RTELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoMGElu\n"
    "dGVybmV0IFdpZGdpdHMgUHR5IEx0ZDAgFw0yMDA2MjMyMzI3MTVaGA8yMTIwMDUz\n"
    "MDIzMjcxNVowRTELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAf\n"
    "BgNVBAoMGEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDA2MBAGByqGSM49AgEGBSuB\n"
    "BAAcAyIABPosZ3ms9pXdj97/g1rxFSfZf07zSf/tIku7ge6ZcMYEo1MwUTAdBgNV\n"
    "HQ4EFgQUrFz8J8IulPUfsCbFvaB+vTqKAy8wHwYDVR0jBBgwFoAUrFz8J8IulPUf\n"
    "sCbFvaB+vTqKAy8wDwYDVR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDAgMnADAkAhAp\n"
    "alLWbPKrUHCGQg+rQbqIAhB7OaZHSZMERw/TNZ2QMY1v\n"
    "-----END CERTIFICATE-----\n"
    "-----BEGIN CERTIFICATE-----\n"
    "MIIBnTCCAWSgAwIBAgIUexkD7Zv5O4SAVifZio+JWVqHjFswCgYIKoZIzj0EAwIw\n"
    "RTELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoMGElu\n"
    "dGVybmV0IFdpZGdpdHMgUHR5IEx0ZDAgFw0yMDA2MjMyMzI4MDZaGA8yMTIwMDUz\n"
    "MDIzMjgwNlowRTELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAf\n"
    "BgNVBAoMGEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDA2MBAGByqGSM49AgEGBSuB\n"
    "BAAcAyIABDd0Fboh4UVeDaOyQ/uHAz7MNxHiggm1VnIbAwQqfjv8o1MwUTAdBgNV\n"
    "HQ4EFgQUkUuhgC4puBVALZZP/PkT42GhDL8wHwYDVR0jBBgwFoAUkUuhgC4puBVA\n"
    "LZZP/PkT42GhDL8wDwYDVR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDAgMnADAkAhBe\n"
    "w1/AUZkDIcM8QmGXta0mAhARBFgqRaeBmlODffvRoSdI\n"
    "-----END CERTIFICATE-----\n";

class SgxPcsToolLibTest : public Test {
 protected:
  void TearDown() override {
    if (temp_fd_ != -1) {
      EXPECT_THAT(close(temp_fd_), Eq(0));
    }
    if (!temp_filename_.empty()) {
      EXPECT_THAT(unlink(temp_filename_.c_str()), Eq(0));
    }
  }

  void OpenTempFile() {
    char tmpl[64] = "/tmp/sgx_pcs_tool_lib_test_XXXXXX";
    int write_fd = mkstemp(tmpl);
    ASSERT_THAT(write_fd, Ne(-1)) << strerror(errno);
    temp_filename_ = tmpl;

    temp_fd_ = open(temp_filename_.c_str(), O_RDONLY);
    ASSERT_THAT(temp_fd_, Ne(-1)) << strerror(errno);
    ASSERT_THAT(close(write_fd), Eq(0)) << strerror(errno);
  }

  absl::FlagSaver flagsaver_;  // Resets the flags on every test.
  std::string temp_filename_;
  int temp_fd_ = -1;
};

TEST_F(SgxPcsToolLibTest, FillEmptyFieldsWhenAllFieldsAreEmpty) {
  PlatformInfo full;
  full.ppid.set_value(kValidPpid);
  full.cpu_svn.set_value(kValidCpuSvn);
  full.pce_svn.set_value(kValidPceSvn);
  full.pce_id.set_value(kSupportedPceId);

  PlatformInfo initially_empty;
  initially_empty.FillEmptyFields(full);
  EXPECT_THAT(initially_empty.ppid.value(), Eq(kValidPpid));
  EXPECT_THAT(initially_empty.cpu_svn.value(), Eq(kValidCpuSvn));
  EXPECT_THAT(initially_empty.pce_svn.value(), Eq(kValidPceSvn));
  EXPECT_THAT(initially_empty.pce_id.value(), Eq(kSupportedPceId));
}

TEST_F(SgxPcsToolLibTest, FillEmptyFieldsWhenNoNoFieldsAreEmpty) {
  PlatformInfo full;
  full.ppid.set_value(kValidPpid);
  full.cpu_svn.set_value(kValidCpuSvn);
  full.pce_svn.set_value(kValidPceSvn);
  full.pce_id.set_value(kSupportedPceId);

  PlatformInfo also_full;
  also_full.ppid.set_value("ppid");
  also_full.cpu_svn.set_value("cpusvn");
  also_full.pce_svn.set_value(12345678);
  also_full.pce_id.set_value(42);

  // Ensure none of the fields in full got overwritten.
  full.FillEmptyFields(also_full);
  EXPECT_THAT(full.ppid.value(), Eq(kValidPpid));
  EXPECT_THAT(full.cpu_svn.value(), Eq(kValidCpuSvn));
  EXPECT_THAT(full.pce_svn.value(), Eq(kValidPceSvn));
  EXPECT_THAT(full.pce_id.value(), Eq(kSupportedPceId));
}

TEST_F(SgxPcsToolLibTest, FillEmptyFieldsWithEmptyInput) {
  PlatformInfo initially_empty;
  initially_empty.FillEmptyFields(PlatformInfo{});

  EXPECT_FALSE(initially_empty.ppid.has_value());
  EXPECT_FALSE(initially_empty.cpu_svn.has_value());
  EXPECT_FALSE(initially_empty.pce_svn.has_value());
  EXPECT_FALSE(initially_empty.pce_id.has_value());
}

TEST_F(SgxPcsToolLibTest, MissingPpidFlagWithGetPlatformInfo) {
  absl::SetFlag(&FLAGS_cpu_svn, kValidCpuSvnHex);
  absl::SetFlag(&FLAGS_pce_svn, kValidPceSvn);

  PlatformInfo info;
  ASYLO_ASSERT_OK_AND_ASSIGN(info, GetPlatformInfoFromFlags());
  EXPECT_FALSE(info.ppid.has_value());
  EXPECT_THAT(info.cpu_svn.value(), Eq(kValidCpuSvn));
  EXPECT_THAT(info.pce_svn.value(), Eq(kValidPceSvn));
  EXPECT_THAT(info.pce_id.value(), Eq(kSupportedPceId));
}

TEST_F(SgxPcsToolLibTest, InvalidPpidFlagWithGetPlatformInfo) {
  absl::SetFlag(&FLAGS_ppid, "totally bogus");
  absl::SetFlag(&FLAGS_cpu_svn, kValidCpuSvnHex);
  absl::SetFlag(&FLAGS_pce_svn, kValidPceSvn);

  EXPECT_THAT(GetPlatformInfoFromFlags(),
              StatusIs(absl::StatusCode::kInvalidArgument, HasSubstr("Ppid")));
}

TEST_F(SgxPcsToolLibTest, MissingCpuSvnFlagWithGetPlatformInfo) {
  absl::SetFlag(&FLAGS_ppid, kValidPpidHex);
  absl::SetFlag(&FLAGS_pce_svn, kValidPceSvn);

  PlatformInfo info;
  ASYLO_ASSERT_OK_AND_ASSIGN(info, GetPlatformInfoFromFlags());
  EXPECT_THAT(info.ppid.value(), Eq(kValidPpid));
  EXPECT_FALSE(info.cpu_svn.has_value());
  EXPECT_THAT(info.pce_svn.value(), Eq(kValidPceSvn));
  EXPECT_THAT(info.pce_id.value(), Eq(kSupportedPceId));
}

TEST_F(SgxPcsToolLibTest, InvalidCpuSvnFlagWithGetPlatformInfo) {
  absl::SetFlag(&FLAGS_ppid, kValidPpidHex);
  absl::SetFlag(&FLAGS_cpu_svn, "not a secure version number");
  absl::SetFlag(&FLAGS_pce_svn, kValidPceSvn);
  EXPECT_THAT(
      GetPlatformInfoFromFlags(),
      StatusIs(absl::StatusCode::kInvalidArgument, HasSubstr("CpuSvn")));
}

TEST_F(SgxPcsToolLibTest, MissingPceSvnFlagWithGetPlatformInfo) {
  absl::SetFlag(&FLAGS_ppid, kValidPpidHex);
  absl::SetFlag(&FLAGS_cpu_svn, kValidCpuSvnHex);

  PlatformInfo info;
  ASYLO_ASSERT_OK_AND_ASSIGN(info, GetPlatformInfoFromFlags());
  EXPECT_THAT(info.ppid.value(), Eq(kValidPpid));
  EXPECT_THAT(info.cpu_svn.value(), Eq(kValidCpuSvn));
  EXPECT_THAT(info.pce_id.value(), Eq(kSupportedPceId));
  EXPECT_FALSE(info.pce_svn.has_value());
}

TEST_F(SgxPcsToolLibTest, InvalidPceSvnFlagWithGetPlatformInfo) {
  absl::SetFlag(&FLAGS_ppid, kValidPpidHex);
  absl::SetFlag(&FLAGS_cpu_svn, kValidCpuSvnHex);
  absl::SetFlag(&FLAGS_pce_svn, kPceSvnMaxValue + 1);
  EXPECT_THAT(
      GetPlatformInfoFromFlags(),
      StatusIs(absl::StatusCode::kInvalidArgument, HasSubstr("PceSvn")));
}

TEST_F(SgxPcsToolLibTest, AllInfoFlags) {
  absl::SetFlag(&FLAGS_ppid, kValidPpidHex);
  absl::SetFlag(&FLAGS_cpu_svn, kValidCpuSvnHex);
  absl::SetFlag(&FLAGS_pce_svn, kValidPceSvn);

  PlatformInfo info;
  ASYLO_ASSERT_OK_AND_ASSIGN(info, GetPlatformInfoFromFlags());
  EXPECT_THAT(info.ppid.value(), Eq(kValidPpid));
  EXPECT_THAT(info.cpu_svn.value(), Eq(kValidCpuSvn));
  EXPECT_THAT(info.pce_svn.value(), Eq(kValidPceSvn));
  EXPECT_THAT(info.pce_id.value(), Eq(kSupportedPceId));
}

TEST_F(SgxPcsToolLibTest, GetPlatformInfoFromDcapWithInvalidSection) {
  EXPECT_THAT(GetPlatformInfoFromDcap("bogus section name"),
              StatusIs(absl::StatusCode::kNotFound));
}

TEST_F(SgxPcsToolLibTest, MissingApiKeyFlagWithCreateSgxPcsClient) {
  EXPECT_THAT(CreateSgxPcsClientFromFlags(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr(FLAGS_api_key.Name())));
}

TEST_F(SgxPcsToolLibTest, CreateSgxPcsClient) {
  absl::SetFlag(&FLAGS_api_key, "not a real key but it's ok");
  EXPECT_THAT(CreateSgxPcsClientFromFlags(), IsOkAndHolds(NotNull()));
}

TEST_F(SgxPcsToolLibTest, WritePemOutputWithInvalidPath) {
  absl::SetFlag(&FLAGS_outfile, "/totally/bogus/path/that/does/not/exist");
  absl::SetFlag(&FLAGS_outfmt, "pem");
  EXPECT_THAT(WriteOutputAccordingToFlags(GetPckCertificateResult{}),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_F(SgxPcsToolLibTest, WriteProtoOutputWithInvalidPath) {
  absl::SetFlag(&FLAGS_outfile, "/totally/bogus/path/that/does/not/exist");
  absl::SetFlag(&FLAGS_outfmt, "textproto");
  EXPECT_THAT(WriteOutputAccordingToFlags(GetPckCertificateResult{}),
              PosixErrorIs(ENOENT));
}

TEST_F(SgxPcsToolLibTest, WritePemCertResultAsPem) {
  GetPckCertificateResult cert_result;
  cert_result.pck_cert = ParseTextProtoOrDie(kPemCertProtos[0]);
  for (size_t i = 1; i < kPemCertProtos.size(); ++i) {
    *cert_result.issuer_cert_chain.add_certificates() =
        ParseTextProtoOrDie(kPemCertProtos[i]);
  }

  OpenTempFile();
  absl::SetFlag(&FLAGS_outfile, temp_filename_);
  absl::SetFlag(&FLAGS_outfmt, "pem");
  EXPECT_THAT(WriteOutputAccordingToFlags(cert_result), IsOk());

  char buffer[kAllPems.size()];
  ASSERT_THAT(read(temp_fd_, buffer, sizeof(buffer)), Eq(sizeof(buffer)));
  EXPECT_THAT(absl::string_view(buffer, sizeof(buffer)), Eq(kAllPems));
}

TEST_F(SgxPcsToolLibTest, WriteDerCertResultAsPem) {
  GetPckCertificateResult cert_result;
  cert_result.pck_cert = ParseTextProtoOrDie(kDerCertProtos[0]);
  for (size_t i = 1; i < kDerCertProtos.size(); ++i) {
    *cert_result.issuer_cert_chain.add_certificates() =
        ParseTextProtoOrDie(kDerCertProtos[i]);
  }

  OpenTempFile();
  absl::SetFlag(&FLAGS_outfile, temp_filename_);
  absl::SetFlag(&FLAGS_outfmt, "pem");
  EXPECT_THAT(WriteOutputAccordingToFlags(cert_result), IsOk());

  char buffer[kAllPems.size()];
  ASSERT_THAT(read(temp_fd_, buffer, sizeof(buffer)), Eq(sizeof(buffer)));
  EXPECT_THAT(absl::string_view(buffer, sizeof(buffer)), Eq(kAllPems));
}

TEST_F(SgxPcsToolLibTest, WriteCertResultAsProto) {
  // Intentionally mix PEM and DER cert inputs.
  GetPckCertificateResult cert_result;
  cert_result.pck_cert = ParseTextProtoOrDie(kDerCertProtos[0]);

  for (size_t i = 1; i < kPemCertProtos.size(); ++i) {
    *cert_result.issuer_cert_chain.add_certificates() =
        ParseTextProtoOrDie(kPemCertProtos[i]);
  }

  OpenTempFile();
  absl::SetFlag(&FLAGS_outfile, temp_filename_);
  absl::SetFlag(&FLAGS_outfmt, "textproto");
  EXPECT_THAT(WriteOutputAccordingToFlags(cert_result), IsOk());

  CertificateChain parsed_proto;
  google::protobuf::io::FileInputStream proto_input(temp_fd_);
  google::protobuf::TextFormat::Parse(&proto_input, &parsed_proto);
  EXPECT_THAT(parsed_proto.certificates_size(), Eq(kPemCertProtos.size()));
  EXPECT_THAT(parsed_proto.certificates(0), EqualsProto(cert_result.pck_cert));
  for (size_t i = 1; i < kPemCertProtos.size(); ++i) {
    EXPECT_THAT(parsed_proto.certificates(i),
                EqualsProto(cert_result.issuer_cert_chain.certificates(i - 1)));
  }
}

}  // namespace
}  // namespace sgx
}  // namespace asylo

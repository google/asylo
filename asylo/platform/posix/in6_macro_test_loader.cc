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

#include <arpa/inet.h>
#include <netinet/in.h>

#include <random>

#include "asylo/platform/posix/in6_macro_test.pb.h"
#include "asylo/test/util/enclave_test.h"
#include "asylo/test/util/status_matchers.h"
#include "asylo/util/statusor.h"

// Used for printing out the IP address being tested when there is a failure.
std::ostream &operator<<(std::ostream &stream, const in6_addr &address) {
  char buf[INET6_ADDRSTRLEN];

  CHECK(inet_ntop(AF_INET6, &address, buf, sizeof(buf)));
  buf[INET6_ADDRSTRLEN - 1] = '\0';

  return stream << buf;
}

namespace asylo {
namespace {

constexpr int kRandomAddressCount = 10000;

in6_addr GetRandomIpv6Address() {
  std::random_device dev_random;
  std::uniform_int_distribution<uint32_t> uniform;

  in6_addr ret;
  ret.s6_addr32[0] = uniform(dev_random);
  ret.s6_addr32[1] = uniform(dev_random);
  ret.s6_addr32[2] = uniform(dev_random);
  ret.s6_addr32[3] = uniform(dev_random);

  return ret;
}

// Verifies that the native versions of these macros get the same results as
// the provided results that were obtained from the enclave.
void VerifyMacroResults(const in6_addr &address, const MacroResults &results) {
  EXPECT_EQ(results.unspecified(), IN6_IS_ADDR_UNSPECIFIED(&address))
      << address;
  EXPECT_EQ(results.loopback(), IN6_IS_ADDR_LOOPBACK(&address)) << address;
  EXPECT_EQ(results.multicast(), IN6_IS_ADDR_MULTICAST(&address)) << address;
  EXPECT_EQ(results.link_local(), IN6_IS_ADDR_LINKLOCAL(&address)) << address;
  EXPECT_EQ(results.site_local(), IN6_IS_ADDR_SITELOCAL(&address)) << address;
  EXPECT_EQ(results.v4_mapped(), IN6_IS_ADDR_V4MAPPED(&address)) << address;
  EXPECT_EQ(results.v4_compat(), IN6_IS_ADDR_V4COMPAT(&address)) << address;
  EXPECT_EQ(results.multicast_node_local(), IN6_IS_ADDR_MC_NODELOCAL(&address))
      << address;
  EXPECT_EQ(results.multicast_link_local(), IN6_IS_ADDR_MC_LINKLOCAL(&address))
      << address;
  EXPECT_EQ(results.multicast_site_local(), IN6_IS_ADDR_MC_SITELOCAL(&address))
      << address;
  EXPECT_EQ(results.multicast_org_local(), IN6_IS_ADDR_MC_ORGLOCAL(&address))
      << address;
  EXPECT_EQ(results.multicast_global(), IN6_IS_ADDR_MC_GLOBAL(&address))
      << address;
}

class Ipv6MacroTest : public EnclaveTest {
 protected:
  // Convenience function to have the enclave run all of the macros and return
  // each of their results for the given address.
  MacroResults RunMacrosInEnclave(const in6_addr &address) {
    EnclaveInput enclave_input;
    In6MacroTestInput *test_input =
        enclave_input.MutableExtension(in6_macro_test_input);
    test_input->set_ipv6_address(&address, sizeof(address));

    EnclaveOutput enclave_output;
    Status test_status = client_->EnterAndRun(enclave_input, &enclave_output);
    ASYLO_CHECK_OK(test_status);

    return enclave_output.GetExtension(in6_macro_test_output);
  }
};

// For every address tested, it compares the result between inside the enclave
// (our implementation) and outside the enclave (native libc, source of truth)
// for all of the macros. Since they each test all of the flags, the
// organization into separate test cases is primarily to note what motivated
// that particular address as a test.
// The random test at the end is really the most valuable, because over
// time it will verify much more than could reasonably be covered explicitly.

TEST_F(Ipv6MacroTest, Unspecified) {
  // ::/128
  in6_addr address;
  ASSERT_EQ(inet_pton(AF_INET6, "::", &address), 1);
  VerifyMacroResults(address, RunMacrosInEnclave(address));
}

TEST_F(Ipv6MacroTest, Loopback) {
  // ::1/128
  in6_addr address;
  ASSERT_EQ(inet_pton(AF_INET6, "::1", &address), 1);
  VerifyMacroResults(address, RunMacrosInEnclave(address));
}

TEST_F(Ipv6MacroTest, MultiCast) {
  // ff00::/8
  in6_addr address;
  ASSERT_EQ(inet_pton(AF_INET6, "ff::", &address), 1);
  VerifyMacroResults(address, RunMacrosInEnclave(address));

  ASSERT_EQ(inet_pton(AF_INET6, "ffff::", &address), 1);
  VerifyMacroResults(address, RunMacrosInEnclave(address));

  ASSERT_EQ(inet_pton(AF_INET6, "ffff:ffff::ffff:ffff:ffff", &address), 1);
  VerifyMacroResults(address, RunMacrosInEnclave(address));

  ASSERT_EQ(inet_pton(AF_INET6, "ff7f::", &address), 1);
  VerifyMacroResults(address, RunMacrosInEnclave(address));

  ASSERT_EQ(inet_pton(AF_INET6, "0:ff::", &address), 1);
  VerifyMacroResults(address, RunMacrosInEnclave(address));

  ASSERT_EQ(inet_pton(AF_INET6, "00::ff", &address), 1);
  VerifyMacroResults(address, RunMacrosInEnclave(address));

  ASSERT_EQ(inet_pton(AF_INET6, "ff0f:12::3456:7890:abcd:cdef", &address), 1);
  VerifyMacroResults(address, RunMacrosInEnclave(address));
}

TEST_F(Ipv6MacroTest, LinkLocal) {
  // fe80::/10
  in6_addr address;
  ASSERT_EQ(inet_pton(AF_INET6, "fe80::", &address), 1);
  VerifyMacroResults(address, RunMacrosInEnclave(address));

  ASSERT_EQ(inet_pton(AF_INET6, "fe8c:ba98::3210:ba98:7654:3210", &address), 1);
  VerifyMacroResults(address, RunMacrosInEnclave(address));

  ASSERT_EQ(inet_pton(AF_INET6, "fe9c:ba98::3210:ba98:7654:3210", &address), 1);
  VerifyMacroResults(address, RunMacrosInEnclave(address));
}

TEST_F(Ipv6MacroTest, SiteLocal) {
  // fec0::/10
  in6_addr address;
  ASSERT_EQ(inet_pton(AF_INET6, "fec0::", &address), 1);
  VerifyMacroResults(address, RunMacrosInEnclave(address));

  ASSERT_EQ(inet_pton(AF_INET6, "fecc:ba98::3210:ba98:7654:3210", &address), 1);
  VerifyMacroResults(address, RunMacrosInEnclave(address));

  ASSERT_EQ(inet_pton(AF_INET6, "fedc:ba98::3210:ba98:7654:3210", &address), 1);
  VerifyMacroResults(address, RunMacrosInEnclave(address));
}

TEST_F(Ipv6MacroTest, V4Mapped) {
  // ::ffff:0:0/96
  in6_addr address;
  ASSERT_EQ(inet_pton(AF_INET6, "::ffff:0:0", &address), 1);
  VerifyMacroResults(address, RunMacrosInEnclave(address));

  ASSERT_EQ(inet_pton(AF_INET6, "::ffff:192.0.2.20", &address), 1);
  VerifyMacroResults(address, RunMacrosInEnclave(address));
}

TEST_F(Ipv6MacroTest, V4Compat) {
  // 0000::/96
  in6_addr address;
  ASSERT_EQ(inet_pton(AF_INET6, "0000::", &address), 1);
  VerifyMacroResults(address, RunMacrosInEnclave(address));

  ASSERT_EQ(inet_pton(AF_INET6, "::1234:0000:5678:90ab:cdef", &address), 1);
  VerifyMacroResults(address, RunMacrosInEnclave(address));
}

TEST_F(Ipv6MacroTest, MultiCastNodeLocal) {
  // ff00::/8 with scope nibble 1
  in6_addr address;
  ASSERT_EQ(inet_pton(AF_INET6, "ff01::", &address), 1);
  VerifyMacroResults(address, RunMacrosInEnclave(address));

  ASSERT_EQ(inet_pton(AF_INET6, "ff01::1", &address), 1);
  VerifyMacroResults(address, RunMacrosInEnclave(address));

  ASSERT_EQ(inet_pton(AF_INET6, "ff51::2", &address), 1);
  VerifyMacroResults(address, RunMacrosInEnclave(address));
}

TEST_F(Ipv6MacroTest, MultiCastLinkLocal) {
  // ff00::/8 with scope nibble 2
  in6_addr address;
  ASSERT_EQ(inet_pton(AF_INET6, "ff02::", &address), 1);
  VerifyMacroResults(address, RunMacrosInEnclave(address));

  ASSERT_EQ(inet_pton(AF_INET6, "ff02::1", &address), 1);
  VerifyMacroResults(address, RunMacrosInEnclave(address));

  ASSERT_EQ(inet_pton(AF_INET6, "ff52::2", &address), 1);
  VerifyMacroResults(address, RunMacrosInEnclave(address));
}

TEST_F(Ipv6MacroTest, MultiCastSiteLocal) {
  // ff00::/8 with scope nibble 5
  in6_addr address;
  ASSERT_EQ(inet_pton(AF_INET6, "ff05::", &address), 1);
  VerifyMacroResults(address, RunMacrosInEnclave(address));

  ASSERT_EQ(inet_pton(AF_INET6, "ff05::1", &address), 1);
  VerifyMacroResults(address, RunMacrosInEnclave(address));

  ASSERT_EQ(inet_pton(AF_INET6, "ff35::3", &address), 1);
  VerifyMacroResults(address, RunMacrosInEnclave(address));
}

TEST_F(Ipv6MacroTest, MultiCastOrgLocal) {
  // ff00::/8 with scope nibble 8
  in6_addr address;
  ASSERT_EQ(inet_pton(AF_INET6, "ff08::", &address), 1);
  VerifyMacroResults(address, RunMacrosInEnclave(address));

  ASSERT_EQ(inet_pton(AF_INET6, "ff08::1", &address), 1);
  VerifyMacroResults(address, RunMacrosInEnclave(address));

  ASSERT_EQ(inet_pton(AF_INET6, "ff75::4", &address), 1);
  VerifyMacroResults(address, RunMacrosInEnclave(address));
}

TEST_F(Ipv6MacroTest, MultiCastGlobal) {
  // ff00::/8 with scope nibble e
  in6_addr address;
  ASSERT_EQ(inet_pton(AF_INET6, "ff0e::", &address), 1);
  VerifyMacroResults(address, RunMacrosInEnclave(address));

  ASSERT_EQ(inet_pton(AF_INET6, "ff0e::1", &address), 1);
  VerifyMacroResults(address, RunMacrosInEnclave(address));

  ASSERT_EQ(inet_pton(AF_INET6, "ffce::5", &address), 1);
  VerifyMacroResults(address, RunMacrosInEnclave(address));
}

// Generate random addresses to get additional coverage.
TEST_F(Ipv6MacroTest, RandomAddresses) {
  for (int i = 0; i < kRandomAddressCount; ++i) {
    in6_addr address = GetRandomIpv6Address();
    VerifyMacroResults(address, RunMacrosInEnclave(address));
  }
}

}  // namespace
}  // namespace asylo

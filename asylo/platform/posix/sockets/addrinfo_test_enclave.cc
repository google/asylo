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

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include <string>

#include "absl/status/status.h"
#include "asylo/platform/posix/sockets/socket_test.pb.h"
#include "asylo/test/util/enclave_test_application.h"

namespace asylo {

class AddrinfoTestEnclave : public EnclaveTestCase {
 public:
  AddrinfoTestEnclave() = default;

  Status Run(const EnclaveInput &input, EnclaveOutput *output) {
    if (!input.HasExtension(addrinfo_test_input)) {
      return absl::InvalidArgumentError(
          "addrinfo test input use addrinfo hints not found");
    }

    AddrInfoTestInput::TestMode mode =
        input.GetExtension(addrinfo_test_input).mode();

    switch (mode) {
      case AddrInfoTestInput::NO_HINTS:
        return AddrInfoTest_NoHints();
      case AddrInfoTestInput::UNSPEC_HINTS:
        return AddrInfoTest_UnspecHints();
      case AddrInfoTestInput::IP_HINTS:
        return AddrInfoTest_IpHints();
      default:
        return absl::InternalError("unknown addrinfo test mode");
    }
  }

 private:
  bool VerifyLocalHostAddrInfoCanonname(const struct addrinfo *info) {
    // The first of the addrinfo structures should point to the canonical name
    // of the host. Verify that there's at least one struct and that the host
    // name in it is correct.
    if (info == nullptr) {
      LOG(ERROR) << "No addrinfo returned!";
      return false;
    }
    if (info->ai_canonname == nullptr) {
      LOG(ERROR) << "No canonname returned!";
      return false;
    }
    if (!strstr(info->ai_canonname, "localhost")) {
      LOG(ERROR) << "Unexpected canon hostname " << info->ai_canonname;
      return false;
    }
    return true;
  }

  bool VerifyLocalHostAddrInfoAddress(const struct addrinfo *info) {
    char addr_buf[INET_ADDRSTRLEN];
    for (const struct addrinfo *i = info; i != nullptr; i = i->ai_next) {
      memset(addr_buf, 0, sizeof(addr_buf));
      // This test only checks the addrinfos returned by getaddrinfo for IPv4
      // and IPv6. We ignore other address families.
      if (i->ai_family == AF_INET6) {
        struct in6_addr *sin_addr6 =
            &(reinterpret_cast<struct sockaddr_in6 *>(i->ai_addr)->sin6_addr);
        inet_ntop(i->ai_family, sin_addr6, addr_buf, sizeof(addr_buf));
        if (strcmp(addr_buf, "::1") != 0) return false;
      } else if (i->ai_family == AF_INET) {
        struct in_addr *sin_addr =
            &(reinterpret_cast<struct sockaddr_in *>(i->ai_addr)->sin_addr);
        inet_ntop(i->ai_family, sin_addr, addr_buf, sizeof(addr_buf));
        if (strcmp(addr_buf, "127.0.0.1") != 0) return false;
      }
    }
    return true;
  }

  bool GetAddrInfoForLocalHost(const struct addrinfo *hints,
                               struct addrinfo **res) {
    return getaddrinfo("localhost", nullptr, hints, res) == 0;
  }

  Status AddrInfoTest_NoHints() {
    struct addrinfo *info = nullptr;
    if (!GetAddrInfoForLocalHost(/*hints=*/nullptr, &info)) {
      return absl::InternalError("getaddrinfo() system call failed");
    }
    if (!VerifyLocalHostAddrInfoAddress(info)) {
      return absl::InternalError(
          "getaddrinfo() returned incorrect address string");
    }
    freeaddrinfo(info);
    return absl::OkStatus();
  }

  Status AddrInfoTest_UnspecHints() {
    struct addrinfo *info = nullptr;
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;  // Should allow any address family
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_CANONNAME;  // return canonical names in addrinfo
    if (!GetAddrInfoForLocalHost(&hints, &info)) {
      return absl::InternalError("getaddrinfo() system call failed");
    }
    if (!VerifyLocalHostAddrInfoAddress(info)) {
      return absl::InternalError(
          "getaddrinfo() returned incorrect address string");
    }
    if (!VerifyLocalHostAddrInfoCanonname(info)) {
      return absl::InternalError(
          "getaddrinfo() returned incorrect canonical name");
    }
    freeaddrinfo(info);
    return absl::OkStatus();
  }

  Status AddrInfoTest_IpHints() {
    struct addrinfo *info = nullptr;
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET | AF_INET6;  // limit to IPv4 and IPv6
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_CANONNAME;  // return canonical names in addrinfo
    if (!GetAddrInfoForLocalHost(&hints, &info)) {
      return absl::InternalError("getaddrinfo() system call failed");
    }
    if (!VerifyLocalHostAddrInfoAddress(info)) {
      return absl::InternalError(
          "getaddrinfo() returned incorrect address string");
    }
    if (!VerifyLocalHostAddrInfoCanonname(info)) {
      return absl::InternalError(
          "getaddrinfo() returned incorrect canonical name");
    }
    freeaddrinfo(info);
    return absl::OkStatus();
  }
};

TrustedApplication *BuildTrustedApplication() {
  return new AddrinfoTestEnclave;
}

}  // namespace asylo

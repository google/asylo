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

#include <netinet/in.h>

#include "absl/status/status.h"
#include "asylo/platform/posix/in6_macro_test.pb.h"
#include "asylo/trusted_application.h"
#include "asylo/util/status.h"

namespace asylo {
namespace {

class In6MacroTestEnclave : public TrustedApplication {
 public:
  In6MacroTestEnclave() = default;

 private:
  Status Run(const EnclaveInput &input, EnclaveOutput *output) override {
    // Pull the IP address out of the input proto.
    in6_addr address;
    In6MacroTestInput test_input = input.GetExtension(in6_macro_test_input);
    if (test_input.ipv6_address().size() != sizeof(in6_addr)) {
      return absl::FailedPreconditionError(
          "Input IPv6 address has incorrect number of bytes");
    }
    test_input.ipv6_address().copy(reinterpret_cast<char *>(&address),
                                   sizeof(in6_addr));

    // Run each of the address macros and stuff the results in the output proto.
    MacroResults *results = output->MutableExtension(in6_macro_test_output);
    results->set_unspecified(IN6_IS_ADDR_UNSPECIFIED(&address));
    results->set_loopback(IN6_IS_ADDR_LOOPBACK(&address));
    results->set_multicast(IN6_IS_ADDR_MULTICAST(&address));
    results->set_link_local(IN6_IS_ADDR_LINKLOCAL(&address));
    results->set_site_local(IN6_IS_ADDR_SITELOCAL(&address));
    results->set_v4_mapped(IN6_IS_ADDR_V4MAPPED(&address));
    results->set_v4_compat(IN6_IS_ADDR_V4COMPAT(&address));
    results->set_multicast_node_local(IN6_IS_ADDR_MC_NODELOCAL(&address));
    results->set_multicast_link_local(IN6_IS_ADDR_MC_LINKLOCAL(&address));
    results->set_multicast_site_local(IN6_IS_ADDR_MC_SITELOCAL(&address));
    results->set_multicast_org_local(IN6_IS_ADDR_MC_ORGLOCAL(&address));
    results->set_multicast_global(IN6_IS_ADDR_MC_GLOBAL(&address));

    return absl::OkStatus();
  }
};

}  // namespace

TrustedApplication *BuildTrustedApplication() {
  return new In6MacroTestEnclave;
}

}  // namespace asylo

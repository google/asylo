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

#include <string>

#include "absl/base/attributes.h"
#include "absl/status/status.h"
#include "asylo/test/misc/exception.h"
#include "asylo/test/util/enclave_test_application.h"
#include "asylo/util/status.h"

namespace asylo {

class Exception : public EnclaveTestCase {
 public:
  Exception() = default;

  Status Run(const EnclaveInput &input, EnclaveOutput *) override {
    const std::string &test = GetEnclaveInputTestString(input);
    if (test == "uncaught") {
      Throw();
    } else if (test == "caught") {
      try {
        Throw();
      } catch (TestException &e) {
        return (e.Code() == 54)
                   ? absl::OkStatus()
                   : absl::InternalError("Unexpected exception code");
      }
    } else {
      return absl::InvalidArgumentError("Unrecognized command");
    }
  }

 protected:
  void ABSL_ATTRIBUTE_NORETURN Throw() { throw TestException(54, "Nope"); }
};

TrustedApplication *BuildTrustedApplication() { return new Exception; }

}  // namespace asylo

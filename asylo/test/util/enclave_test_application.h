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

#ifndef ASYLO_TEST_UTIL_ENCLAVE_TEST_APPLICATION_H_
#define ASYLO_TEST_UTIL_ENCLAVE_TEST_APPLICATION_H_

#include "asylo/enclave.pb.h"
#include "asylo/trusted_application.h"

namespace asylo {

class EnclaveTestCase : public TrustedApplication {
 public:
  // Sets test_string in the enclave_output_test_string protobuf extension.
  void SetEnclaveOutputTestString(EnclaveOutput *enclave_output,
                                  const std::string &str_test);

  // Gets test_string from the enclave_config_test_string protobuf extension.
  const std::string &GetEnclaveConfigTestString(const EnclaveConfig &config);

  // Gets test_string from the enclave_input_test_string protobuf extension.
  const std::string &GetEnclaveInputTestString(const EnclaveInput &input);

  // Gets test_string from the enclave_final_test_string protobuf extension.
  const std::string &GetEnclaveFinalTestString(const EnclaveFinal &final_input);
};

}  // namespace asylo

#endif  // ASYLO_TEST_UTIL_ENCLAVE_TEST_APPLICATION_H_

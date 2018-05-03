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

#include "asylo/test/util/enclave_test_application.h"
#include "asylo/test/util/test_string.pb.h"

namespace asylo {

void EnclaveTestCase::SetEnclaveOutputTestString(EnclaveOutput *enclave_output,
                                                 const std::string &str_test) {
  enclave_output->MutableExtension(enclave_output_test_string)
      ->set_test_string(str_test);
}

const std::string &EnclaveTestCase::GetEnclaveConfigTestString(
    const EnclaveConfig &config) {
  return config.GetExtension(enclave_config_test_string).test_string();
}

const std::string &EnclaveTestCase::GetEnclaveInputTestString(
    const EnclaveInput &input) {
  return input.GetExtension(enclave_input_test_string).test_string();
}

const std::string &EnclaveTestCase::GetEnclaveFinalTestString(
    const EnclaveFinal &final_input) {
  return final_input.GetExtension(enclave_final_test_string).test_string();
}

}  // namespace asylo

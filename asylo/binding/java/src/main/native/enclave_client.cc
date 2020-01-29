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

#include "asylo/binding/java/src/main/native/enclave_client.h"

#include "asylo/binding/java/src/main/native/jni_utils.h"
#include "asylo/client.h"

// Executes the enclave with given input and return the result.
JNIEXPORT jobject JNICALL Java_com_asylo_client_EnclaveClient_enterAndRun(
    JNIEnv *env, jobject this_object, jlong client_pointer,
    jobject enclave_input, jobject registry) {
  asylo::EnclaveClient *client =
      reinterpret_cast<asylo::EnclaveClient *>(client_pointer);

  asylo::EnclaveInput enclave_native_input;
  bool converted = asylo::jni::ConvertJavaToNativeProto(env, enclave_input,
                                                        &enclave_native_input);
  if (!converted) {
    return nullptr;
  }

  asylo::EnclaveOutput output;

  asylo::Status status = client->EnterAndRun(enclave_native_input, &output);
  if (!status.ok()) {
    asylo::jni::ThrowEnclaveException(env, status);
  }

  return asylo::jni::ConvertNativeToJavaProto(env, &output, registry);
}

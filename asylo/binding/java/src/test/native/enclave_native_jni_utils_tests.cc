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

#include "asylo/binding/java/src/test/native/enclave_native_jni_utils_tests.h"

#include "absl/status/status.h"
#include "asylo/binding/java/src/main/native/jni_utils.h"
#include "asylo/binding/java/src/test/java/com/asylo/client/jni_utils_test.pb.h"
#include "asylo/enclave.pb.h"

JNIEXPORT jboolean JNICALL
Java_com_asylo_client_EnclaveNativeJniUtilsTest_nativeCheckJniException(
    JNIEnv *env, jobject this_obj) {
  // throw some exception
  jclass this_class = env->GetObjectClass(this_obj);
  env->GetMethodID(this_class, "class", "()V");

  // check if exception is detected
  bool result = asylo::jni::CheckForPendingException(env);
  env->ExceptionClear();
  return result;
}

JNIEXPORT void JNICALL
Java_com_asylo_client_EnclaveNativeJniUtilsTest_nativeThrowEnclaveExceptionUsingStatus(
    JNIEnv *env, jobject this_obj) {
  asylo::jni::ThrowEnclaveException(env, absl::OkStatus());
}

JNIEXPORT void JNICALL
Java_com_asylo_client_EnclaveNativeJniUtilsTest_nativeThrowEnclaveExceptionUsingString(
    JNIEnv *env, jobject this_obj, jstring message) {
  const char *native_message = env->GetStringUTFChars(message, nullptr);
  std::string native_string(native_message);
  env->ReleaseStringUTFChars(message, native_message);
  asylo::jni::ThrowEnclaveException(env, native_string);
}

JNIEXPORT jobject JNICALL
Java_com_asylo_client_EnclaveNativeJniUtilsTest_nativeProtoConversionBetweenJavaAndNative(
    JNIEnv *env, jobject this_obj, jobject java_enclave_input,
    jobject java_registry) {
  asylo::EnclaveInput native_enclave_input;
  bool converted = asylo::jni::ConvertJavaToNativeProto(env, java_enclave_input,
                                                        &native_enclave_input);
  if (!converted) {
    return nullptr;
  }

  asylo::java::test::Data data =
      native_enclave_input.GetExtension(asylo::java::test::input_data);

  asylo::EnclaveOutput native_enclave_output;
  native_enclave_output.MutableExtension(asylo::java::test::output_data)
      ->set_int32_val(data.int32_val());
  native_enclave_output.MutableExtension(asylo::java::test::output_data)
      ->set_string_val(data.string_val());

  return asylo::jni::ConvertNativeToJavaProto(env, &native_enclave_output,
                                               java_registry);
}

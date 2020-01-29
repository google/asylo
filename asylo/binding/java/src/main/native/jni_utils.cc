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

#include "asylo/binding/java/src/main/native/jni_utils.h"

#include "absl/memory/memory.h"

namespace asylo {
namespace jni {

bool CheckForPendingException(JNIEnv *env) {
  return env->ExceptionCheck() == JNI_TRUE;
}

void ThrowEnclaveException(JNIEnv *env, const asylo::Status &status) {
  ThrowEnclaveException(env, status.ToString());
}

void ThrowEnclaveException(JNIEnv *env, const std::string &message) {
  jclass exception_class = env->FindClass("com/asylo/client/EnclaveException");
  if (env->ExceptionCheck()) {
    return;
  }
  env->ThrowNew(exception_class, message.c_str());
}

bool ConvertJavaToNativeProto(JNIEnv *env, const jobject java_object,
                              google::protobuf::MessageLite *native_object) {
  jclass java_class = env->GetObjectClass(java_object);
  jmethodID java_method_id =
      env->GetMethodID(java_class, "toByteArray", "()[B");
  if (CheckForPendingException(env)) {
    return false;
  }

  jbyteArray bytearray = static_cast<jbyteArray>(
      env->CallObjectMethod(java_object, java_method_id));
  if (CheckForPendingException(env)) {
    return false;
  }

  jsize length = env->GetArrayLength(bytearray);
  jbyte *native_byte_array = env->GetByteArrayElements(bytearray, nullptr);
  if (native_byte_array == nullptr) {
    // Something wrong happened. Throw exception and return.
    ThrowEnclaveException(
        env, "Not able to get serialized buffer of java protobuf object.");
    return false;
  }
  bool parse_success = native_object->ParseFromArray(native_byte_array, length);
  env->ReleaseByteArrayElements(bytearray, native_byte_array, JNI_ABORT);

  if (!parse_success) {
    ThrowEnclaveException(
        env, "Not able to parse buffer to create native protobuf object.");
    return false;
  }
  return true;
}

jobject ConvertNativeToJavaProto(JNIEnv *env,
                                 google::protobuf::MessageLite *native_object,
                                 const jobject &registry) {
  jclass enclave_output_class = env->FindClass("com/asylo/EnclaveOutput");
  if (CheckForPendingException(env)) {
    return nullptr;
  }

  jmethodID parseMethodId = env->GetStaticMethodID(
      enclave_output_class, "parseFrom",
      "([BLcom/google/protobuf/ExtensionRegistryLite;)Lcom/asylo/"
      "EnclaveOutput;");
  if (CheckForPendingException(env)) {
    return nullptr;
  }
  auto native_object_length = native_object->ByteSizeLong();
  auto native_object_buffer = absl::make_unique<jbyte[]>(native_object_length);
  native_object->SerializeToArray(native_object_buffer.get(),
                                  native_object_length);

  jbyteArray java_byte_array = env->NewByteArray(native_object_length);
  env->SetByteArrayRegion(java_byte_array, 0, native_object_length,
                          native_object_buffer.get());
  if (CheckForPendingException(env)) {
    return nullptr;
  }

  jobject output_java_obj = env->CallStaticObjectMethod(
      enclave_output_class, parseMethodId, java_byte_array, registry);
  if (CheckForPendingException(env)) {
    return nullptr;
  }

  return output_java_obj;
}
}  // namespace jni
}  // namespace asylo

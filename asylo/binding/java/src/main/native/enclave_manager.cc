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

#include "asylo/binding/java/src/main/native/enclave_manager.h"

#include "asylo/binding/java/src/main/native/jni_utils.h"
#include "asylo/client.h"

// JNI function to create an EnclaveManager instance and return its pointer.
// This function will throw an exception to the JVM if there is an error in
// fetching the instance.
JNIEXPORT jlong JNICALL
Java_com_asylo_client_EnclaveManager_create(JNIEnv *env, jclass this_class) {
  auto manager_result = asylo::EnclaveManager::Instance();

  if (!manager_result.ok()) {
    asylo::jni::ThrowEnclaveException(env, manager_result.status());
    return 0;
  }

  asylo::EnclaveManager *manager = manager_result.value();
  return reinterpret_cast<jlong>(manager);
}

// Loads an enclave based on the given EnclaveLoadConfig.
JNIEXPORT void JNICALL Java_com_asylo_client_EnclaveManager_loadEnclave(
    JNIEnv *env, jobject this_object, jlong manager_pointer,
    jobject load_config) {
  asylo::EnclaveManager *manager =
      reinterpret_cast<asylo::EnclaveManager *>(manager_pointer);

  asylo::EnclaveLoadConfig native_load_config;

  if (!asylo::jni::ConvertJavaToNativeProto(env, load_config,
                                            &native_load_config)) {
    return;
  }
  auto result = manager->LoadEnclave(native_load_config);
  if (!result.ok()) {
    asylo::jni::ThrowEnclaveException(env, result);
  }
}

// Returns a java EnclaveClient corresponding to given name.
JNIEXPORT jobject JNICALL Java_com_asylo_client_EnclaveManager_getEnclaveClient(
    JNIEnv *env, jobject this_object, jlong manager_pointer,
    jstring enclave_java_name) {
  asylo::EnclaveManager *manager =
      reinterpret_cast<asylo::EnclaveManager *>(manager_pointer);

  const char *name = env->GetStringUTFChars(enclave_java_name, nullptr);
  if (name == nullptr) {
    // Can't proceed if we cannot get name of the enclave to load.
    asylo::jni::ThrowEnclaveException(
        env, "Not able to convert enclave name to native");
    return nullptr;
  }
  std::string enclave_native_name(name);
  env->ReleaseStringUTFChars(enclave_java_name, name);

  asylo::EnclaveClient *client = manager->GetClient(enclave_native_name);
  if (client == nullptr) {
    asylo::jni::ThrowEnclaveException(
        env,
        absl::StrCat(
            enclave_native_name,
            " not found. Please make sure it is loaded via EnclaveManager."));
    return nullptr;
  }

  jclass client_java_class = env->FindClass("com/asylo/client/EnclaveClient");
  if (env->ExceptionCheck()) {
    return nullptr;
  }

  jmethodID constructor_id =
      env->GetMethodID(client_java_class, "<init>", "(J)V");
  if (env->ExceptionCheck()) {
    return nullptr;
  }

  return env->NewObject(client_java_class, constructor_id,
                        reinterpret_cast<jlong>(client));
}

// Destory the given enclave client with final input to enclave.
JNIEXPORT void JNICALL
Java_com_asylo_client_EnclaveManager_destroyEnclaveClient(
    JNIEnv *env, jobject this_object, jlong manager_pointer,
    jlong client_pointer, jobject enclave_final) {
  asylo::EnclaveManager *manager =
      reinterpret_cast<asylo::EnclaveManager *>(manager_pointer);
  asylo::EnclaveClient *client =
      reinterpret_cast<asylo::EnclaveClient *>(client_pointer);

  asylo::EnclaveFinal final_input;
  bool converted =
      asylo::jni::ConvertJavaToNativeProto(env, enclave_final, &final_input);
  if (!converted) {
    return;
  }

  asylo::Status manager_result = manager->DestroyEnclave(client, final_input);
  if (!manager_result.ok()) {
    asylo::jni::ThrowEnclaveException(env, manager_result);
  }
}

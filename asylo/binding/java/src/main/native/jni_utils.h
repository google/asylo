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

#ifndef ASYLO_BINDING_JAVA_SRC_MAIN_NATIVE_JNI_UTILS_H_
#define ASYLO_BINDING_JAVA_SRC_MAIN_NATIVE_JNI_UTILS_H_

#include <jni.h>

#include <string>

#include <google/protobuf/message_lite.h>
#include "asylo/util/status.h"

namespace asylo {
namespace jni {

// Checks if there is a pending exception in JVM.
bool CheckForPendingException(JNIEnv *env);

// Throws an enclave exception based on Status to the JVM.
void ThrowEnclaveException(JNIEnv *env, const Status &status);

// Throws an enclave exception based on message string.
void ThrowEnclaveException(JNIEnv *env, const std::string &message);

// Converts a Java protobuf object to a C++ protobuf object, queuing a JVM
// exception and returning false on failure. Otherwise populates |native_object|
// from |java_object| and returns true.
bool ConvertJavaToNativeProto(JNIEnv *env, const jobject java_object,
                              google::protobuf::MessageLite *native_object);

// Converts a C++ protobuf object to a Java protobuf object, queuing a JVM
// exception and returning nullptr on failure. Otherwise returns
// the Java protobuf object from |native_object| using protobuf extension
// registry.
jobject ConvertNativeToJavaProto(JNIEnv *env,
                                 google::protobuf::MessageLite *native_object,
                                 const jobject &registry);
}  // namespace jni
}  // namespace asylo

#endif  // ASYLO_BINDING_JAVA_SRC_MAIN_NATIVE_JNI_UTILS_H_

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

#ifndef ASYLO_BINDING_JAVA_SRC_TEST_NATIVE_ENCLAVE_NATIVE_JNI_UTILS_TESTS_H_
#define ASYLO_BINDING_JAVA_SRC_TEST_NATIVE_ENCLAVE_NATIVE_JNI_UTILS_TESTS_H_

#include <jni.h>

#ifdef __cplusplus
extern "C" {
#endif  // __cplusplus
/*
 * Class:     com_asylo_client_EnclaveNativeJniUtilsTest
 * Method:    nativeAbleToCheckJniException
 * Signature: ()Z
 */
JNIEXPORT jboolean JNICALL
Java_com_asylo_client_EnclaveNativeJniUtilsTest_nativeCheckJniException(
    JNIEnv *, jobject);

/*
 * Class:     com_asylo_client_EnclaveNativeJniUtilsTest
 * Method:    nativeAbleToThrowEnclaveExceptionUsingStatus
 * Signature: ()V
 */
JNIEXPORT void JNICALL
Java_com_asylo_client_EnclaveNativeJniUtilsTest_nativeThrowEnclaveExceptionUsingStatus(
    JNIEnv *, jobject);

/*
 * Class:     com_asylo_client_EnclaveNativeJniUtilsTest
 * Method:    nativeAbleToThrowEnclaveExceptionUsingString
 * Signature: (Ljava/lang/String;)V
 */
JNIEXPORT void JNICALL
Java_com_asylo_client_EnclaveNativeJniUtilsTest_nativeThrowEnclaveExceptionUsingString(
    JNIEnv *, jobject, jstring);

/*
 * Class:     com_asylo_client_EnclaveNativeJniUtilsTest
 * Method:    nativeProtoConversionBetweenJavaAndNative
 * Signature:
 * (Lcom/google/protos/asylo/Enclave/EnclaveInput;Lcom/google/protobuf/ExtensionRegistry;)Lcom/google/protos/asylo/Enclave/EnclaveOutput;
 */
JNIEXPORT jobject JNICALL
Java_com_asylo_client_EnclaveNativeJniUtilsTest_nativeProtoConversionBetweenJavaAndNative(
    JNIEnv *, jobject, jobject, jobject);

#ifdef __cplusplus
}
#endif  // __cplusplus
#endif  // ASYLO_BINDING_JAVA_SRC_TEST_NATIVE_ENCLAVE_NATIVE_JNI_UTILS_TESTS_H_

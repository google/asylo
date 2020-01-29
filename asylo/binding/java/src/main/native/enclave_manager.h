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

#ifndef ASYLO_BINDING_JAVA_SRC_MAIN_NATIVE_ENCLAVE_MANAGER_H_
#define ASYLO_BINDING_JAVA_SRC_MAIN_NATIVE_ENCLAVE_MANAGER_H_

#include <jni.h>

#ifdef __cplusplus
extern "C" {
#endif
/*
 * Class:     com_asylo_client_EnclaveManager
 * Method:    create
 * Signature: ()J
 */
JNIEXPORT jlong JNICALL Java_com_asylo_client_EnclaveManager_create(JNIEnv *,
                                                                    jclass);

/*
 * Class:     com_asylo_client_EnclaveManager
 * Method:    loadEnclave
 * Signature: (JLcom/asylo/EnclaveLoadConfig;)V
 */
JNIEXPORT void JNICALL Java_com_asylo_client_EnclaveManager_loadEnclave(
    JNIEnv *, jobject, jlong, jobject);

/*
 * Class:     com_asylo_client_EnclaveManager
 * Method:    getEnclaveClient
 * Signature: (JLjava/lang/String;)Lcom/asylo/client/EnclaveClient;
 */
JNIEXPORT jobject JNICALL Java_com_asylo_client_EnclaveManager_getEnclaveClient(
    JNIEnv *, jobject, jlong, jstring);

/*
 * Class:     com_asylo_client_EnclaveManager
 * Method:    destroyEnclave
 * Signature: (JJLcom/asylo/EnclaveFinal;)V
 */
JNIEXPORT void JNICALL
Java_com_asylo_client_EnclaveManager_destroyEnclaveClient(JNIEnv *, jobject,
                                                          jlong, jlong,
                                                          jobject);

#ifdef __cplusplus
}
#endif  // __cplusplus
#endif  // ASYLO_BINDING_JAVA_SRC_MAIN_NATIVE_ENCLAVE_MANAGER_H_

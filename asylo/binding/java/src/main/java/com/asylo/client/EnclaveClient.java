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

package com.asylo.client;

import com.asylo.EnclaveInput;
import com.asylo.EnclaveOutput;
import com.google.protobuf.ExtensionRegistry;
import java.util.Objects;

/** EnclaveClient class which provides methods for invoking enclave's entry points. */
public class EnclaveClient extends AutoCloseablePointer {

  /**
   * Enclave clients are created in native using JNI APIs.
   *
   * @param pointer Handle to the native object.
   */
  private EnclaveClient(long pointer) {
    super(pointer);
  }

  @Override
  protected void closeNative(long pointer) {
    // Enclaves are destroyed by EnclaveManager.
  }

  /**
   * Enters the enclave and invokes its execution entry point. This method uses a default protobuf
   * {@link ExtensionRegistry}. Consider using {@link #enterAndRun(EnclaveInput, ExtensionRegistry)}
   * if you are expecting some result back otherwise you will have to serialize and deserialize
   * again to get your extension from protobuf.
   *
   * @param enclaveInput Input to the enclave which will be used in invoking entry point method.
   * @return Output from the enclave.
   * @throws EnclaveException if any exception occurs in native execution.
   */
  public EnclaveOutput enterAndRun(EnclaveInput enclaveInput) {
    Objects.requireNonNull(enclaveInput);
    return enterAndRun(enclaveInput, ExtensionRegistry.getEmptyRegistry());
  }

  /**
   * Enter the enclave and invokes its execution entry point.
   *
   * @param enclaveInput Input to the enclave which will be used in invoking entry point method.
   * @param registry A user protobuf registry which will be used generate EnclaveOutput.
   * @return Output from the enclave.
   * @throws EnclaveException if any exception occurs in native execution.
   */
  public EnclaveOutput enterAndRun(EnclaveInput enclaveInput, ExtensionRegistry registry) {
    Objects.requireNonNull(enclaveInput);
    Objects.requireNonNull(registry);

    return enterAndRun(getPointer(), enclaveInput, registry);
  }

  private native EnclaveOutput enterAndRun(
      long pointer, EnclaveInput enclaveInput, ExtensionRegistry registry);
}

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

import com.asylo.EnclaveFinal;
import com.asylo.EnclaveLoadConfig;
import java.util.Objects;

/**
 * A manager class responsible for creating and managing enclave instances.
 *
 * <p>EnclaveManager is a singleton class that tracks the status of enclaves within a process. Users
 * can access singleton instance by calling the static getInstance() method.
 */
public final class EnclaveManager extends AutoCloseablePointer {

  static {
    System.loadLibrary("enclave_client_java");
  }

  private static class EnclaveManagerHolder {
    static final EnclaveManager enclaveManager = createEnclaveManager();
  }

  /**
   * Returns the EnclaveManager singleton object.
   *
   * @return {@link EnclaveManager} singleton object.
   * @throws EnclaveException if EnclaveManager cannot be created.
   */
  public static EnclaveManager getInstance() {
    return EnclaveManagerHolder.enclaveManager;
  }

  /**
   * Returns an enclave manager instance which maps to the native EnclaveManager.
   *
   * @return {@link EnclaveManager} object.
   * @throws EnclaveException if EnclaveManager cannot be created.
   */
  private static EnclaveManager createEnclaveManager() {
    long pointer = create();
    return new EnclaveManager(pointer);
  }

  private static native long create();

  private EnclaveManager(long pointer) {
    super(pointer);
  }

  @Override
  public void close() {
    // Do nothing on closing. Modifying parent class behaviour.
  }

  @Override
  protected void closeNative(long pointer) {
    // Nothing to do. Managers are not supposed to be destroyed in native. They are singleton.
  }

  /**
   * Loads a new enclave utilizing the passed enclave loader configuration settings. The loaded
   * enclave is bound to the value of the field `name` in {@link EnclaveLoadConfig}. It is an error
   * to specify a name which is already bound to an enclave.
   *
   * @param config Loading configuration of the enclave.
   * @throws EnclaveException if manager is not able to load enclave properly.
   */
  public void loadEnclave(EnclaveLoadConfig config) {
    Objects.requireNonNull(config);
    loadEnclave(getPointer(), config);
  }

  private native void loadEnclave(long pointer, EnclaveLoadConfig config);

  /**
   * Returns the {@link EnclaveClient} which is loaded previously by calling {@link
   * #loadEnclave(EnclaveLoadConfig)}.
   *
   * @param enclaveName Name of the enclave registered with the enclave manager.
   * @return {@link EnclaveClient} loaded before.
   * @throws EnclaveException if it cannot return the client.
   */
  public EnclaveClient getEnclaveClient(String enclaveName) {
    Objects.requireNonNull(enclaveName);
    return getEnclaveClient(getPointer(), enclaveName);
  }

  private native EnclaveClient getEnclaveClient(long pointer, String enclaveName);

  /**
   * Destroys an enclave client. It first passes the {@link EnclaveFinal} to enclave's
   * EnterAndExecute method and then it frees up the native memory of the client. It should not be
   * called more than once for a client.
   *
   * @param enclaveClient Client which needs to be destroyed.
   * @param enclaveFinal Final input to the client.
   * @throws EnclaveException if there is any problem in destruction of the enclave.
   * @throws IllegalStateException if enclaveClient is already destroyed.
   */
  public void destroyEnclaveClient(EnclaveClient enclaveClient, EnclaveFinal enclaveFinal) {
    Objects.requireNonNull(enclaveClient);
    Objects.requireNonNull(enclaveFinal);
    if (enclaveClient.getPointer() == 0) {
      throw new IllegalStateException("Enclave client is already destroyed.");
    }
    destroyEnclaveClient(getPointer(), enclaveClient.getPointer(), enclaveFinal);
    enclaveClient.close();
  }

  private native void destroyEnclaveClient(
      long managerPointer, long clientPointer, EnclaveFinal enclaveFinal);
}

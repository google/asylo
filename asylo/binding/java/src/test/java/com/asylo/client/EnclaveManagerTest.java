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

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertThrows;

import com.asylo.EnclaveFinal;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Unit test for EnclaveManager */
@RunWith(JUnit4.class)
public class EnclaveManagerTest {

  @Test
  public void testDefaultInitialization() {
    assertThat(EnclaveManager.getInstance().getPointer()).isNotEqualTo(0);
  }

  @Test
  public void testMultipleInstancesHavingSamePointer() {
    EnclaveManager manager1 = EnclaveManager.getInstance();
    EnclaveManager manager2 = EnclaveManager.getInstance();

    assertThat(manager1.getPointer()).isEqualTo(manager2.getPointer());
  }

  @Test
  public void testThrowExceptionOnLoadWithNull() {
    assertThrows(NullPointerException.class, () -> EnclaveManager.getInstance().loadEnclave(null));
  }

  @Test
  public void testGetEnclaveClientWithNulls() {
    assertThrows(
        NullPointerException.class, () -> EnclaveManager.getInstance().getEnclaveClient(null));
  }

  @Test
  public void testDestroyEnclaveWithNullClient() {
    assertThrows(
        NullPointerException.class,
        () ->
            EnclaveManager.getInstance()
                .destroyEnclaveClient(null, EnclaveFinal.getDefaultInstance()));
  }

  @Test
  public void testDestroyEnclaveWithNullEnclaveFinal()
      throws InstantiationException, IllegalAccessException, NoSuchMethodException,
          InvocationTargetException {
    EnclaveClient client = createEnclaveClient(1);

    assertThrows(
        NullPointerException.class,
        () -> EnclaveManager.getInstance().destroyEnclaveClient(client, null));
  }

  @Test
  public void testDestroyingClosedEnclaveClient()
      throws InstantiationException, IllegalAccessException, NoSuchMethodException,
          InvocationTargetException {
    EnclaveClient client = createEnclaveClient(0);

    IllegalStateException exception =
        assertThrows(
            IllegalStateException.class,
            () ->
                EnclaveManager.getInstance()
                    .destroyEnclaveClient(client, EnclaveFinal.getDefaultInstance()));

    assertThat(exception).hasMessageThat().isEqualTo("Enclave client is already destroyed.");
  }

  private static EnclaveClient createEnclaveClient(long pointer)
      throws InstantiationException, IllegalAccessException, NoSuchMethodException,
          InvocationTargetException {
    Constructor<EnclaveClient> enclaveClientConstructor =
        EnclaveClient.class.getDeclaredConstructor(long.class);
    enclaveClientConstructor.setAccessible(true);
    return enclaveClientConstructor.newInstance(pointer);
  }
}

package com.asylo.client;

import static org.junit.Assert.assertThrows;

import com.asylo.EnclaveInput;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Java test for EnclaveClient. */
@RunWith(JUnit4.class)
public class EnclaveClientTest {

  private EnclaveClient enclaveClient;

  @Before
  public void prepare()
      throws InstantiationException, IllegalAccessException, NoSuchMethodException,
          InvocationTargetException {
    Constructor<EnclaveClient> enclaveClientConstructor =
        EnclaveClient.class.getDeclaredConstructor(long.class);
    enclaveClientConstructor.setAccessible(true);
    enclaveClient = enclaveClientConstructor.newInstance(1);
  }

  @Test
  public void testEnterAndRunEnclaveInputNullCheck() {
    assertThrows(NullPointerException.class, () -> enclaveClient.enterAndRun(null));
  }

  @Test
  public void testEnterAndRunExtensionRegistryNullCheck() {
    EnclaveInput input = EnclaveInput.newBuilder().build();
    assertThrows(NullPointerException.class, () -> enclaveClient.enterAndRun(input, null));
  }
}

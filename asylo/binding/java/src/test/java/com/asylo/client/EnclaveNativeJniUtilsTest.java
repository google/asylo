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

import com.asylo.EnclaveInput;
import com.asylo.EnclaveOutput;
import com.asylo.test.JniUtilsTestProto;
import com.google.protobuf.ExtensionRegistry;
import java.util.UUID;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/**
 * This class is used to test helper functions in native code which are present in file
 * src/main/native/jni_utils.h
 */
@RunWith(JUnit4.class)
public class EnclaveNativeJniUtilsTest {

  @Test
  public void testCheckJniForException() {
    assertThat(nativeCheckJniException()).isTrue();
  }

  @Test
  public void testThrowEnclaveExceptionUsingStatus() {
    Assert.assertThrows(EnclaveException.class, () -> nativeThrowEnclaveExceptionUsingStatus());
  }

  @Test
  public void testThrowEnclaveExceptionUsingString() {
    String random = UUID.randomUUID().toString();
    EnclaveException exception =
        Assert.assertThrows(
            EnclaveException.class, () -> nativeThrowEnclaveExceptionUsingString(random));
    assertThat(exception).hasMessageThat().isEqualTo(random);
  }

  @Test
  public void testProtoConversionBetweenJavaAndNative() {
    JniUtilsTestProto.Data inData =
        JniUtilsTestProto.Data.newBuilder()
            .setInt32Val((int) (Math.random() * 100 + 1))
            .setStringVal(UUID.randomUUID().toString())
            .build();

    EnclaveInput input =
        EnclaveInput.newBuilder().setExtension(JniUtilsTestProto.inputData, inData).build();

    ExtensionRegistry registry = ExtensionRegistry.newInstance();
    registry.add(JniUtilsTestProto.outputData);
    EnclaveOutput output = nativeProtoConversionBetweenJavaAndNative(input, registry);

    assertThat(output).isNotNull();
    JniUtilsTestProto.Data outData = output.getExtension(JniUtilsTestProto.outputData);
    assertThat(outData.getInt32Val()).isEqualTo(inData.getInt32Val());
    assertThat(outData.getStringVal()).isEqualTo(inData.getStringVal());
  }

  private native boolean nativeCheckJniException();

  private native void nativeThrowEnclaveExceptionUsingStatus();

  private native void nativeThrowEnclaveExceptionUsingString(String message);

  private native EnclaveOutput nativeProtoConversionBetweenJavaAndNative(
      EnclaveInput input, ExtensionRegistry registry);
}

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

package com.example;

import static java.nio.charset.StandardCharsets.UTF_8;

import com.asylo.EnclaveFinal;
import com.asylo.EnclaveInput;
import com.asylo.EnclaveLoadConfig;
import com.asylo.EnclaveLoadConfigSgxExtension;
import com.asylo.EnclaveOutput;
import com.asylo.SgxLoadConfig;
import com.asylo.SgxLoadConfig.FileEnclaveConfig;
import com.asylo.client.EnclaveClient;
import com.asylo.client.EnclaveManager;
import com.google.protobuf.ExtensionRegistry;
import java.util.Scanner;

/**
 * Class to demonstrate usage of Asylo Java client. This class uses the enclave created by the C++
 * quickstart example, which can be found in asylo/examples/quickstart.
 */
public class DemoDriver {
  public static void main(String[] args) {

    if (args.length != 1) {
      System.err.println("Expecting a single argument which is the filepath of an enclave.");
      System.exit(1);
    }

    String enclavePath = args[0];
    String enclaveName = "demo_enclave";

    // Part 1: Initialization
    // Specify enclave file.
    FileEnclaveConfig fileEnclaveConfig =
        FileEnclaveConfig.newBuilder().setEnclavePath(enclavePath).build();

    // Specify that the enclave uses SGX, and configure the SGX loader with the
    // path to the enclave binary.
    SgxLoadConfig sgxLoadConfig =
        SgxLoadConfig.newBuilder().setDebug(true).setFileEnclaveConfig(fileEnclaveConfig).build();

    // Specify enclave load config.
    EnclaveLoadConfig enclaveLoadConfig =
        EnclaveLoadConfig.newBuilder()
            .setName(enclaveName)
            .setExtension(EnclaveLoadConfigSgxExtension.sgxLoadConfig, sgxLoadConfig)
            .build();

    EnclaveManager.getInstance().loadEnclave(enclaveLoadConfig);

    // Part 2: Secure execution
    // Get user input.
    String plainText = getMessage();

    // Prepare input for enclave.
    Demo demoInput = Demo.newBuilder().setValue(plainText).setAction(Demo.Action.ENCRYPT).build();
    EnclaveInput enclaveInput =
        EnclaveInput.newBuilder()
            .setExtension(EnclaveDemoExtension.quickstartInput, demoInput)
            .build();

    // Register protobuf extension for output.
    ExtensionRegistry registry = ExtensionRegistry.newInstance();
    registry.add(EnclaveDemoExtension.quickstartOutput);

    EnclaveClient client = EnclaveManager.getInstance().getEnclaveClient(enclaveName);
    EnclaveOutput output = client.enterAndRun(enclaveInput, registry);
    Demo encryptedText = output.getExtension(EnclaveDemoExtension.quickstartOutput);

    System.out.println("Encrypted message:" + encryptedText.getValue());

    // Part 3: Finalization
    EnclaveFinal finalInput = EnclaveFinal.getDefaultInstance();
    EnclaveManager.getInstance().destroyEnclaveClient(client, finalInput);
  }

  public static String getMessage() {
    String plainText = null;
    try (Scanner scanner = new Scanner(System.in, UTF_8.name())) {
      System.out.println("Please enter a message to encrypt: ");
      plainText = scanner.nextLine();
    }

    if (plainText == null || plainText.length() == 0) {
      System.out.println("No input provided.");
      System.exit(1);
    }

    return plainText;
  }

  private DemoDriver() {}
}

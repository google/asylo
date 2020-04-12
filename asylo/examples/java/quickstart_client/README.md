<!--jekyll-front-matter
---

title: Asylo Java Client

overview: Run an enclave from a Java application

location: /_docs/guides/asylo_java_client.md

order: 70

layout: docs

type: markdown

toc: true

---
{% include home.html %}
jekyll-front-matter-->

This guide describes how to use Java to run an Asylo enclave that was written in
C++. This guide assumes that the reader is familiar with
[Asylo quickstart guide](https://asylo.dev/docs/guides/quickstart.html).

## Introduction

There are two parts in an enclave application written using Asylo framework,
_untrusted application_ and _trusted application (enclave)_. Asylo release 0.5.2
and older required both trusted and untrusted components to be written in C++.

With the introduction of Asylo Java client, untrusted application can now be
written in Java as well. An Asylo Java client can load and run an enclave
written in C++. This model enables users to write their enclave once and then
reuse it in an untrusted application written in C++ or Java.

## Using a Java client

An enclave can be loaded using an
[`EnclaveManager`](/asylo/binding/java/src/main/java/com/asylo/client/EnclaveManager.java).
It is a singleton class which can load an enclave from the file system by
providing the path to the enclave binary using the
[`EnclaveLoadConfig`](/asylo/enclave.proto) proto.

Users may interact with a loaded enclave through an
[`EnclaveClient`](/asylo/binding/java/src/main/java/com/asylo/client/EnclaveClient.java).
The `EnclaveManager` returns a loaded and named `EnclaveClient` with the method
`getEnclaveClient`.

Most of the configurations, inputs, and outputs in a Java client are passed
using
[protocol-buffer messages](https://developers.google.com/protocol-buffers/docs/reference/cpp/google.protobuf.message#Message).

One major difference between the Java and C++ APIs is that in Java, errors are
thrown as exceptions derived from
[`EnclaveException`](/asylo/binding/java/src/main/java/com/asylo/client/EnclaveException.java),
rather returned through a `StatusOr<T>` type.

The following snippet is a small example of a Java client that interacts with an
enclave written in C++.

```java
public static void main(String[] args) {

  if (args.length != 1) {
    System.err.println("Expecting a single argument which is the filepath of an enclave.");
    System.exit(1);
  }

  String enclavePath = args[0];
  String enclaveName = "demo_enclave";

  // Part 1: Initialization
  // Specify the enclave file.
  FileEnclaveConfig fileEnclaveConfig =
      FileEnclaveConfig.newBuilder().setEnclavePath(enclavePath).build();

  // Specify that the enclave uses SGX, and configure the SGX loader with the
  // path to the enclave binary.
  SgxLoadConfig sgxLoadConfig =
      SgxLoadConfig.newBuilder().setDebug(true).setFileEnclaveConfig(fileEnclaveConfig).build();

  // Specify the enclave name and inject the SGX configuration.
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
```

The above snippet is conceptually the same as the one mentioned in
[enclave lifecycle](https://asylo.dev/docs/guides/quickstart.html#enclave-lifecycle)

## Building and running an enclave Java application

The Java library `//asylo:enclave_client_java` provides the API to load C++
enclaves in Java.

```python
java_binary(
    name = "quickstart",
    srcs = [
        "src/main/java/com/example/DemoDriver.java",
    ],
    main_class = "com.example.DemoDriver",
    deps = [
        ":demo_java_proto",
        "//java/com/google/protobuf",
        "//asylo:enclave_client_java",
    ],
)

java_proto_library(
    name = "demo_java_proto",
    deps = [
        "//quickstart:demo_proto",
    ],
)
```

The [Bazel](https://bazel.build) BUILD file shown above has untrusted java code
in the target `:quickstart`, which contains the code to handle logic of
initializing, running, and finalizing the enclave.

To run this example first we need an enclave. The following workflow uses the
enclave from
[Asylo quickstart guide](https://asylo.dev/docs/guides/quickstart.html#building-and-running-an-enclave-application)
by running:

```bash
bazel build //asylo/examples/quickstart:demo_enclave_sgx_sim.so
```

Copy the generated file to some location:

```bash
cp $(bazel info bazel-bin)/quickstart/demo_enclave_sgx_sim.so /tmp/demo_enclave_sgx_sim.so
```

Now, untrusted Java client can be run as:

```bash
bazel run //asylo/examples/java/quickstart_client:quickstart /tmp/demo_enclave_sgx_sim.so
```

You should then see a prompt for a message to encrypt, similar to the quickstart
guide.

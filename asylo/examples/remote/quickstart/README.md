<!--jekyll-front-matter
---

title: Remote Backend Quickstart Guide

overview: Learn how to utilize Asylo Remote Backend

location: /_docs/guides/remote_quickstart.md

order: 50

layout: docs

type: markdown

toc: true

---
{% include home.html %}
jekyll-front-matter-->

This guide demonstrates using Asylo with a Remote Backend. It assumes the reader
has knowledge introduced in the
[quickstart guide](https://github.com/google/asylo/examples/quickstart/README.md).

## Introduction

### What is an Asylo Remote Backend?

An Asylo Remote Backend provides Asylo users with the capability to run a local
application running on untrusted hardware and distribute secure operations to
trusted systems with enclaves. After launching an enclave with an
`EnclaveLoader` and `EnclaveManager`, the local application will interact with
it through a `GenericEnclaveClient` like normal.

The Asylo Remote Backend utilizes [gRPC](https://www.grpc.io) and a uniquely
built Communicator to set up a peer to peer connection between the local
application and the remote enclave. The Communicator handles translating local
application requests to remote enclave execution.

In a well designed enclave, data passed between an untrusted client and trusted
enclave is expected to be encrypted. The ability to enable the additional
precaution of adding encryption to the gRPC connection is provided.

### Components

-   `RemoteEnclaveProxyServer`

    Provides the target process with the set of trusted primitives, allowing the
    enclave code to run even though it is not loaded into the host process.

    Utilizes a gRPC server that waits for a request for connection from a
    `RemoteEnclaveProxyClient`. The request contains the network address of the
    `RemoteEnclaveProxyClient` for bidirectional communication.

-   `RemoteEnclaveProxyClient`

    Provides the host process with the set of untrusted primitives, allowing the
    host code to run even though the enclave is located outside of the host
    process.

    Utilizes a gRPC client that sends a request for connection to the
    `RemoteEnclaveProxyServer`. The request contains the network address of the
    `RemoteEnclaveProxyClient` for bidirectional communication and the
    configuration of the actual enclave to be loaded, including the path to its
    binary.

### Example Use Cases

1.  Applications run primarily on hardware that has no enclave support. The
    portions of the application that are deemed confidential can be secured
    remotely with a Remote Backend, while the rest of the application can run on
    the unsecured host.

    Example: An application could utilize on-prem SGX Enclaves with a Remote
    Backend while running on an edge device.

2.  Data owners would like to share access to their data without sharing or
    transporting the data itself in a Data as a Service model.

    Example: The data owner would be able to setup Remote Enclaves for access to
    their data. The data would be accessible through the enclave, operations on
    the data would be secure, and the messages passed between accessor and data
    warehouse could be secured through encryption.

### How does the Asylo Remote Backend work?

When the untrusted application requests loading the enclave remotely, Remote
Enclave Backend instantiates `RemoteEnclaveProxyClient`. The latter in turn
utilizes a Provisioning callback to provision a `RemoteEnclaveProxyServer`,
which connects to the client through a bi-directional gRPC connection. When
`RemoteEnclaveProxyClient` calls `Connect` the `RemoteEnclaveProxyServer` loads
the actual enclave into its trusted address space. Once the loading succeeds,
`RemoteEnclaveProxyClient` forwards each enclave entry call to remotely loaded
enclave through `RemoteEnclaveProxyServer`. When the enclave makes a hostcall,
syscall, or other exit call it is forwarded to the `RemoteEnclaveProxyClient`
and handled locally on that system.

## Getting started with the example code

Run the following commands to grab our Docker container and download the example
source code used in this guide. See our
[README](https://github.com/google/asylo/blob/master/README.md) for additional
instructions on Docker usage.

```bash
docker pull gcr.io/asylo-framework/asylo
MY_PROJECT=~/asylo-examples
mkdir -p "${MY_PROJECT}"
wget -q -O - https://github.com/google/asylo-examples/archive/master.tar.gz | \
    tar -zxv --strip 1 --directory "${MY_PROJECT}"
```

Note that you can set `MY_PROJECT` to any directory of your choice. This
environment variable is later used in the instructions for
[building-and-running](#building-and-running-a-remote-enclave-application-on-a-single-machine)
the enclave application in this example.

The example source code can be found in the
[Asylo SDK](https://github.com/google/asylo/tree/master/asylo/examples) on
GitHub.

## Remote Enclave lifecycle

Entering a Remote Enclave has been built to be as similar to entering a local
enclave as possible. One of the key differences is there must be a provisioniong
service that is accessed via `asylo::RemoteProvision::Instantiate()` (specific
implementation may start remote proxy locally or remotely).

To demonstrate the differences, this code has been branched from the quickstart
guide, with the changes highlighted with comments:

```cpp
ABSL_FLAG(std::string, enclave_path, "",
          "Path to enclave binary image to load");
ABSL_FLAG(std::string, message, "", "Message to encrypt");

// ADDITION
ABSL_FLAG(std::string, remote_proxy, "",
          "Path to binary for running RemoteEnclaveProxyServer");

int main(int argc, char *argv[]) {
  absl::ParseCommandLine(argc, argv);

  constexpr char kEnclaveName[] = "demo_enclave";

  const std::string message = absl::GetFlag(FLAGS_message);
  LOG_IF(QFATAL, message.empty()) << "Empty --message flag.";

  const std::string enclave_path = absl::GetFlag(FLAGS_enclave_path);
  LOG_IF(QFATAL, enclave_path.empty()) << "Empty --enclave_path flag.";

  // ADDITION
  // Part 1: Initialization

  // Prepare |EnclaveManager| with default |EnclaveManagerOptions|
  asylo::EnclaveManager::Configure(asylo::EnclaveManagerOptions());
  auto manager_result = asylo::EnclaveManager::Instance();
  LOG_IF(QFATAL, !manager_result.ok()) << "Could not obtain EnclaveManager";

  // Prepare |load_config| message.
  asylo::EnclaveLoadConfig load_config;
  load_config.set_name(kEnclaveName);

  // BEGIN_ADDITION
  // Prepare |remote_config| message.
  auto proxy_config_result = RemoteProxyClientConfig::DefaultsWithProvision(
      asylo::RemoteProvision::Instantiate());
  LOG_IF(QFATAL, !proxy_config_result.ok())
      << "Could not build RemoteProxyClientConfig";

  auto remote_config = load_config.MutableExtension(asylo::remote_load_config);
  remote_config->set_remote_proxy_config(
      reinterpret_cast<uintptr_t>(proxy_config_result.value().get()));
  // END_ADDITION

  // Prepare |sgx_config| message.
  auto sgx_config = remote_config->mutable_sgx_load_config(); // ALTERATION
  sgx_config->set_debug(true);
  auto file_enclave_config = sgx_config->mutable_file_enclave_config();
  file_enclave_config->set_enclave_path(enclave_path);

  // Load Enclave with prepared |EnclaveManager| and |load_config| message.
  asylo::EnclaveManager *manager = manager_result.value();
  auto status = manager->LoadEnclave(load_config);
  LOG_IF(QFATAL, !status.ok()) << "LoadEnclave failed with: " << status;

  // Part 2: Secure execution

  // Prepare |input| with |message| and create |output| to retrieve response
  // from enclave.
  asylo::EnclaveInput input;
  SetEnclaveUserMessage(&input, message);
  asylo::EnclaveOutput output;

  // Get |EnclaveClient| for loaded enclave and execute |EnterAndRun|.
  asylo::EnclaveClient *const client = manager->GetClient(kEnclaveName);
  status = client->EnterAndRun(input, &output);
  LOG_IF(QFATAL, !status.ok()) << "EnterAndRun failed with: " << status;

  // Part 3: Finalization

  // |DestroyEnclave| before exiting program.
  asylo::EnclaveFinal empty_final_input;
  status = manager->DestroyEnclave(client, empty_final_input, false);
  LOG_IF(QFATAL, !status.ok()) << "DestroyEnclave failed with: " << status;

  return 0;
}
```

The changes from the non-remote quickstart guide are as follows:

1.  `RemoteProxyClientConfig`

    The `RemoteProxyClientConfig` object provides a `RemoteEnclaveProxyClient`
    with the configruation to provision and make a secure connection with a
    `RemoteEnclaveProxyServer`. We create one and pass the memory address to the
    `EnclaveManager` through the `RemoteLoadConfig`

2.  `RemoteLoadConfig`

    The `RemoteLoadConfig` holds a regular `SgxLoadConfig` and passes it to the
    `RemoteEnclaveProxyServer` to load the enclave. The `RemoteLoadConfig` needs
    to be built with the filepath of the enclave shared object library on the
    `RemoteEnclaveProxyServer`.

3.  `remote_proxy` flag

    The `remote_proxy` flag points to a binary that will be executed in order to
    start a `RemoteEnclaveProxyServer`. Normally this would be done by a
    provisioning layer, but is started manually as part of this example.

4.  `sgx_config`

    The `sgx_config` variable is created by the `remote_config` rather than the
    `enclave_config`. This is because the it is sent across the wire to the
    `RemoteEnclaveProxyServer` and used as part of the launch.

## Writing an enclave application

The enclave application is the same as the original Quickstart example. Except
that it has been updated to send the output string back to the host server and
printed there.

## Building and running a remote enclave application on a single machine

To build our remote enclave application, we define several targets that utilize
a sgx backend and then run it in simulated mode. See the
[overview](https://asylo.dev/about/overview.html#security-backends) for details
on all supported backends.

```python
proto_library(
    name = "demo_proto",
    srcs = ["demo.proto"],
    deps = ["//asylo:enclave_proto"],
)

cc_proto_library(
    name = "demo_cc_proto",
    deps = [":demo_proto"],
)

cc_unsigned_enclave(
    name = "demo_enclave_unsigned.so",
    srcs = ["demo_enclave.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":demo_cc_proto",
        "@com_google_absl//absl/base:core_headers",
        "@com_google_absl//absl/strings",
        "//asylo:enclave_runtime",
        "//asylo/crypto:aead_cryptor",
        "//asylo/util:cleansing_types",
        "//asylo/util:status",
    ],
)

sgx_debug_enclave(
    name = "demo_enclave_debug.so",
    unsigned = ":demo_enclave_unsigned.so",
)

enclave_loader(
    name = "quickstart",
    srcs = ["demo_driver.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    enclaves = {"enclave": ":demo_enclave_debug.so"},
    loader_args = [
        "--enclave_path='{enclave}'",
        "--message='clock'",
    ],
    remote_proxy = "//asylo/util/remote:sgx_remote_proxy",
    visibility = ["//asylo:implementation"],
    deps = [
        ":demo_cc_proto",
        "@com_google_absl//absl/flags:flag",
        "@com_google_absl//absl/flags:parse",
        "//asylo:enclave_client",
        "//asylo/util:logging",
        "//asylo/platform/primitives/sgx:loader_cc_proto",
        "//asylo/util:status",
        "//asylo/util/remote:remote_loader_cc_proto",
        "//asylo/util/remote:remote_proxy_config",
    ],
)
```

The [Bazel](https://bazel.build) BUILD file shown above defines our enclave's
logic in a `sgx_debug_enclave` called `demo_enclave_debug.so`. This target
contains our implementation of `TrustedApplication` and is linked against the
Asylo runtime. We use a `sgx_debug_enclave` rule to generate an enclave that can
be run in debug mode.

The untrusted component is the target `//remote/quickstart`, which contains code
to handle the logic of initializing, running, and finalizing the enclave, as
well as sending and receiving messages through the enclave boundary. In a
non-enclave application, we would write `:quickstart` as a *cc_binary* target,
but the `enclave_loader` rule streamlines the combination of driver and enclave
targets. Specifically, it ensures that *demo_driver.cc* is compiled with the
host crosstool, `:demo_enclave_debug.so` is compiled with the
enclave-backend-specific crosstool, and that the untrusted enclave loader is
invoked with a flag that specifies the enclave's path.

Let us now run the demo enclave inside the Docker image we downloaded
[above](#getting-started-with-the-example-code). You can set the `--message`
flag passed to the `//remote/quickstart` target to contain any string that you
would like to encrypt.

First, if you haven't already done so, download the Asylo SDK and Examples
repos:

```bash
ASYLO_SDK=~/asylo-sdk
git clone https://github.com/google/asylo.git "${ASYLO_SDK}"
MY_PROJECT=~/asylo-examples
mkdir -p "${MY_PROJECT}"
wget -q -O - https://github.com/google/asylo-examples/archive/master.tar.gz | \
    tar -zxv --strip 1 --directory "${MY_PROJECT}"
```

Then run the quickstart example:

Note: The following command runs the enclave in sgx mode (to run it in simulated
mode, replace `CONFIG_TYPE=sgx` with `CONFIG_TYPE=sgx-sim`).

```bash
export MESSAGE="Asylo Rocks" # Or another message
export CONFIG_TYPE=sgx # Or sgx-sim if Remote Provision server isn't running on SGX-enabled hardware.
docker run -it --net=host \
    -v ${ASYLO_SDK}:/opt/asylo/sdk \
    -v ${MY_PROJECT}:/opt/asylo/examples \
    -e MESSAGE='${MESSAGE}' \
    -e CONFIG_TYPE=${CONFIG_TYPE} \
    -w /opt/asylo/examples \
    gcr.io/asylo-framework/asylo:latest \
    sh -c 'bazel run --config=${CONFIG_TYPE} --define=ASYLO_REMOTE=1 //remote/quickstart -- --message="${MESSAGE}"'
```

It will then print an encrypted message similar to the following:

```
Encrypted message:
2dc402068266ba995608e0d4a16c1604b792355d4635dec43cf2888cf2036d2007772ed5f24e5c
```

Congratulations on building and running your first remote enclave application!

### Building and running a remote enclave application with remote provisioning

Note that the demo above had ran the application within a single docker image.

To make it truly remote, we will now build and run the same application with
enclaves deployed on another docker image, using
[provision server](https://github.com/google/asylo/tree/master/asylo/examples/remote/provision_server).

First, if you haven't already done so, download the Asylo SDK and Examples
repos:

```bash
export ASYLO_SDK=~/asylo-sdk
git clone https://github.com/google/asylo.git "${ASYLO_SDK}"
export MY_PROJECT=~/asylo-examples
mkdir -p "${MY_PROJECT}"
wget -q -O - https://github.com/google/asylo-examples/archive/master.tar.gz | \
    tar -zxv --strip 1 --directory "${MY_PROJECT}"
```

Next, run the provision server:

```bash
docker run -it --net=host \
    -v ${ASYLO_SDK}:/opt/asylo/sdk \
    -v ${MY_PROJECT}:/opt/asylo/examples \
    -w /opt/asylo/examples/remote/provision_server \
    gcr.io/asylo-framework/asylo:latest \
    ./build.sh
```

Then, once it started and reported listening to the port `4321` (configurable),
build and run the application `quickstart_remote` (to run it in simulated mode,
replace `CONFIG_TYPE=sgx` with `CONFIG_TYPE=sgx-sim`):

```bash
export MESSAGE="Asylo Rocks" # Or another message
export CONFIG_TYPE=sgx # Or sgx-sim if not running on SGX-enabled hardware.
docker run -it --net=host \
    -v ${ASYLO_SDK}:/opt/asylo/sdk \
    -v ${MY_PROJECT}:/opt/asylo/examples \
    -e MESSAGE='${MESSAGE}' \
    -e CONFIG_TYPE=${CONFIG_TYPE} \
    -w /opt/asylo/examples/remote/quickstart \
    gcr.io/asylo-framework/asylo:latest \
    ./build.sh "${MESSAGE}" ${CONFIG_TYPE}
```

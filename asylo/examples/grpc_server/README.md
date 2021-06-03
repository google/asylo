<!--jekyll-front-matter
---

title: gRPC Server Example

overview: Run a gRPC server inside an enclave.

location: /_docs/guides/grpc_server.md

order: 20

layout: docs

type: markdown

toc: true

---
{% include home.html %}
jekyll-front-matter-->

This guide describes how to run a gRPC server inside an enclave and interact
with it from a client running in an untrusted environment.

**NOTE:** Since release 0.5.0, the example has undergone a major refactoring.
The most significant change is that the gRPC server running in the enclave no
longer waits for a timeout to expire because that logic was moved into the
driver. For that reason the Shutdown API is no longer necessary and has been
removed. Instead, the enclave's `Run` method just stores the assigned port in
`EnclaveOutput` and returns immediately.

**NOTE:** The `GrpcSeverEnclave` driver code was also restructured to have a
separate [`grpc_server_util`](#grpc-server-util-module) module, where the bulk
of the logic that invokes the `GrpcServerEnclave`'s entry-points now resides.

This guide assumes that you are familiar with:

*   The [Asylo quickstart guide](https://asylo.dev/docs/guides/quickstart.html)
*   The [gRPC C++ basics](https://grpc.io/docs/tutorials/basic/cpp) tutorial
*   [Protocol Buffers](https://developers.google.com/protocol-buffers/)
*   The C++ language

## Introduction

The Asylo enclave runtime features rich POSIX support that allows full-featured
[gRPC](https://grpc.io/) servers to run inside an enclave. Enclaves can then
serve as secure nodes in your distributed systems and cloud applications.

The source files for this example are located in the
[grpc_server](https://github.com/google/asylo-examples/tree/master/grpc_server)
directory of [asylo-examples](https://github.com/google/asylo-examples).
Download the latest release
[here](https://github.com/google/asylo-examples/releases).

## Setting up the environment

To get started with the example code quickly, you can use the Asylo Docker image
by following
[the Docker instructions in the Asylo repository README.md](https://github.com/google/asylo/blob/master/README.md#running-an-interactive-terminal)
and running the `bazel` commands below inside an interactive Docker terminal. If
you'd like to run your code outside of Docker, you can follow
[the manual installation instructions in the README.md](https://github.com/google/asylo/blob/master/README.md#manual-installation).

## Defining the gRPC service

This example shows how to run a gRPC server that implements a simple translation
service inside an enclave. The service provides translations of some Greek words
into English.

This example uses the following service definition from
[translator_server.proto](/asylo/examples/grpc_server/translator_server.proto):

```protobuf
// A request message containing a word to be translated.
message GetTranslationRequest {
  optional string input_word = 1;
}

// A response message containing the translation of a GetTranslationRequest's
// input_word.
message GetTranslationResponse {
  optional string translated_word = 1;
}

service Translator {
  // Translates the given word.
  rpc GetTranslation(GetTranslationRequest) returns (GetTranslationResponse) {
    // errors: no input word, no translation available
  }
}
```

This document doesn't include the server implementation because the details are
mostly irrelevant to this example. To learn about the server implementation, see
[translator_server_impl.h](/asylo/examples/grpc_server/translator_server_impl.h)
and
[translator_server_impl.cc](/asylo/examples/grpc_server/translator_server_impl.cc).

## Setting up a server enclave

This example features a step-by-step guide to writing a custom server enclave so
that you can see how gRPC works within Asylo. However, if you want to skip the
example and get a server up and running sooner, you can use the `EnclaveServer`
utility included in Asylo. `EnclaveServer` is a whole enclave that runs a single
gRPC service. You can find `EnclaveServer` in
[enclave_server.h](/asylo/grpc/util/enclave_server.h).

To set up the server, the enclave needs to know the desired server address and
the maximum time the server will wait before shutting down the server. This
information can be passed through the `Initialize` method, which accepts an
`EnclaveConfig`. This example extends the `EnclaveConfig` in a new file named
[grpc_server_config.proto](/asylo/examples/grpc_server/grpc_server_config.proto):

```protobuf
extend asylo.EnclaveConfig {
  // The address that the gRPC server inside the enclave will be hosted on.
  // Required.
  optional string server_address = 205739939;

  // The port that the gRPC server should listen to. Required. May be 0 to
  // request that the server let the operating system choose an unused port.
  optional int32 port = 253106740;
}

extend asylo.EnclaveOutput {
  // The Translator server's port.
  optional int32 actual_server_port = 285084421;
}
```

This example maps the logic of setting up the gRPC server to the virtual methods
of `TrustedApplication` as follows:

*   The `Initialize` method builds and starts the gRPC server using the
    information from the `EnclaveConfig`.
*   The `Run` method writes the server's final port to an extension of the
    `EnclaveOutput` message and returns an `OK` status. All of our interaction
    with the enclave goes through gRPC, so `Run` doesn't need to do any other
    work.
*   The `Finalize` method shuts down the gRPC server.

The enclave keeps track of the server, service object in member variables. This
example defines the server enclave in
[grpc_server_enclave.cc](/asylo/examples/grpc_server/grpc_server_enclave.cc):

```cpp
class GrpcServerEnclave final : public asylo::TrustedApplication {
 public:
  asylo::Status Initialize(const asylo::EnclaveConfig &enclave_config)
      ABSL_LOCKS_EXCLUDED(server_mutex_) override;

  asylo::Status Run(const asylo::EnclaveInput &enclave_input,
                    asylo::EnclaveOutput *enclave_output) override;

  asylo::Status Finalize(const asylo::EnclaveFinal &enclave_final)
      ABSL_LOCKS_EXCLUDED(server_mutex_) override;

 private:
  absl::Mutex server_mutex_;
  std::unique_ptr<::grpc::Server> server_ ABSL_GUARDED_BY(server_mutex_);
  std::unique_ptr<TranslatorServerImpl> service_;
  int selected_port_;
};
```

#### Initializing the server

The `Initialize` method uses `grpc::ServerBuilder` to configure and start the
server. The server configuration includes the `server_address` extension from
the `EnclaveConfig` and the `service_` member described above. The logic of the
`Initialize` method ensures that the server is initialized and started only one
time.

If the `EnclaveConfig` does not have a `server_address` extension or if the
server fails to start, then `Initialize` returns a non-OK `Status`. Otherwise,
`Initialize` returns an OK `Status`:

```cpp
asylo::Status GrpcServerEnclave::Initialize(
    const asylo::EnclaveConfig &enclave_config)
        ABSL_LOCKS_EXCLUDED(server_mutex_) {
  if (!enclave_config.HasExtension(server_address)) {
    return asylo::Status(asylo::error::GoogleError::INVALID_ARGUMENT,
                         "Expected a server_address extension on config.");
  }

  if (!enclave_config.HasExtension(port)) {
    return asylo::Status(asylo::error::GoogleError::INVALID_ARGUMENT,
                         "Expected a port extension on config.");
  }

  absl::MutexLock lock(&server_mutex_);

  if (server_) {
    return asylo::Status(asylo::error::GoogleError::ALREADY_EXISTS,
                         "Server is already started");
  }

  ::grpc::ServerBuilder builder;

  std::shared_ptr<::grpc::ServerCredentials> server_credentials =
      ::grpc::InsecureServerCredentials();

  builder.AddListeningPort(
      absl::StrCat(enclave_config.GetExtension(server_address), ":",
                   enclave_config.GetExtension(port)),
      server_credentials, &selected_port_);

  service_ = absl::make_unique<TranslatorServerImpl>();

  builder.RegisterService(service_.get());

  server_ = builder.BuildAndStart();
  if (!server_) {
    return asylo::Status(asylo::error::GoogleError::INTERNAL,
                         "Failed to start server");
  }

  return absl::OkStatus();
}
```

**NOTE:** This gRPC server uses `InsecureServerCredentials`. This means that the
server uses no additional security for channel establishment. The server and its
clients are not authenticated, and no channels are secured. **This configuration
is not suitable for a production environment**, but it is fine for this
demonstration.

#### Running the server

The `Run` method returns an OK `Status` and an `EnclaveOutput` containing the
port assigned to the gRPC server:

```cpp
asylo::Status GrpcServerEnclave::Run(const asylo::EnclaveInput &enclave_input,
                                     asylo::EnclaveOutput *enclave_output) {
  enclave_output->SetExtension(server_port, selected_port_);
  return absl::OkStatus();
}
```

#### Finalizing the server

The `Finalize` method shuts down the server with a 500 millisecond timeout for
all outstanding RPCs. `Finalize` also informs the user that the server is
shutting down:

```cpp
asylo::Status GrpcServerEnclave::Finalize(
    const asylo::EnclaveFinal &enclave_final)
        ABSL_LOCKS_EXCLUDED(server_mutex_) {
  absl::MutexLock lock(&server_mutex_);

  if (server_) {
    LOG(INFO) << "Server shutting down";

    server_->Shutdown(std::chrono::system_clock::now() +
                      std::chrono::milliseconds(500));
    server_.reset(nullptr);
  }

  return absl::OkStatus();
}
```

This enclave uses `LOG()` statements to print information to `stdout` and
`stderr`. Asylo's logging system also writes all logs to the file system. By
default, logs are written to `/tmp/${ENCLAVE_NAME}`. You can configure the log
file path using the `logging_config` field of the `EnclaveConfig` object.

## Driving the enclave

The driver for the server enclave does the following:

*   Loads the enclave, passing the address that the server will run on using the
    `server_address` extension of `EnclaveConfig`
*   Enters the enclave to get the port assigned to the server
*   Finalizes the enclave cleanly

This example implements the driver in
[grpc_server_driver.cc](/asylo/examples/grpc_server/grpc_server_driver.cc).

#### Driver setting definitions

The driver defines three flags and a `constexpr` string to hold the information
it needs:

```cpp
ABSL_FLAG(std::string, enclave_path, "", "Path to enclave to load");

ABSL_FLAG(int32_t, server_max_lifetime, 300,
          "The longest amount of time (in seconds) that the server should be "
          "allowed to run");

ABSL_FLAG(int32_t, port, 0, "Port that the server listens to");

constexpr char kServerAddress[] = "localhost";
```

The `localhost` address indicates that the server should run locally. Default
port value 0 indicates that the port will be chosen by the operating system.

#### gRPC server util module

The driver interacts with the enclave using the `grpc_server_util` module. This
module contains the core logic for invoking the `GrpcServerEnclave`'s
entry-points. Each of its functions assumes that the `asylo::EnclaveManager`
instance has been configured using `asylo::EnclaveManager::Configure()`.

They are declared in
[grpc_server_util.h](/asylo/examples/grpc_server/grpc_server_util.h) and
implemented in
[grpc_server_util.cc](/asylo/examples/grpc_server/grpc_server_util.cc).

`LoadGrpcServerEnclave` loads the GrpcServerEnclave from `enclave_path`. If
`debug_enclave` is true, then the enclave is started in debug mode. By loading
the enclave, `LoadGrpcServerEnclave` starts the enclave's server on
`server_port` and configures the server to refer requests to the
`GetTranslation` RPC.

```cpp
asylo::Status LoadGrpcServerEnclave(const std::string &enclave_path,
                                    int server_port, bool debug_enclave) {
  asylo::EnclaveLoadConfig load_config;
  load_config.set_name(kEnclaveName);

  asylo::EnclaveConfig *config = load_config.mutable_config();
  config->SetExtension(server_address, kServerAddress);
  config->SetExtension(port, server_port);

  asylo::SgxLoadConfig *sgx_config =
      load_config.MutableExtension(asylo::sgx_load_config);
  sgx_config->mutable_file_enclave_config()->set_enclave_path(enclave_path);
  sgx_config->set_debug(debug_enclave);

  asylo::EnclaveManager *manager = nullptr;
  ASYLO_ASSIGN_OR_RETURN(manager, asylo::EnclaveManager::Instance());

  return manager->LoadEnclave(load_config);
}
```

`GrpcServerEnclaveGetPort` retrieves the port of the server inside the
`GrpcServerEnclave`. It returns a non-OK `Status` if the `GrpcServerEnclave` is
not running.

```cpp
asylo::StatusOr<int> GrpcServerEnclaveGetPort() {
  asylo::EnclaveManager *manager = nullptr;
  ASYLO_ASSIGN_OR_RETURN(manager, asylo::EnclaveManager::Instance());

  asylo::EnclaveClient *client = manager->GetClient(kEnclaveName);
  if (!client) {
    return asylo::Status(asylo::error::FAILED_PRECONDITION,
                         absl::StrCat(kEnclaveName, " not running"));
  }

  asylo::EnclaveInput enclave_input;
  asylo::EnclaveOutput enclave_output;
  ASYLO_RETURN_IF_ERROR(client->EnterAndRun(enclave_input, &enclave_output));
  if (!enclave_output.HasExtension(actual_server_port)) {
    return asylo::Status(asylo::error::INTERNAL,
                         "Server output missing server_port extension");
  }
  return enclave_output.GetExtension(actual_server_port);
}
```

`DestroyGrpcServerEnclave` destroys the `GrpcServerEnclave` and returns its
finalization `Status`. It returns a non-OK `Status` if the `GrpcServerEnclave`
is not running.

```cpp
asylo::Status DestroyGrpcServerEnclave() {
  asylo::EnclaveManager *manager = nullptr;
  ASYLO_ASSIGN_OR_RETURN(manager, asylo::EnclaveManager::Instance());

  asylo::EnclaveClient *client = manager->GetClient(kEnclaveName);
  if (!client) {
    return asylo::Status(asylo::error::FAILED_PRECONDITION,
                         absl::StrCat(kEnclaveName, " not running"));
  }

  asylo::EnclaveFinal final_input;
  return manager->DestroyEnclave(client, final_input);
}
```

#### Parsing flags and creating configuration

The driver's `main` function starts by parsing command-line arguments:

```cpp
  absl::ParseCommandLine(argc, argv);

  std::string enclave_path = absl::GetFlag(FLAGS_enclave_path);
  LOG_IF(QFATAL, enclave_path.empty()) << "--enclave_path cannot be empty";
```

#### Starting the enclave

The driver configures the `EnclaveManager` and calls `LoadGrpcServerEnclave` in
[`grpc_server_util`](#grpc-server-util-module) module to load the enclave,
indicating the desired server port (if specified) and whether to start the
enclave in debug mode. The call to `LoadGrpcServerEnclave` triggers a call to
the `Initialize` method of the `TrustedApplication`:

```cpp
  asylo::Status status =
      asylo::EnclaveManager::Configure(asylo::EnclaveManagerOptions());
  LOG_IF(QFATAL, !status.ok())
      << "Failed to configure EnclaveManager: " << status;

  status = examples::grpc_server::LoadGrpcServerEnclave(
      enclave_path, absl::GetFlag(FLAGS_port), absl::GetFlag(FLAGS_debug));
  LOG_IF(QFATAL, !status.ok())
      << "Loading " << enclave_path << " failed: " << status;

  asylo::StatusOr<int> port_result =
      examples::grpc_server::GrpcServerEnclaveGetPort();
  LOG_IF(QFATAL, !port_result.ok())
      << "Retrieving port failed: " << port_result.status();

  std::cout << "Server started on port " << port_result.value()
            << std::endl;
```

#### Entering the enclave

The driver blocks for the configured timeout period, allowing the enclave and
the gRPC service to run on other threads.

```cpp
  absl::SleepFor(absl::Seconds(absl::GetFlag(FLAGS_server_max_lifetime)));
```

While the enclave's gRPC server is running, clients can communicate with it
through the assigned server port.

#### Finalizing the enclave

The driver then finalizes the enclave:

```cpp
  status = examples::grpc_server::DestroyGrpcServerEnclave();
  LOG_IF(QFATAL, !status.ok())
      << "Destroy " << enclave_path << " failed: " << status;
```

## Building the application

To build the gRPC service with Bazel, the
[BUILD file](/asylo/examples/grpc_server/BUILD) needs the following targets:

*   A `proto_library` target that contains the proto definitions
*   A `cc_proto_library` target that contains the C++ language specific proto
    definitions
*   A `cc_grpc_library` target that contains the generated service code
*   A `cc_library` target that contains the implementation of the service

```python
proto_library(
    name = "translator_server_proto",
    srcs = ["translator_server.proto"],
    tags = ASYLO_ALL_BACKEND_TAGS,
)

cc_proto_library(
    name = "translator_server_cc_proto",
    tags = ASYLO_ALL_BACKEND_TAGS,
    deps = [":translator_server_proto"],
)

cc_grpc_library(
    name = "translator_server",
    srcs = [":translator_server_proto"],
    tags = ASYLO_ALL_BACKEND_TAGS,
    grpc_only = True,
    deps = [":translator_server_cc_proto"],
)

cc_library(
    name = "translator_server_impl",
    hdrs = ["translator_server_impl.h"],
    srcs = ["translator_server_impl.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    tags = ASYLO_ALL_BACKEND_TAGS,
    deps = [
        ":translator_server",
        "@com_google_absl//absl/base:core_headers",
        "@com_google_absl//absl/container:flat_hash_map",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/synchronization",
        "@com_github_grpc_grpc//:grpc++",
    ],
)
```

The enclave requires the following additional targets:

*   A `proto_library` target that contains the extensions to the enclave proto
    definitions.
*   A `cc_proto_library` target that contains the C++ language specific
    extension to the enclave proto definitions.
*   A `cc_unsigned_enclave` target that contains the enclave behavior without
    the configuration and signer identity metadata. This enclave is configured
    with `grpc_enclave_config`, which expands the heap size and maximum number
    of threads to accommodate gRPC's resource requirements.
*   A `debug_sign_enclave` target is a signed enclave that Asylo can load and
    run in debug mode. This rule adds the enclave configuration and a signature
    of the bits in `sgx_cc_unsigned_enclave` to the unsigned enclave. The
    signing key is a debug key that is distributed with the Asylo source code.

```python
proto_library(
    name = "grpc_server_config_proto",
    srcs = ["grpc_server_config.proto"],
    deps = [
        "//asylo:enclave_proto",
    ],
)

cc_proto_library(
    name = "grpc_server_config_cc_proto",
    deps = [":grpc_server_config_proto"],
)

cc_unsigned_enclave(
    name = "grpc_server_enclave_unsigned.so",
    srcs = ["grpc_server_enclave.cc"],
    backends = sgx.backend_labels,
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":grpc_server_config_cc_proto",
        ":translator_server_impl",
        "@com_google_absl//absl/base:core_headers",
        "@com_google_absl//absl/memory",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/synchronization",
        "@com_google_absl//absl/time",
        "//asylo:enclave_runtime",
        "//asylo/util:status",
        "@com_github_grpc_grpc//:grpc++",
        "@com_github_grpc_grpc//:grpc++_reflection",
    ],
)

debug_sign_enclave(
    name = "grpc_server_enclave.so",
    backends = sgx.backend_labels,
    config = "//asylo/grpc/util:grpc_enclave_config",
    unsigned = "grpc_server_enclave_unsigned.so",
)

```

Finally, the BUILD file needs an `enclave_loader` target for the driver with an
additional `cc_library` target that contains the routines for loading and
unloading the enclave:

```python
enclave_loader(
    name = "grpc_server",
    srcs = ["grpc_server_driver.cc"],
    copts = ASYLO_DEFAULT_COPTS,
    enclaves = {"enclave": ":grpc_server_enclave.so"},
    loader_args = ["--enclave_path='{enclave}'"],
    deps = [
        ":grpc_server_util",
        "//net/proto2/public:proto2",
        "@com_google_absl//absl/flags:flag",
        "@com_google_absl//absl/flags:parse",
        "@com_google_absl//absl/time",
        "//asylo:enclave_client",
        "//asylo/util:logging",
        "//asylo/util:status",
    ],
)

cc_library(
    name = "grpc_server_util",
    srcs = ["grpc_server_util.cc"],
    hdrs = ["grpc_server_util.h"],
    copts = ASYLO_DEFAULT_COPTS,
    deps = [
        ":grpc_server_config_cc_proto",
        "//net/proto2/public:proto2",
        "@com_google_absl//absl/strings",
        "//asylo:enclave_cc_proto",
        "//asylo:enclave_client",
        "//asylo/platform/primitives/sgx:loader_cc_proto",
        "//asylo/util:status",
    ],
)
```

## Interacting with the server

You can run the server enclave using `bazel`:

```bash
$ bazel run //asylo/examples/grpc_server:grpc_server_sgx_sim
```

The above command starts the server and keeps it running for five minutes. If
you want to set a different upper bound for the server lifetime, you can use the
`--server_max_lifetime` flag that is defined in the
[driver](#driving-the-enclave).

For example, to set a maximum server lifetime of ten seconds, run:

```bash
$ bazel run //asylo/examples/grpc_server:grpc_server_sgx_sim -- \
    --server_max_lifetime=10
```

In addition, if you want the server listen on a specific port, you can use the
`--port` flag that is defined in the [driver](#driving-the-enclave).

For example, to make the server listen on port 62831, run:

```bash
$ bazel run //asylo/examples/grpc_server:grpc_server_sgx_sim -- \
    --port=62831
```

For this example, use the
[gRPC command-line interface](https://github.com/grpc/grpc/blob/master/doc/command_line_tool.md)
to make RPCs to the translation server.

In a **different** terminal window, compile the gRPC command-line interface and
copy the binary to a temporary location:

```bash
$ bazel build @com_github_grpc_grpc//test/cpp/util:grpc_cli
$ cp "$(bazel info bazel-bin)/external/com_github_grpc_grpc/test/cpp/util/grpc_cli" \
    /tmp/grpc_cli
```

In your original terminal window, start the server with the `bazel run` command
[above](#interacting-with-the-server) passing a port of your choosing via the
`--port` flag. After the server starts running, it should print a message:

```
2019-10-11 12:18:46  INFO  grpc_server_enclave.cc : 136 : Server started on port 62831
```

**NOTE:** The log message printed by your enclave will only match the example
here if you passed `--port=62831`.

With the port number, you can use `grpc_cli` to make an RPC to the server:

```bash
$ /tmp/grpc_cli call localhost:62831 GetTranslation 'input_word: "asylo"'
connecting to localhost:62831
translated_word: "sanctuary"

Rpc succeeded with OK status
```

The server also has translations for some other Greek words:

```bash
$ /tmp/grpc_cli call localhost:62831 GetTranslation 'input_word: "istio"'
connecting to localhost:62831
translated_word: "sail"

Rpc succeeded with OK status
$ /tmp/grpc_cli call localhost:62831 GetTranslation 'input_word: "kubernetes"'
connecting to localhost:62831
translated_word: "helmsman"

Rpc succeeded with OK status
```

If you ask the server for a word that doesn't have a known translation, the
`grpc_cli` should display an error message:

```bash
$ /tmp/grpc_cli call localhost:62831 GetTranslation 'input_word: "orkut"'
connecting to localhost:62831
Rpc failed with status code 3, error message: No known translation for "orkut"
```

## Exercises

If you want to experiment more with gRPC inside enclaves, try some of the
exercises below:

*   **Periodically print RPC statistics from the server:** Make the translation
    service maintain some statistics about the RPCs it receives. Using the
    driver, periodically fetch a snapshot of these statistics from the enclave
    using `EnterAndRun` and print them out.
*   **Write a gRPC client in another enclave:** Write a gRPC client that makes
    RPCs to the translation server. Run this client inside another enclave.

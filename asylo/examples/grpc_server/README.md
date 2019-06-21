<!--jekyll-front-matter
---

title: gRPC Server Example

overview: Run a gRPC server inside an enclave.

location: /_docs/guides/grpc_server.md

order: 10

layout: docs

type: markdown

toc: true

---
{% include home.html %}
jekyll-front-matter-->

This guide describes how to run a gRPC server inside an enclave and interact
with it from a client running in an untrusted environment.

This guide assumes that you are familiar with:

*   The [Asylo quickstart guide](https://asylo.dev/docs/guides/quickstart.html)
*   The [gRPC C++ basics](https://grpc.io/docs/tutorials/basic/c.html) tutorial
*   [Protocol Buffers](https://developers.google.com/protocol-buffers/)
*   The C++ language

## Introduction

The Asylo enclave runtime features rich POSIX support that allows full-featured
[gRPC](https://grpc.io/) servers to run inside an enclave. Enclaves can then
serve as secure nodes in your distributed systems and cloud applications.

The source files for this example are located in the
[asylo/examples/grpc_server](https://github.com/google/asylo/tree/master/asylo/examples/grpc_server)
folder.

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
into English. The service also includes a shutdown RPC that triggers server
shutdown.

This example uses the following service definition from
[translator_server.proto](https://github.com/google/asylo/tree/master/asylo/examples/grpc_server/translator_server.proto):

```protobuf
// An empty message to serve as the input to the Shutdown RPC.
message ShutdownRequest {}

// An empty message to serve as the output from the Shutdown RPC.
message ShutdownResponse {}

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

  // Shuts down the Translator server.
  rpc Shutdown(ShutdownRequest) returns (ShutdownResponse) {}
}
```

This document doesn't include the server implementation because the details are
mostly irrelevant to this example. To learn about the server implementation, see
[translator_server.h](https://github.com/google/asylo/tree/master/asylo/examples/grpc_server/translator_server.h)
and
[translator_server.cc](https://github.com/google/asylo/tree/master/asylo/examples/grpc_server/translator_server.cc).

## Setting up a server enclave

This example features a step-by-step guide to writing a custom server enclave so
that you can see how gRPC works within Asylo. However, if you want to skip the
example and get a server up and running sooner, you can use the `EnclaveServer`
utility included in Asylo. `EnclaveServer` is a whole enclave that runs a single
gRPC service. You can find `EnclaveServer` in
[enclave_server.h](https://github.com/google/asylo/tree/master/asylo/grpc/util/enclave_server.h).

To set up the server, the enclave needs to know the desired server address and
the maximum time the server will wait before shutting down the server. This
information can be passed through the `Initialize` method, which accepts an
`EnclaveConfig`. This example extends the `EnclaveConfig` in a new file named
[grpc_server_config.proto](https://github.com/google/asylo/tree/master/asylo/examples/grpc_server/grpc_server_config.proto):

```protobuf
extend asylo.EnclaveConfig {
  // The address that the gRPC server inside the enclave will be hosted on.
  // Required.
  optional string server_address = 205739939;

  // The maximum amount of time in seconds before the server is shut down.
  // Required.
  optional int32 server_max_lifetime = 225604125;
}
```

This example maps the logic of setting up the gRPC server to the virtual methods
of `TrustedApplication` as follows:

*   The `Initialize` method builds and starts the gRPC server using the
    information from the `EnclaveConfig`.
*   The `Run` method waits for a shutdown RPC (or for the timeout to run out)
    and returns an `OK` status. All of our interaction with the enclave goes
    through gRPC, so `Run` doesn't need to do any other work.
*   The `Finalize` method shuts down the gRPC server.

**NOTE:** Enclaves do not have a secure source of time information.
Consequently, enclaves should not rely on timing for security. For instance, the
host can make the server in this example run forever or shut down prematurely by
providing the enclave with incorrect time information. However, neither of these
possibilities would compromise the security of the server in this example, so it
is fine to rely on a non-secure source of time here.

The enclave keeps track of the server, service object, shutdown timeout, and
whether a shutdown RPC has been received in member variables. This example
defines the server enclave in
[grpc_server_enclave.cc](https://github.com/google/asylo/tree/master/asylo/examples/grpc_server/grpc_server_enclave.cc):

```cpp
class GrpcServerEnclave final : public asylo::TrustedApplication {
 public:
  GrpcServerEnclave() : service_(&shutdown_requested_) {}

  asylo::Status Initialize(const asylo::EnclaveConfig &enclave_config)
      LOCKS_EXCLUDED(server_mutex_) override;

  asylo::Status Run(const asylo::EnclaveInput &enclave_input,
                    asylo::EnclaveOutput *enclave_output) override;

  asylo::Status Finalize(const asylo::EnclaveFinal &enclave_final)
      LOCKS_EXCLUDED(server_mutex_) override;

 private:
  absl::Mutex server_mutex_;

  std::unique_ptr<::grpc::Server> server_ GUARDED_BY(server_mutex_);

  TranslatorServer service_;

  absl::Notification shutdown_requested_;

  absl::Duration shutdown_timeout_;
};
```

#### Initializing the server

The `Initialize` method uses `grpc::ServerBuilder` to configure and start the
server. The server configuration includes the `server_address` extension from
the `EnclaveConfig` and the `service_` member described above. The logic of the
`Initialize` method ensures that the server is initialized and started only one
time.

If the `EnclaveConfig` does not have a `server_address` extension or a
`server_max_lifetime` extension, or if the server fails to start, then
`Initialize` returns a non-OK `Status`. Otherwise, `Initialize` logs the final
address and port, and returns an OK `Status`:

```cpp
asylo::Status GrpcServerEnclave::Initialize(
    const asylo::EnclaveConfig &enclave_config) LOCKS_EXCLUDED(server_mutex_) {
  if (!enclave_config.HasExtension(server_address)) {
    return asylo::Status(asylo::error::GoogleError::INVALID_ARGUMENT,
                         "Expected a server_address extension on config.");
  }

  if (!enclave_config.HasExtension(server_max_lifetime)) {
    return asylo::Status(asylo::error::GoogleError::INVALID_ARGUMENT,
                         "Expected a server_max_lifetime extension on config.");
  }

  shutdown_timeout_ =
      absl::Seconds(enclave_config.GetExtension(server_max_lifetime));

  absl::MutexLock lock(&server_mutex_);

  if (server_) {
    return asylo::Status(asylo::error::GoogleError::ALREADY_EXISTS,
                         "Server is already started");
  }

  ::grpc::ServerBuilder builder;

  int selected_port;
  builder.AddListeningPort(enclave_config.GetExtension(server_address),
                           ::grpc::InsecureServerCredentials(), &selected_port);

  builder.RegisterService(&service_);

  server_ = builder.BuildAndStart();
  if (!server_) {
    return asylo::Status(asylo::error::GoogleError::INTERNAL,
                         "Failed to start server");
  }

  LOG(INFO) << "Server started on port " << selected_port;

  return asylo::Status::OkStatus();
}
```

**NOTE:** This gRPC server uses `InsecureServerCredentials`. This means that the
server uses no additional security for channel establishment. The server and its
clients are not authenticated, and no channels are secured. **This configuration
is not suitable for a production environment**, but it is fine for this
demonstration.

#### Running the server

The `Run` method waits for the server's configured lifetime to expire or for a
shutdown RPC, whichever takes place first, and then returns an `OK` status:

```cpp
asylo::Status GrpcServerEnclave::Run(const asylo::EnclaveInput &enclave_input,
                                     asylo::EnclaveOutput *enclave_output) {
  shutdown_requested_.WaitForNotificationWithTimeout(shutdown_timeout_);

  return asylo::Status::OkStatus();
}
```

#### Finalizing the server

The `Finalize` method shuts down the server with a 500 millisecond timeout for
all outstanding RPCs. `Finalize` also informs the user that the server is
shutting down:

```cpp
asylo::Status GrpcServerEnclave::Finalize(
    const asylo::EnclaveFinal &enclave_final) LOCKS_EXCLUDED(server_mutex_) {
  absl::MutexLock lock(&server_mutex_);

  if (server_) {
    LOG(INFO) << "Server shutting down";

    server_->Shutdown(std::chrono::system_clock::now() +
                      std::chrono::milliseconds(500));
    server_.reset(nullptr);
  }

  return asylo::Status::OkStatus();
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
*   Enters the enclave to wait until either the shutdown RPC has been received
    or the timeout has expired
*   Finalizes the enclave cleanly

This example implements the driver in
[grpc_server_driver.cc](https://github.com/google/asylo/tree/master/asylo/examples/grpc_server/grpc_server_driver.cc).

#### Driver setting definitions

The driver defines three flags and a `constexpr` string to hold the information
it needs:

```cpp
DEFINE_string(enclave_path, "", "Path to enclave to load");

DEFINE_int32(server_max_lifetime, 300,
             "The longest amount of time (in seconds) that the server should "
             "be allowed to run");

DEFINE_int32(port, 0, "Port number that server listens to");

constexpr char kServerAddress[] = "[::1]";
```

The address `[::1]` indicates that the server should run locally. Default port
value 0 indicates that the port will be chosen by the operating system.

#### Parsing flags and creating configuration

The driver's `main` function starts by parsing command-line arguments:

```cpp
google::ParseCommandLineFlags(
    &argc, &argv, /*remove_flags=*/true);
```

Then, the driver creates and configures a `SimLoader` using the `enclave_path`
flag and an `EnclaveConfig` message object containing the server address:

```cpp
asylo::SimLoader loader(FLAGS_enclave_path, /*debug=*/true);

asylo::EnclaveConfig config;
config.SetExtension(examples::grpc_server::server_address, kServerAddress);
config.SetExtension(examples::grpc_server::server_max_lifetime,
                    FLAGS_server_max_lifetime);
config.SetExtension(examples::grpc_server::port, FLAGS_port);

```

#### Starting the enclave

The driver gets the `EnclaveManager` and loads the enclave with the config
object. The call to `LoadEnclave` triggers a call to the `Initialize` method of
the `TrustedApplication`:

```cpp
asylo::EnclaveManager::Configure(asylo::EnclaveManagerOptions());
auto manager_result = asylo::EnclaveManager::Instance();
LOG_IF(QFATAL, !manager_result.ok())
    << "Failed to retrieve EnclaveManager instance: "
    << manager_result.status();
asylo::EnclaveManager *manager = manager_result.ValueOrDie();

asylo::Status status = manager->LoadEnclave("grpc_example", loader, config);
LOG_IF(QFATAL, !status.ok())
    << "Load " << FLAGS_enclave_path << " failed: " << status;
```

#### Entering the enclave

The driver retrieves the `EnclaveClient` and enters the enclave with
`EnterAndRun`:

```cpp
asylo::EnclaveClient *client = manager->GetClient("grpc_example");
asylo::EnclaveInput input;
status = client->EnterAndRun(input, nullptr);
LOG_IF(QFATAL, !status.ok())
    << "Running " << FLAGS_enclave_path << " failed: " << status;
```

As covered in the
[Asylo quickstart](https://asylo.dev/docs/guides/quickstart.html#part-2-secure-execution),
the call to `EnterAndRun` invokes the enclave's `Run` method. This means that
`EnterAndRun` will not return until either the server's configured lifetime
expires or the server receives a shutdown RPC, whichever takes place first.

#### Finalizing the enclave

The driver then finalizes the enclave:

```cpp
asylo::EnclaveFinal final_input;
status = manager->DestroyEnclave(client, final_input);
LOG_IF(QFATAL, !status.ok())
    << "Destroy " << FLAGS_enclave_path << " failed: " << status;
```

## Building the application

To build the gRPC service with Bazel, the
[BUILD file](https://github.com/google/asylo/tree/master/asylo/examples/grpc_server/BUILD)
needs the following targets:

*   An `asylo_grpc_proto_library` target that contains the generated service
    code
*   A `cc_library` target that contains the implementation of the service

```python
asylo_grpc_proto_library(
    name = "translator_server_grpc_proto",
    srcs = ["translator_server.proto"],
)

cc_library(
    name = "translator_server",
    srcs = ["translator_server.cc"],
    hdrs = ["translator_server.h"],
    deps = [
        ":translator_server_grpc_proto",
        "@com_google_absl//absl/base:core_headers",
        "@com_google_absl//absl/container:flat_hash_map",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/synchronization",
        "@com_github_grpc_grpc//:grpc++",
    ],
)
```

The enclave requires the following additional targets:

*   An `asylo_proto_library` target that contains the extensions to the enclave
    proto definitions
*   A `sim_enclave` target that contains the actual enclave. This enclave is
    configured with `grpc_enclave_config`, which expands the heap size and
    maximum number of threads to accommodate gRPC's resource requirements.

```python
asylo_proto_library(
    name = "grpc_server_config_proto",
    srcs = ["grpc_server_config.proto"],
    deps = ["//asylo:enclave_proto"],
)

cc_proto_library(
    name = "grpc_server_config_cc_proto",
    deps = [":grpc_server_config_proto"],
)

sim_enclave(
    name = "grpc_server_enclave.so",
    srcs = ["grpc_server_enclave.cc"],
    config = "//asylo/grpc/util:grpc_enclave_config",
    deps = [
        ":grpc_server_config_cc_proto",
        ":translator_server",
        "@com_google_absl//absl/base:core_headers",
        "@com_google_absl//absl/memory",
        "@com_google_absl//absl/synchronization",
        "@com_google_absl//absl/time",
        "//asylo:enclave_runtime",
        "//asylo/util:status",
        "@com_github_grpc_grpc//:grpc++",
        "@com_github_grpc_grpc//:grpc++_reflection",
    ],
)
```

Finally, the BUILD file needs an `enclave_loader` target for the driver:

```python
enclave_loader(
    name = "grpc_server",
    srcs = ["grpc_server_driver.cc"],
    enclaves = {"enclave": ":grpc_server_enclave.so"},
    loader_args = ["--enclave_path='{enclave}'"],
    deps = [
        ":grpc_server_config_cc_proto",
        "//asylo:enclave_client",
        "@com_github_gflags_gflags//:gflags_nothreads",
        "//asylo/util:logging",
    ],
)
```

## Interacting with the server

You can run the server enclave using `bazel`:

```bash
$ bazel run --config=enc-sim \
    //asylo/examples/grpc_server:grpc_server
```

The above command starts the server and keeps it running for five minutes or
until it receives a shutdown RPC. If you want to set a different upper bound for
the server lifetime, you can use the `--server_max_lifetime` flag that is
defined in the [driver](#driving-the-enclave). The `--server_max_lifetime` flag
specifies the number of seconds to wait for a shutdown RPC.

For example, to set a maximum server lifetime of ten seconds, run:

```bash
$ bazel run --config=enc-sim \
    //asylo/examples/grpc_server:grpc_server -- \
    --server_max_lifetime=10
```

In addition, if you want the server listen on a specific port, you can use the
`--port` flag that is defined in the [driver](#driving-the-enclave).

For example, to make server listen on port 8558, run:

```bash
$ bazel run --config=enc-sim \
    //asylo/examples/grpc_server:grpc_server -- \
    --port=8558
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
[above](#interacting-with-the-server). After the server starts running, it
should print a message that displays what port it's running on:

```
2019-10-11 12:18:46  INFO  grpc_server_enclave.cc : 136 : Server started on port 62831
```

**NOTE:** Each time the enclave is started, it auto-selects a new port for the
server. Your server will probably be running on a different port than 62831.

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

When you are done making RPCs to the server, you can send it a shutdown RPC:

```bash
$ /tmp/grpc_cli call localhost:62831 Shutdown ""
connecting to localhost:62831

Rpc succeeded with OK status
```

The server should display a message that it's shutting down:

```
2019-10-11 12:23:46  INFO  grpc_server_enclave.cc : 152 : Server shutting down
```

Alternatively, if you don't send a shutdown RPC to the server, it will shut down
by itself after the number seconds given at startup (300 by default).

## Exercises

If you want to experiment more with gRPC inside enclaves, try some of the
exercises below:

*   **Periodically print RPC statistics from the server:** Make the translation
    service maintain some statistics about the RPCs it receives. Using the
    driver, periodically fetch a snapshot of these statistics from the enclave
    using `EnterAndRun` and print them out.
*   **Write a gRPC client in another enclave:** Write a gRPC client that makes
    RPCs to the translation server. Run this client inside another enclave.

<!--jekyll-front-matter
---

title: Quickstart Guide

overview: Install Asylo, build, and run your first enclave!

location: /_docs/guides/quickstart.md

order: 10

layout: docs

type: markdown

toc: true

---
{% include home.html %}
jekyll-front-matter-->

This guide demonstrates using Asylo to protect secret data from an attacker with
root privileges.

## Introduction

### What is an enclave?

On traditional systems, the Operating System (OS) kernel has unrestricted access
to a machine's hardware resources. The kernel typically exposes most of its
access permissions to a root user without any restrictions. Additionally, a root
user can extend or modify the kernel on a running system. As a result, if an
attacker can execute code with root privileges, they can compromise every secret
and bypass every security policy on the machine. For instance, if an attacker
obtains root access on a machine that manages TLS keys, those keys may be
compromised.

Enclaves are an emerging technology paradigm that changes this equation. An
enclave is a special execution context where code can run protected from even
the OS kernel, with the guarantee that even a user running with root privileges
cannot extract the enclave's secrets or compromise its integrity. Such
protections are enabled through hardware isolation technologies such as
[Intel SGX](https://software.intel.com/en-us/sgx) or
[ARM TrustZone](https://www.arm.com/products/security-on-arm/trustzone), or even
through additional software layers such as a hypervisor. These technologies
enable new forms of isolation beyond the usual kernel/user-space separation.

New security features are exciting for developers building secure applications,
but in practice there is a big gap between having a raw capability and
developing applications that leverage that capability. Building useful enclave
applications requires tools to construct, load, and operate enclaves. Doing
useful work in an enclave requires programming-language support and access to
core platform libraries.

### What is Asylo?

Asylo is an open source framework for developing enclave applications. It
defines an abstract enclave model that can be mapped transparently onto a
variety of enclave technologies (a.k.a., _enclave backends_). Asylo provides a
software-development platform that supports a growing range of use cases. In a
sense, the enclave backend can be viewed as a special-purpose embedded computer
running inside a conventional machine, with Asylo providing the necessary
runtime for that embedded computer.

Below, we walk through building a simple example enclave. The example
demonstrates initializing an enclave, passing arguments to code running inside
the enclave, encrypting those arguments inside the enclave, and returning the
processed results. Even though this is a very simple example, it demonstrates
the basic functionality provided by Asylo and the steps required to utilize that
functionality.

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
[building and running](#building-and-running-an-enclave-application) the enclave
application in this example.

The example source code can be found in the
[Asylo SDK](https://github.com/google/asylo/tree/master/asylo/examples) on
GitHub.

## Overall approach

In Asylo, an enclave runs in the context of a user-space application. However,
for security and portability reasons, Asylo does not support direct interactions
between the enclave code and the OS. Instead, all enclave-to-OS interactions
must be mediated through code that runs outside the enclave. We refer to the
code running outside the enclave as the _untrusted application_ and the code
running inside the enclave as the _trusted application_, or simply the
_enclave_.

Here, we focus on a model where a majority of the user-developed logic lives
inside the enclave. In this model, users may have to write some boiler-plate
(similar to what is presented later in this guide), but most of the code needed
for creating, launching, and interacting with enclaves is provided by the Asylo
framework.

Asylo takes an object-oriented approach to enclave application development.
Conceptually, an enclave is a collection of private data and private logic,
along with public methods to access it. To this end, Asylo models an enclave
using `TrustedApplication`, an abstract class that defines various enclave
entry-points. To implement an enclave application, a developer creates a
subclass of `TrustedApplication` and implements the appropriate methods.

Throughout this guide, we use both _trusted application_ and _enclave_ to refer
to an instance of `TrustedApplication`.

## Enclave interaction model

In Asylo, enclaves operate on
[protocol-buffer messages](https://developers.google.com/protocol-buffers/docs/reference/cpp/google.protobuf.message#Message);
all enclave inputs and outputs are protocol buffers.

We refer to the process of switching from an untrusted application to an enclave
as _entering the enclave_ and the process of switching from an enclave to an
untrusted application as _exiting an enclave_.

In Asylo, all enclave interactions are handled through an abstract class called
`EnclaveClient`. The Asylo framework provides concrete implementations of this
class for each supported enclave technology. The `EnclaveClient` class defines
several methods for entering an enclave. Enclave exits, on the other hand, are
implicit—they either happen automatically when an enclave entry finishes its
work, or they happen when an enclave requests services from the operating
system.

Of the various enclave-entry methods defined by the `EnclaveClient` interface,
three are of particular interest to Asylo users:

*   `EnterAndInitialize`: This method takes an `EnclaveConfig` message
    containing basic enclave configuration settings and passes it to the
    enclave. This is a private method, and is implicitly invoked by the Asylo
    framework when an enclave binary image is loaded.
*   [`EnterAndRun`](https://asylo.dev/doxygen/classasylo_1_1EnclaveClient.html#enter-and-run):
    This method takes an `EnclaveInput` message, passes it to the enclave, which
    can populate the `EnclaveOutput` result. The `EnclaveInput` and
    `EnclaveOutput` messages can be extended with
    [protobuf extensions](https://developers.google.com/protocol-buffers/docs/proto#extensions)
    by the developer to meet the data-processing requirements of the
    application. This method is a public method, and may be called an arbitrary
    number of times with different inputs after the enclave is initialized.
*   `EnterAndFinalize`: This method takes an `EnclaveFinal` message, which may
    contain any information needed by the enclave for finalization, and passes
    that message to the enclave just before it is destroyed. This method is also
    a private method of the `EnclaveClient` class, and is implicitly invoked by
    the Asylo framework on enclave tear-down.

Each `EnclaveClient` is associated with exactly one enclave, and the Asylo
framework forwards calls to the above `EnclaveClient` methods to appropriate
enclave methods on the corresponding `TrustedApplication` instance, which can be
overridden by the enclave developer.

The `TrustedApplication` interface declares methods corresponding to the three
entry methods defined by the `EnclaveClient` abstract class:

*   [`Initialize`](https://asylo.dev/doxygen/classasylo_1_1TrustedApplication.html#initialize):
    This method takes an `EnclaveConfig` message from
    `EnclaveClient::EnterAndInitialize`, and initializes the enclave with the
    configuration settings in the `EnclaveConfig`.
*   [`Run`](https://asylo.dev/doxygen/classasylo_1_1TrustedApplication.html#run):
    This method takes an `EnclaveInput` message from
    `EnclaveClient::EnterAndRun`, populates an `EnclaveOutput` message, and
    performs trusted execution.
*   [`Finalize`](https://asylo.dev/doxygen/classasylo_1_1TrustedApplication.html#finalize):
    This method takes an `EnclaveFinal` message from
    `EnclaveClient::EnterAndFinalize`, and prepares the enclave for destruction.

## Enclave lifecycle

Entering an enclave is analogous to making a system call. The enclave entry
point represents a gateway to protected code with access to the enclave's
resources. Arguments are copied into the enclave's protected memory on entry and
results are copied out on exit.

```cpp
ABSL_FLAG(std::string, enclave_path, "",
          "Path to enclave binary image to load");
ABSL_FLAG(std::string, message, "", "Message to encrypt");

int main(int argc, char *argv[]) {
  absl::ParseCommandLine(argc, argv);

  constexpr char kEnclaveName[] = "demo_enclave";

  const std::string message = absl::GetFlag(FLAGS_message);
  LOG_IF(QFATAL, message.empty()) << "Empty --message flag.";

  const std::string enclave_path = absl::GetFlag(FLAGS_enclave_path);
  LOG_IF(QFATAL, enclave_path.empty()) << "Empty --enclave_path flag.";

  // Part 1: Initialization

  // Prepare |EnclaveManager| with default |EnclaveManagerOptions|
  asylo::EnclaveManager::Configure(asylo::EnclaveManagerOptions());
  auto manager_result = asylo::EnclaveManager::Instance();
  LOG_IF(QFATAL, !manager_result.ok()) << "Could not obtain EnclaveManager";

  // Prepare |load_config| message.
  asylo::EnclaveLoadConfig load_config;
  load_config.set_name(kEnclaveName);

  // Prepare |sgx_config| message.
  auto sgx_config = load_config.MutableExtension(asylo::sgx_load_config);
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
  status = manager->DestroyEnclave(client, empty_final_input);
  LOG_IF(QFATAL, !status.ok()) << "DestroyEnclave failed with: " << status;

  return 0;
}
```

The three enclave entry points are shown in the above code. Let's go through
each part of the code.

### Part 1: Initialization

The untrusted application performs the following steps to initialize the trusted
application:

1.  Configures an instance of `EnclaveManager` with default options. The
    `EnclaveManager` handles all enclave resources in an untrusted application.
2.  Configures a `EnclaveLoadConfig` object to specify options for the
    SgxLoadConfig to fetch the enclave binary image from disk.
3.  Calls `EnclaveManager::LoadEnclave` to bind the enclave to the name `"demo
    enclave"`. This call implicitly invokes the enclave's `Initialize` method.

### Part 2: Secure execution

The untrusted application performs the following steps to securely execute a
workload in the trusted application:

1.  Provides arbitrary input data in an `EnclaveInput`. This example uses a
    single string protobuf extension to the `EnclaveInput` message. This
    extension field is used to pass data to the enclave for encryption.
2.  Gets a handle to the enclave via `EnclaveManager::GetClient`.
3.  Invokes the enclave by calling `EnclaveClient::EnterAndRun`. This method is
    the primary entry point used to dispatch messages to the enclave. It can be
    called an arbitrary number of times.
4.  Receives the result from the enclave in an `EnclaveOutput`. Developers can
    add protobuf extensions to the `EnclaveOutput` message to provide arbitrary
    output values from their enclave.

### Part 3: Finalization

The untrusted application performs the following steps to finalize the trusted
application:

1.  Provides arbitrary finalization data to the enclave and destroys the enclave
    via `EnclaveManager::DestroyEnclave`.
2.  Runs the enclave's `Finalize` method. The Asylo framework performs this step
    implicitly during enclave destruction.

## Writing an enclave application

We just saw how to initialize, run, and finalize an enclave using the Asylo
framework. These calls happened on the untrusted side of the enclave boundary.
Now, let us take a look at the code on the trusted side.

```cpp
constexpr size_t kMaxMessageSize = 1 << 16;

// Dummy 128-bit AES key.
constexpr uint8_t kAesKey128[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
                                  0x06, 0x07, 0x08, 0x09, 0x10, 0x11,
                                  0x12, 0x13, 0x14, 0x15};

// Encrypts a message against `kAesKey128` and returns a 12-byte nonce followed
// by authenticated ciphertext, encoded as a hex string.
const StatusOr<std::string> EncryptMessage(const std::string &message) {
  std::unique_ptr<AeadCryptor> cryptor;
  ASYLO_ASSIGN_OR_RETURN(cryptor,
                         AeadCryptor::CreateAesGcmSivCryptor(kAesKey128));

  std::vector<uint8_t> additional_authenticated_data;
  std::vector<uint8_t> nonce(cryptor->NonceSize());
  std::vector<uint8_t> ciphertext(message.size() + cryptor->MaxSealOverhead());
  size_t ciphertext_size;

  ASYLO_RETURN_IF_ERROR(cryptor->Seal(
      message, additional_authenticated_data, absl::MakeSpan(nonce),
      absl::MakeSpan(ciphertext), &ciphertext_size));

  return absl::StrCat(BytesToHexString(nonce), BytesToHexString(ciphertext));
}

class EnclaveDemo : public TrustedApplication {
 public:
  EnclaveDemo() = default;

  Status Run(const EnclaveInput &input, EnclaveOutput *output) {
    std::string user_message = GetEnclaveUserMessage(input);
    std::string result;
    ASYLO_ASSIGN_OR_RETURN(result, EncryptMessage(user_message));
    std::cout << "Encrypted message:" << std::endl << result << std::endl;
    return absl::OkStatus();
  }

  const std::string GetEnclaveUserMessage(const EnclaveInput &input) {
    return input.GetExtension(guide::asylo::enclave_input_demo).value();
  }
};
```

The above snippet defines a class `EnclaveDemo`, which derives from
`TrustedApplication`, and implements the enclave's secure execution logic in its
`Run` method. This method encrypts the input message and prints the resulting
ciphertext.

The `TrustedApplication` base class provides default implementations for the
`Initialize`, `Run`, and `Finalize` methods. The enclave author is expected to
override these methods as needed to implement their enclave's logic. As
demonstrated in this example, an enclave author typically would override the
`TrustedApplication::Run` method to provide the core logic for their enclave,
and use that method to interact with their enclave. Alternatively, the enclave
author may launch an RPC server (e.g., a gRPC server) in the
`TrustedApplication::Initialize` method, and then interact with their enclave
via RPCs. In this case, the developer may choose not to override the
`TrustedApplication::Run` method. The Asylo framework is flexible, and allows
developers to use enclaves in a way that is most suitable to their needs.

## Building and running an enclave application

To build our enclave application, we define several targets that utilize a
simulated backend. See the
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

debug_sign_enclave(
    name = "demo_enclave.so",
    unsigned = "demo_enclave_unsigned.so",
)

enclave_loader(
    name = "quickstart",
    srcs = ["demo_driver.cc"],
    enclaves = {"enclave": ":demo_enclave.so"},
    loader_args = ["--enclave_path='{enclave}'"],
    deps = [
        ":demo_cc_proto",
        "@com_google_absl//absl/flags:flag",
        "@com_google_absl//absl/flags:parse",
        "//asylo:enclave_client",
        "//asylo/util:logging",
    ],
)
```

The [Bazel](https://bazel.build) BUILD file shown above defines our enclave's
logic in a `cc_unsigned_enclave` called `demo_enclave_unsigned.so`. This target
contains our implementation of `TrustedApplication` and is linked against the
Asylo runtime. We use a `debug_sign_enclave` rule to generate an enclave that
has been signed with a debug key, and can be run in supported backends (e.g.,
SGX simulation mode or on SGX hardware in debug mode).

The untrusted component is the target `:quickstart`, which contains code to
handle the logic of initializing, running, and finalizing the enclave, as well
as sending and receiving messages through the enclave boundary. In a non-enclave
application, we would write `:quickstart` as a *cc_binary* target, but the
`enclave_loader` rule streamlines the combination of driver and enclave targets.
Specifically, it ensures that *demo_driver.cc* is compiled with the host
crosstool, `:demo_enclave` is compiled with the enclave-backend-specific
crosstool, and that the untrusted enclave loader is invoked with a flag that
specifies the enclave's path.

Let us now run the demo enclave inside the Docker image we downloaded
[above](#getting-started-with-the-example-code). You can set the `--message`
flag passed to the `//quickstart:quickstart_sgx_sim` target to contain any
string that you would like to encrypt.

Note: The following command runs the enclave in simulation mode.

```bash
docker run -it --rm \
    -v bazel-cache:/root/.cache/bazel \
    -v "${MY_PROJECT}":/opt/my-project \
    -w /opt/my-project \
    gcr.io/asylo-framework/asylo \
    bazel run //quickstart:quickstart_sgx_sim -- --message="Asylo Rocks"
Encrypted message:
2dc402068266ba995608e0d4a16c1604b792355d4635dec43cf2888cf2036d2007772ed5f24e5c
```

Congratulations on building and running your first enclave application!

## Further exercises

Now you know enough about Asylo to begin modifying an enclave application. Here
are some things to try:

*   Note that our current example does not make use of the `output` variable
    passed to `EnterAndRun`. Use `SetEnclaveOutputMessage` in `demo_enclave.cc`,
    and `GetEnclaveOutputMessage` in `demo_driver.cc`, to return the encrypted
    message from the enclave to the driver, and print it there. The application
    output should remain unchanged.
*   The `EnterAndRun` function can be called multiple times once the enclave is
    initialized. Modify `demo_driver.cc` to add another call to `EnterAndRun`,
    in order to re-enter enclave with a different message to encrypt.
*   Use
    [protobuf extensions](https://developers.google.com/protocol-buffers/docs/proto#extensions)
    in the `EnclaveInput` message to support sending ciphertext into the enclave
    for decryption, using the provided `DecryptMessage` function.

A sample
[solution](https://github.com/google/asylo/tree/master/asylo/examples/quickstart/solution)
is available on GitHub.

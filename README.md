# Asylo ([asylo.dev](https://asylo.dev)) [![Build status](https://badge.buildkite.com/34525fbee9a2289bba7f3ac74df984c8916e5e1725f45941fa.svg)](https://buildkite.com/asylo/asylo-docker-test-for-master-branch)

Asylo is an open and flexible framework for developing enclave applications.
Asylo lets you take advantage of a range of emerging trusted execution
environments (TEEs), including both software and hardware isolation
technologies.

Asylo provides:

+   The ability to execute trusted workloads in an untrusted environment,
    inheriting the confidentiality and integrity guarantees from the security
    backend, i.e., the underlying enclave technology.
+   Ready-to-use containers, an open source API, libraries, and tools so you can
    develop and run applications that use one or more enclaves.
+   A choice of security backends.
+   Portability of your application's source code across security backends.

Asylo is under active development. We want to expand Asylo's capabilities to
meet more developers' needs. To do this, we plan to add support for more
backends, libraries, and languages.

## Documentation

The Asylo project documentation can be found at
[asylo.dev](https://asylo.dev/docs).

The [`asylo-examples`](https://github.com/google/asylo-examples) repository
contains a working Bazel workspace with example source code that can be used as
a template for starting a new project.

## Support

There are several ways of getting support with Asylo:

+   Join the [asylo-users](https://groups.google.com/forum/#!forum/asylo-users)
    mailing list to participate in discussions and get help troubleshooting
    problems.
+   Ask questions and find curated answers on
    [Stack Overflow](https://stackoverflow.com) using the
    [`asylo`](https://stackoverflow.com/questions/tagged/asylo) tag.

## Build Environment in Docker (recommended)

Asylo provides a custom Docker image that contains all required dependencies, as
well as Asylo's custom toolchain, which is required for compiling enclave
applications for various enclave backends.

```bash
docker run -it --rm gcr.io/asylo-framework/asylo
```

See the [Dockerfile](/asylo/distrib/toolchain/Dockerfile) for an in-depth view
of what's inside the container image.

See this
[guide](https://cloud.google.com/container-registry/docs/pushing-and-pulling#pulling_images_from_the_registry)
for additional details on how to pull images from Google's Container Registry.

Some of Asylo's tests require IPv6 to be enabled in your Docker daemon. See this
[guide](https://docs.docker.com/config/daemon/ipv6/) for how to enable IPv6.

### Examples

#### Running the `hello_world` example

To run the `hello_world` example, first use the following set of commands to
grab the
[`asylo-examples` repository source code](https://github.com/google/asylo-examples):

```bash
MY_PROJECT=~/asylo-examples
git clone https://github.com/google/asylo-examples.git "${MY_PROJECT}"
```

Next, use Docker to build and run the `hello_world` application, using a
simulated enclave backend:

```bash
NAMES="${USER}"
docker run -it --rm \
    -v bazel-cache:/root/.cache/bazel \
    -v "${MY_PROJECT}":/opt/my-project \
    -w /opt/my-project \
    gcr.io/asylo-framework/asylo \
    bazel run //hello_world:hello_world_sgx_sim -- --names="${NAMES}"
```

You can also set `NAMES` to a comma-separated list of names and see the
enclave's entry-point get invoked for each name.

##### Docker flags

In the above example, we use the following Docker flags:

+   `-it` is used to allocate an interactive terminal in which the command is
    run.
+   `--rm` is used to automatically delete the temporary container after the
    command completes so that unnecessary images don't persist on disk.
+   `-v` is used to map local files to paths inside the container.
    -   The example project files are mapped to `/opt/my-project`.
    -   The local Bazel cache is mapped to `/root/.cache/bazel`, enabling
        incremental builds between `bazel` invocations.
+   `-w` is used to set the working directory in the container so that `bazel
    run` command is executed in the example project.

If using the Intel SGX hardware backend (see the
[Manual Installation guide](/INSTALL.md#intel-sgx-hardware-backend-support)),
the following Docker flags are needed to propagate the necessary capabilities
from the host:

+   `--device=/dev/isgx` gives the container access to the SGX device that is
    used to interact with the SGX hardware features.
+   `-v /var/run/aesmd/aesm.socket:/var/run/aesmd/aesm.socket` allows the
    container to access the Architectural Enclave Service Manager (AESM) daemon
    running on the host.

##### Bazel flags and workspace settings

In the above example, we use the following Bazel flag:

+   `--names="${NAMES}"` is the argument passed to the
    `//hello_world:hello_world_sgx_sim` target.

Note: The example source code includes an additional Bazel configuration file,
`.bazelrc`, at the root of the source tree. Remember to copy the contents of
this file into the `.bazelrc` file at the root of any future Bazel workspaces
that use Asylo's toolchain.

#### Running your own enclave application

You can follow the [steps above](#running-the-hello_world-example) to build your
own enclave application instead. You can use the example code in `MY_PROJECT` as
a template for a new project, or simply change `MY_PROJECT` to point to your own
Bazel project instead.

#### Running an interactive terminal

You can get an interactive terminal (instead of running a single command) by
omitting the `bazel run ...` part of the `docker` invocation. For instance, to
run the `hello_world` example as above but in an interactive terminal, run:

```bash
docker run -it --rm \
    -v bazel-cache:/root/.cache/bazel \
    -v "${MY_PROJECT}":/opt/my-project \
    -w /opt/my-project \
    gcr.io/asylo-framework/asylo
```

This opens a terminal inside the Docker container. From this terminal, you can
run Bazel as usual:

```bash
bazel run //hello_world:hello_world_sgx_sim -- --names="${NAMES}"
```

#### Running the regression tests

To run our regression test suite, first clone the Asylo repository to a
directory of your choice:

```bash
ASYLO_SDK=~/asylo-sdk
git clone https://github.com/google/asylo.git "${ASYLO_SDK}"
```

The regression test suite includes tests that unit-test code directly as well as
tests that run inside a simulated enclave environment. You can run it with the
following command:

```bash
docker run -it --rm \
    -v "${ASYLO_SDK}:/opt/asylo/sdk" \
    -v bazel-cache:/root/.cache/bazel \
    -w "/opt/asylo/sdk" \
    gcr.io/asylo-framework/asylo \
    asylo/test/run_enclave_tests.sh
```

See [Docker flags](#docker-flags) for a breakdown of the flags used in this
command. Note that in this command we also use `-v` to map the Asylo SDK source
files to `/opt/asylo/sdk`.

## Manual Installation

If you don't want to use the Asylo Docker image, you can manually install Asylo
and its dependencies instead. See [INSTALL.md](/INSTALL.md) for detailed
installation steps.

### Examples

The following examples assume that the Asylo SDK was installed at `ASYLO_SDK`,
which can be a directory of your choice.

#### Running the `hello_world` example

To run the `hello_world` example, first use the following set of commands to
grab the
[`asylo-examples` repository source code](https://github.com/google/asylo-examples):

```bash
MY_PROJECT=~/asylo-examples
git clone https://github.com/google/asylo-examples.git "${MY_PROJECT}"
```

Next, use Bazel to build and run the `hello_world` application, which uses a
simulated SGX enclave backend:

```bash
cd "${MY_PROJECT}"
NAMES="${USER}"
bazel run //hello_world:hello_world_sgx_sim -- --names="${NAMES}"
```

Refer to
[Bazel flags and workspace settings](#bazel-flags-and-workspace-settings) for an
explanation of the flags and workspace configuration used in this example.

#### Running your own enclave application

You can follow the [steps above](#running-the-hello_world-example-1) to build
your own enclave application instead. You can use the examples code in
`MY_PROJECT` as the start of your own project, or simply change `MY_PROJECT` to
point to your own Bazel project instead.

#### Running the regression test suite

If you haven't already, use the following commands to clone the Asylo source
code repository and copy it to a directory of your choice:

```bash
ASYLO_SDK=~/asylo-sdk
git clone https://github.com/google/asylo.git "${ASYLO_SDK}"
```

The regression test suite includes tests that unit-test code directly as well as
tests that run inside a simulated enclave environment. You can run it with the
following command:

```bash
"${ASYLO_SDK}"/asylo/test/run_enclave_tests.sh
```

## Repository Structure & Status

This repository contains source code for the Asylo framework. The framework
supports C++17 applications (from release 0.4) and a Bazel build environment.

The following packages contain source code that may be of particular interest to
users of the Asylo framework as well as those looking to contribute to Asylo
development.

+   [asylo/](/asylo)
    +   [bazel/](/asylo/bazel)
        -   Libraries for Asylo development in the Bazel build system.
    +   [crypto/](/asylo/crypto)
        -   Crypto utilities and wrappers around BoringSSL.
    +   [distrib/](/asylo/distrib)
        -   Asylo toolchain and dependencies.
    +   [examples/](/asylo/examples)
        -   Sample applications written with the Asylo framework.
    +   [grpc/](/asylo/grpc)
        +   [auth/](/asylo/grpc/auth)
            -   gRPC authentication support.
        +   [util/](/asylo/grpc/util)
            -   Utilities for using gRPC from a trusted application.
    +   [identity/](/asylo/identity)
        -   Identity and attestation support.
    +   [platform/](/asylo/platform)
        -   Implementation of enclave platforms and backends.
    +   [test/](/asylo/test)
        -   Testing utilities provided to application writers.
    +   [util/](/asylo/util)
        -   Common utilities provided for use both inside and outside an enclave
            environment.

## License

Asylo is released under the [Apache 2.0 license](/LICENSE).

```
Copyright 2018 Asylo authors

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```

## Disclaimers

This is not an officially supported Google product.

Asylo's support for various enclave backend technologies does not constitute an
endorsement of those technologies or the security properties therein. Users of
Asylo should perform due diligence in evaluating whether a backend technology
meets the security requirements of their application. Users are advised to use
defense-in-depth measures to protect their sensitive applications.

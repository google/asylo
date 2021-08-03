<!--jekyll-front-matter
---

title: Running SQLite with Asylo

overview: Wrap an entire application in an enclave.

location: /_docs/guides/sqlite.md

order: 35

layout: docs

type: markdown

toc: true

---
{% include home.html %}
jekyll-front-matter-->

## Overview

### Why running in an enclave?

Enclaves are an emerging technology paradigm that protects the user application
from the operating systems. Running a user application inside an enclave
provides security protection for user data against attacks from the OS kernel or
even a user running with root privileges.

### Asylo support to run SQLite

Asylo is an open source framework for developing enclave applications. Asylo
provides support for full-featured applications, such as SQLite 3.30.1, to run
inside an enclave. We also provide an application-wrapper to make it easy to run
an application in an enclave without any source code changes, along with a BUILD
file that allows external sources to be built with Bazel.

## Build SQLite 3.30.1 with Asylo

### Setting up the environment in Docker

Asylo provides a custom Docker image that contains all required dependencies, as
well as Asylo's custom toolchain, which is a convenient tool for compiling
enclave applications without manually installing the toolchain. To get started,
please follow
[the Docker instructions in the Asylo repository README.md](https://github.com/google/asylo/blob/master/README.md)
to setup the environment for Docker.

### Set up a workspace

#### Import Asylo and SQLite

In any directory that you would like to define your project workspace, import
Asylo and SQLite by creating a `WORKSPACE` file and add the following lines to
it:

```
workspace(name = "asylo_sqlite_example")

load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")

# Asylo
http_archive(
    name = "com_google_asylo",
    urls = ["https://github.com/google/asylo/archive/v0.6.0.tar.gz"],
    sha256 = "bb6e9599f3e174321d96616ac8069fac76ce9d2de3bd0e4e31e1720c562e83f7",
    strip_prefix = "asylo-0.6.0",
)

# SQLite
http_archive(
    name = "org_sqlite",
    build_file = "@com_google_asylo//asylo/distrib:sqlite.BUILD",
    urls = ["https://www.sqlite.org/2019/sqlite-autoconf-3300100.tar.gz"],
    sha256 = "8c5a50db089bd2a1b08dbc5b00d2027602ca7ff238ba7658fabca454d4298e60",
    strip_prefix = "sqlite-autoconf-3300100",
)

load("@com_google_asylo//asylo/bazel:asylo_deps.bzl", "asylo_deps")
asylo_deps()

load("@com_google_asylo//asylo/bazel:sgx_deps.bzl", "sgx_deps")
sgx_deps()

# The grpc dependency is defined by asylo_deps, and load must be top-level,
# so this has to come after asylo_deps().
load("@com_github_grpc_grpc//bazel:grpc_deps.bzl", "grpc_deps")

grpc_deps()

# Projects using gRPC as an external dependency must call both grpc_deps() and
# grpc_extra_deps().
load("@com_github_grpc_grpc//bazel:grpc_extra_deps.bzl", "grpc_extra_deps")

grpc_extra_deps()
```

This bazel rule imports Asylo and SQLite. To build SQLite with Bazel, Asylo
provides the BUILD file for SQLite 3.30.1, located at
`@com_google_asylo/asylo/distrib/sqlite.BUILD`.

#### Add .bazelrc

Next, in the same workspace, create a `.bazelrc` file by copying from
[the one in Asylo Repository](https://github.com/google/asylo/blob/master/.bazelrc)

This file specifies the toolchain and configurations used to build Asylo
targets.

#### Build target for SQLite 3.30.1 with application wrapper

Asylo provides an application wrapper which makes it easy to run external user
applications in Asylo. To make use of it, create a BUILD file in your workspace,
and add the following lines to it.

```build
licenses(["notice"])

load("@com_google_asylo//asylo/bazel:asylo.bzl", "cc_enclave_binary")

cc_enclave_binary(
    name = "asylo_sqlite",
    deps = ["@org_sqlite//:sqlite3_shell"],
)
```

The `cc_enclave_binary` is the build rule that uses the application wrapper. By
claiming SQLite as a dependency (`sqlite3_shell` is defined by our `BUILD.bazel`
file), it will wrap SQLite and run it in Asylo.

## Run SQLite in SGX Simulation Mode

Now we are ready to build and run SQLite. First, we load a Docker container that
imports the current workspace by running the following Docker command from the
root of your project:

```
docker run -it --rm \
    -v ${PWD}:/opt/my-project \
    --tmpfs /root/.cache/bazel:exec \
    -w /opt/my-project \
    gcr.io/asylo-framework/asylo:buildenv-v0.6.0
```

Here `-v` maps the current workspace to the directory in Docker, and `-w` sets
the workspace in Docker.

As the SQLite build target is created, now it can be run with the following
`bazel` command from the Docker container:

```shell
bazel run :asylo_sqlite_sgx_sim
```

Specifying the `_sgx_sim` target suffix runs SQLite in SGX simulation mode.

After finishing building, you should be able to see SQLite up and messages
similar as following:

```shell
SQLite version 3.30.1 2019-10-10 20:19:45
Enter ".help" for usage hints.
Connected to a transient in-memory database.
Use ".open FILENAME" to reopen on a persistent database.
sqlite>
```

Now we can run SQLite inside an enclave with some simple examples, such as:

```shell
sqlite> create table mytable(one varchar(10), two smallint);
sqlite> insert into mytable values('Asylo', 060);
sqlite> insert into mytable values('SQLite', 33001);
sqlite> select * from mytable;
Asylo|60
SQLite|33001
```

## Run SQLite in SGX Hardware Mode

The following steps show how to run enclavized SQLite on SGX hardware.

NOTE: The following steps only work on real SGX hardware.

Similar as SGX simulation case, run the following docker command from the root
of your project:

```
docker run -it --rm \
    --device=/dev/isgx \
    -v ${PWD}:/opt/my-project \
    -v /var/run/aesmd/aesm.socket:/var/run/aesmd/aesm.socket \
    --tmpfs /root/.cache/bazel:exec \
    -w /opt/my-project \
    gcr.io/asylo-framework/asylo:buildenv-v0.6.0
```

The SGX capabilities are propagated by the docker flags `--device=/dev/isgx` and
`-v /var/run/aesmd/aesm.socket:/var/run/aesmd/aesm.socket`. More details can be
found on the
[Asylo website](https://asylo.dev/docs/guides/sgx_release_enclaves.html).

Now we can run with the following `bazel` command from the Docker container to
run SQLite in SGX hardware mode:

```shell
bazel run :asylo_sqlite_sgx_hw
```

Specifying the `_sgx_hw` target suffix runs SQLite in SGX hardware mode.

SQLite should be running now in SGX hardware mode. Please follow the same steps
above to create an example table.

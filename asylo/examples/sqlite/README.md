<!--jekyll-front-matter
---

title: Running SQLite with Asylo

overview: Wrap an entire application in an enclave.

location: /_docs/guides/sqlite.md

order: 50

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
provides support for full-featured applications, such as SQLite 3.28.0, to run
inside an enclave. We also provide an application-wrapper to make it easy to run
an application in an enclave without any source code changes, along with a BUILD
file that allows external sources to be built with Bazel.

## Build SQLite 3.28.0 with Asylo

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
    urls = ["https://github.com/google/asylo/archive/v0.4.0.tar.gz"],
    sha256 = "9dd8063d1a8002f6cc729f0115e2140a2eb1b14a10c111411f6b554e14ee739c",
    strip_prefix = "asylo-0.4.0",
)

# SQLite
http_archive(
    name = "org_sqlite",
    build_file = "//asylo/distrib:sqlite.BUILD",
    urls = ["https://www.sqlite.org/2019/sqlite-autoconf-3280000.tar.gz"],
    sha256 = "d61b5286f062adfce5125eaf544d495300656908e61fca143517afcc0a89b7c3",
    strip_prefix = "sqlite-autoconf-3280000",
)

load("//asylo/bazel:asylo_deps.bzl", "asylo_deps")
asylo_deps()

load("//asylo/bazel:sgx_deps.bzl", "sgx_deps")
sgx_deps()
```

This bazel rule imports Asylo and SQLite. To build SQLite with Bazel, Asylo
provides the BUILD file for SQLite 3.28.0, located at
`@com_google_asylo/asylo/distrib/sqlite.BUILD`.

#### Add .bazelrc

Next, in the same workspace, create a `.bazelrc` file by copying from
[the one in Asylo Repository](https://github.com/google/asylo/blob/master/.bazelrc)

This file specifies the toolchain and configurations used to build Asylo
targets.

#### Build target for SQLite 3.28.0 with application wrapper

Asylo provides an application wrapper which makes it easy to run external user
applications in Asylo. To make use of it, create a BUILD file in your workspace,
and add the following lines to it.

```BUILD
licenses(["notice"])

load("//asylo/bazel:asylo.bzl", "cc_enclave_binary")

cc_enclave_binary(
    name = "asylo_sqlite",
    deps = ["@org_sqlite//:sqlite3_shell"],
)
```

The `cc_enclave_binary` is the build rule that uses the application wrapper. By
claiming SQLite as a dependency (`sqlite3_shell` is defined by our `BUILD.bazel`
file), it will wrap SQLite and run it in Asylo.

## Run SQLite

Now we are ready to build and run SQLite. First, we load a Docker container that
imports the current workspace by running the following Docker command from the
root of your project:

```
docker run -it --rm \
    -v ${PWD}:/opt/my-project \
    --tmpfs /root/.cache/bazel:exec \
    -w /opt/my-project \
    gcr.io/asylo-framework/asylo
```

Here `-v` maps the current workspace to the directory in Docker, and `-w` sets
the workspace in Docker.

As the SQLite build target is created, now it can be run with the following
`bazel` command from the Docker container:

```shell
bazel run --config=sgx-sim :asylo_redis
```

After finishing building, you should be able to see SQLite up and messages
similar as following:

```shell
SQLite version 3.28.0 2019-04-16 19:49:53
Enter ".help" for usage hints.
Connected to a transient in-memory database.
Use ".open FILENAME" to reopen on a persistent database.
sqlite>
```

Now we can run SQLite inside an enclave with some simple examples, such as:

```shell
sqlite> create table mytable(one varchar(10), two smallint);
sqlite> insert into mytable values('Asylo', 040);
sqlite> insert into mytable values('SQLite', 3280);
sqlite> select * from mytable;
Asylo|40
SQLite|3280
```

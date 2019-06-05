<!--jekyll-front-matter
---

title: Running Redis with Asylo

overview: Wrap an entire application in an enclave.

location: /_docs/guides/redis.md

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

### Asylo support to run Redis

Asylo is an open source framework for developing enclave applications. Asylo
provides support for full-featured applications, such as Redis 5.0.4, to run
inside an enclave. We also provide an application-wrapper to make it easy to run
an application in an enclave without any source code changes, along with a BUILD
file that allows external sources to be built with Bazel.

## Build Redis 5.0.4 with Asylo

### Setting up the environment in Docker

Asylo provides a custom Docker image that contains all required dependencies, as
well as Asylo's custom toolchain, which is a convenient tool for compiling
enclave applications without manually installing the toolchain. To get started,
please follow
[the Docker instructions in the Asylo repository README.md](https://github.com/google/asylo/blob/master/README.md)
to setup the environment for Docker.

### Set up a workspace

#### Import Asylo and Redis

In any directory that you would like to define your project workspace, import
Asylo and Redis by creating a `WORKSPACE` file and add the following lines to
it:

```
workspace(name = "asylo_redis_example")

load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")

# Asylo
http_archive(
    name = "com_google_asylo",
    urls = ["https://github.com/google/asylo/archive/v0.3.4.tar.gz"],
    strip_prefix = "asylo-0.3.4",
)

# Redis
http_archive(
    name = "com_github_antirez_redis",
    build_file = "@com_google_asylo//asylo/distrib:redis.BUILD",
    urls = ["https://github.com/antirez/redis/archive/5.0.4.tar.gz"],
    strip_prefix = "redis-5.0.4",
)

load("@com_google_asylo//asylo/bazel:asylo_deps.bzl", "asylo_deps")
asylo_deps()

load("@com_google_asylo//asylo/bazel:sgx_deps.bzl", "sgx_deps")
sgx_deps()

load("@com_google_asylo//asylo/bazel:asylo_deps.bzl", "asylo_go_deps")
asylo_go_deps()
```

This bazel rule imports Asylo and Redis. To build Redis with Bazel, Asylo
provides the BUILD file for Redis 5.0.4, located at
`@com_google_asylo/asylo/distrib/redis:BUILD.bazel`.

#### Add .bazelrc

Next, in the same workspace, create a `.bazelrc` file by copying from
[the one in Asylo Repository](https://github.com/google/asylo/blob/master/.bazelrc)

This file specifies the toolchain and configurations used to build Asylo
targets.

#### Build target for Redis 5.0.4 with application wrapper

Asylo provides an application wrapper which makes it easy to run external user
applications in Asylo. To make use of it, create a BUILD file in your workspace,
and add the following lines to it.

```BUILD
licenses(["notice"])

load("@com_google_asylo//asylo/bazel:asylo.bzl", "cc_enclave_binary")
load("@linux_sgx//:sgx_sdk.bzl", "sgx_enclave_configuration")

sgx_enclave_configuration(
    name = "redis_enclave_configuration",
    stack_max_size = "0x400000",
    heap_max_size = "0x1000000",
)

cc_enclave_binary(
    name = "asylo_redis",
    enclave_config = "redis_enclave_configuration",
    deps = ["@com_github_antirez_redis//:redis_main"],
)
```

The `cc_enclave_binary` is the build rule that uses the application wrapper. By
claiming Redis as a dependency (`redis_main` is defined by our `BUILD.bazel`
file), it will wrap Redis and run it in Asylo. The default enclave memory size
is not sufficient to run Redis, so we need to also pass an
`sgx_enclave_configuration` to increase both the stack and heap size in order to
run Redis.

## Run Redis Server

Now we are ready to build and run Redis server. First, we load a docker
container that imports the current workspace by running the following Docker
command from the root of your project:

```
docker run -it --rm \
    -v ${PWD}:/opt/my-project \
    --tmpfs /root/.cache/bazel:exec \
    -w /opt/my-project \
    --network host \
    gcr.io/asylo-framework/asylo
```

Here `-v` maps the current workspace to the directory in Docker, and `-w` sets
the workspace in Docker. `--network host` allows Docker to expose ports, which
is not the case by default.

As the Redis build target is created, now it can be built with the following
`bazel` command from the Docker container:

```shell
bazel build --config=sgx-sim :asylo_redis
```

After the target is built, run the following command to start Redis server:

```shell
./bazel-bin/asylo_redis
```

After running it you should be able to see Redis server up and messages similar
as following:

```shell
5884:M 25 Mar 2019 17:08:05.024 # Server initialized
5884:M 25 Mar 2019 17:08:05.024 * Ready to accept connections
```

## Run Redis Client

Now we can start a Redis client to connect to the server and start using it. In
a different terminal, run `redis-cli` to connect to the server.

```shell
redis-cli
```

After successfully connected to the server, now you can start playing with it by
setting/getting keys:

```shell
192.168.9.2:6379> ping
PONG
192.168.9.2:6379> set redis 5.0.4
OK
192.168.9.2:6379> get redis
"5.0.4"
```

To enable snapshotting (if it's not automatically enabled by the config file),
run from your redis client:

```shell
192.168.9.2:6379> CONFIG SET "save" "900 1"
```

These sets snapshotting after 900 seconds if there is at least 1 change to the
dataset. You can modify the config to the snapshotting rate you would like to
set.

WARNING: The `fork` security support is not fully implemented yet. Currently
`fork` in Asylo copies the enclave memory to untrusted memory without
encryption. It is INSECURE and leaks all enclave data. We are working actively
towards supporting secure `fork`.

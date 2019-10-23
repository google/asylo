<!--jekyll-front-matter
---

title: Asylo Remote Backend Guide

overview: Learn how to utilize an Asylo Remote Backend

location: /_docs/guides/remotebackend.md

order: 11

layout: docs

type: markdown

toc: true

---
{% include home.html %}
jekyll-front-matter-->

# Asylo Remote Backend Guide

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

There are two possible frameworks that are accessed identically by the remote
backend: local and remote. Both of them provision RemoteEnclaveProxyServer, but
do it differently:

*   local version runs the enclaves on the same machine as the application

*   remote version runs the enclaves on an SGX-enabled machine while the Web
    Application can be run on a non-SGX machine.

This guide shows how to buid Asylo Remote Backend provisioning server, to be
used in other examples: *
[Remote quickstart](https://github.com/google/asylo/tree/master/asylo/examples/remote/quickstart)
*
[Bouncing circles](https://github.com/google/asylo/tree/master/asylo/examples/remote/bouncing_circles)

### Building and launching provisioning server

```bash
docker run -it --net=host \
    -v ${ASYLO_SDK}:/opt/asylo/sdk \
    -v ${MY_PROJECT}:/opt/asylo/examples \
    -w /opt/asylo/examples/remote/provision_server \
    gcr.io/asylo-framework/asylo:latest \
    ./build.sh
```

After that, applications can be run and rely on this server to deploy enclaves
remotely.

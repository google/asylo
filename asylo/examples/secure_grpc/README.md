<!--jekyll-front-matter
---

title: Secure gRPC Example

overview: A code example illustrating how to use Asylo's secure gRPC support.

location: /_docs/guides/secure_grpc.md

order: 25

layout: docs

type: markdown

toc: true

---

{% include home.html %}

jekyll-front-matter-->

This guide demonstrates how to run secure gRPC endpoints inside SGX enclaves
using the features described in Asylo's
[gRPC Authn and Authz reference](https://asylo.dev/docs/reference/grpc_auth.html).
Specifically, the guide demonstrates how to configure the authentication
policies on two gRPC endpoints, and how to enforce a per-call authorization
policy based on enclave identity in the gRPC server.

The source files for this example are located in the
[secure_grpc](https://github.com/google/asylo-examples/tree/master/secure_grpc)
directory of [asylo-examples](https://github.com/google/asylo-examples).
Download the latest release
[here](https://github.com/google/asylo-examples/releases).

This guide builds on the concepts introduced in the
[Asylo gRPC Server Example](https://asylo.dev/docs/guides/grpc_server.html).
Readers are recommended to first review that guide before starting on this one.
Readers are also recommended to review the
[basics of gRPC authentication](https://grpc.io/docs/guides/auth/).

Note that this guide is for C++.

This guide focuses specifically on ACLs for SGX enclaves. Readers can refer to
the following resources to familiarize themselves with SGX identity:

*   [Enclave Signature](https://software.intel.com/en-us/node/702979)
*   [Running an Enclave with Validated Attributes](https://software.intel.com/en-us/node/703003)

## Introduction

This example uses the gRPC server enclave and Translator service implementation
from the
[Asylo gRPC Server Example](https://asylo.dev/docs/guides/grpc_server.html). The
original code has been refactored, and has a few additions for enforcing
authentication and authorization policies.

*   `grpc_server_enclave.cc` - Modifies `GrpcServerEnclave` to extract an ACL
    from its `EnclaveConfig` and pass to the `TranslatorServerImpl` instance.
*   `translator_server_impl.{cc,h}` - Modifies the `TranslatorServerImpl` to
    enforce an ACL on the `Translate()` RPC.

The `GrpcSeverEnclave` driver code was also restructed into different files:

*   `grpc_server_util.{cc,h}` - The bulk of the logic that invokes the
    `GrpcServerEnclave`'s entry-points.
*   `grpc_server_main.cc` (previously `grpc_server.cc`) - Defines a `main()`
    that runs the `GrpcServerEnclave` using the logic defined in
    `grpc_server_util.{cc,h}`. It now also parses an ACL flag in the form of a
    [text-format proto](https://developers.google.com/protocol-buffers/docs/reference/cpp/google.protobuf.text_format)
    and uses it to start the server.

The example code also includes a second enclave that uses a gRPC client to
communicate with the Translator server in `GrpcServerEnclave`.

*   `grpc_client_enclave.cc` - Defines an enclave, `GrpcClientEnclave`, that
    calls the Translator gRPC service using a gRPC stub.
*   `grpc_client_util.{cc,h}` - The bulk of the logic that invokes the
    `GrpcClientEnclave`'s entry-points.
*   `grpc_client_main.cc` - Defines a `main()` that starts the
    `GrpcClientEnclave` and invokes its entry-points.

Both gRPC endpoints are configured to use
[bidirectional SGX local authentication](https://asylo.dev/docs/reference/grpc_auth.html#bidirectional-sgx-local-authentication).
Authentication is bidirectional and takes places at the channel level. The
server uses call-level authorization. The client doesn't perform any
authorization checks on the server.

## Running the Server Enclave

Build and run the server enclave with the following command:

```bash
$ bazel run //asylo/examples/secure_grpc:grpc_server_sgx_sim -- \
   --acl="$(cat asylo/examples/secure_grpc/acl_isvprodid_2.textproto)"
```

There is one small difference between the invocation in this example and in the
original gRPC Server Example. We now pass an `--acl` command-line flag
containing a
[text format](https://developers.google.com/protocol-buffers/docs/reference/cpp/google.protobuf.text_format)
protobuf that defines an ACL to enforce within the `Translate()` RPC. This ACL
is further described in [Server ACL](#server-acl).

## Running the Client Enclave

Run the client enclave in a separate terminal, passing the server’s port in
`--port` and an input word to be translated in `--word_to_translate`:

```bash
$ bazel run //asylo/examples/secure_grpc:grpc_client_sgx_sim -- \
  --word_to_translate="asylo" \
  --port=<PORT>
```

In the server process, you should see the server enclave log that the peer was
authorized:

```
The peer is authorized for GetTranslation
```

In the client process, you should see the client enclave log the server’s
response:

```
Translation for "asylo" is "sanctuary"
```

## Server ACL

In the above [command](#running-the-server-enclave) for running the server, the
server uses ACL defined in
[`acl_isvprodid_2.textproto`](/asylo/examples/secure_grpc/acl_isvprodid_2.textproto):

```textproto
# Message type: asylo.SgxIdentityExpectation
reference_identity: {
  code_identity: {
    signer_assigned_identity: {
      mrsigner: {
        # This value corresponds to the Asylo debug signing key.
        hash: "\x83\xd7\x19\xe7\x7d\xea\xca\x14\x70\xf6\xba\xf6\x2a\x4d\x77\x43\x03\xc8\x99\xdb\x69\x02\x0f\x9c\x70\xee\x1d\xfc\x08\xc7\xce\x9e"
      }
      isvprodid: 2
      isvsvn: 1
    }
    miscselect: 0
    attributes: {
      flags: 0x0
      xfrm: 0x0
    }
  }
}
match_spec: {
  machine_configuration_match_spec: {
    is_cpu_svn_match_required: false
    is_sgx_type_match_required: false
  }
  code_identity_match_spec: {
    is_mrenclave_match_required: false
    is_mrsigner_match_required: true
    miscselect_match_mask: 0x0
    attributes_match_mask: {
      flags: 0x0
      xfrm: 0x0
    }
  }
}
```

This policy enforces the following properties of the peer’s identity:

*   The ACL sets an expectation on the caller’s SGX `signer_assigned_identity`,
    which includes the peer’s `mrsigner`, `isvprodid`, and `isvsvn` values:
    *   `mrsigner` is expected to match the Asylo debug signing key
    *   `isvprodid` is expected to be `2`
    *   `isvsvn` is expected to be greater than or equal to `1`
*   `is_mrenclave_match_required` is set `false` to indicate that the peer’s
    MRENCLAVE value is ignored.
*   `attributes_match_mask.flags` and `attributes_match_mask.xfrm` are both set
    to `0` to indicate that all of the peer’s ATTRIBUTES bits are ignored.
*   `miscselect_match_mask` is set to `0` to indicate that all of the peer’s
    MISCSELECT bits are ignored.

This expectation matches the client’s enclave configuration:

```python
sgx_enclave_configuration(
  name = "grpc_client_config",
  base = "//asylo/grpc/util:grpc_enclave_config",
  prodid = "2",
  isvsvn = "1",
)
```

WARNING: This ACL specifies an MRSIGNER value corresponding to Asylo’s RSA-3072
debug signing key. This key is used to sign all enclaves defined as
`debug_sign_enclave` targets, like the ones used in this example. The private
key is distributed in plaintext within Asylo. As such, the key is not
trustworthy and enclaves signed with this key should not be used within
production systems. We recommend following
[Intel’s suggested key stewardship practices](https://software.intel.com/en-us/node/702980)
for safeguarding enclave-signing keys.

## Authorization Failure: Wrong ISVPRODID

Let’s try running the server with a different ACL. The
[`acl_isvprodid_3.proto`](/asylo/examples/secure_grpc/acl_isvprodid_3.textproto):
file specifies an ACL for an ISVPRODID of `3`, which does not match the client’s
signer-assigned identity:

```bash
$ bazel run //asylo/examples/secure_grpc:grpc_server_sgx_sim -- \
   --acl="$(cat asylo/examples/secure_grpc/acl_isvprodid_3.textproto)"
```

Now, run the client enclave using the same command as before:

```bash
$ bazel run //asylo/examples/secure_grpc:grpc_client_sgx_sim -- \
  --word_to_translate="asylo" \
  --port=<PORT>
```

As expected, the RPC fails due to client having the wrong ISVPRODID value. The
authorization failure and explanation is reported in the server’s log:

```
The peer is unauthorized for GetTranslation: ISVPRODID value 2 does not match expected ISVPRODID value 3
```

The authorization failure is also reported by the client:

```
2019-11-20 01:51:21  QFATAL  grpc_client_main.cc : 64 : Getting translation for asylo failed: ::error::GoogleError::PERMISSION_DENIED: Peer is unauthorized for GetTranslation: ACL failed to match:
  ISVPRODID value 2 does not match expected ISVPRODID value 3
```

## Authorization Failure: Non-debug enclave

Both enclaves in this example are launched in debug mode, an insecure mode in
which the enclave’s memory can be inspected by a debugger. In production
systems,
[release enclaves](https://asylo.dev/docs/guides/sgx_release_enclaves.html) are
launched in non-debug mode so that their memory cannot be examined from outside
the enclave.

Whether or not an enclave is run in debug mode is reflected in the enclave’s SGX
ATTRIBUTES. ATTRIBUTES is a bit vector that represents the state of various
security-relevant properties of a running enclave. ATTRIBUTES has two
components: *flags*, which contains bits about the enclave, and *xfrm*, which
contains bits about the enclave’s execution environment. The DEBUG bit is
`attributes.flags[1]`.

We can enforce that the peer is a non-debug enclave by setting an expectation on
the peer’s SGX ATTRIBUTES in the server’s ACL. This is shown in
[`acl_non_debug.textproto`](/asylo/examples/secure_grpc/acl_non_debug.textproto),
which sets ATTRIBUTES to `0x0` in the reference identity, and the ATTRIBUTES
match mask to `0x2`. This indicates that the DEBUG bit in the peer’s identity
_must_ match the value of the DEBUG bit the reference identity (i.e., the peer
must *not* be a DEBUG enclave).

```textproto
# Message type: asylo.SgxIdentityExpectation
#
# This configuration enforces that the caller is a non-debug enclave.
#
# DEBUG is bit 1 of ATTRIBUTES. We set the corresponding bit in
# attributes_match_mask.flags to indicate that it should match the value of
# attributes.flags[1].
reference_identity: {
  code_identity: {
    # … other stuff
    attributes: {
      flags: 0x0
      xfrm: 0x0
    }
  }
}
match_spec: {
  machine_configuration_match_spec: {
    # … other stuff
  }
  code_identity_match_spec: {
    # … other stuff
    attributes_match_mask: {
      flags: 0x2
      xfrm: 0x0
    }
  }
}
```

```bash
$ bazel run //asylo/examples/secure_grpc:grpc_server_sgx_sim -- \
   --acl="$(cat asylo/examples/secure_grpc/acl_non_debug.textproto)"
```

As expected, the RPC fails in this case due to the peer’s DEBUG bit being set.
This authorization failure is logged by the server:

```
Peer is unauthorized for GetTranslation: ATTRIBUTES value {flags: [INIT, DEBUG, MODE64BIT] xfrm: [FPU, SSE, AVX] } does not match expected ATTRIBUTES value {flags: [] xfrm: [] } masked with {flags: [DEBUG] xfrm: [] }
```

NOTE: You may see a slightly different `ATTRIBUTES.xfrm` value reported on your
system, but this is irrelevant to the example because the server ACL doesn't set
any expectations on `ATTRIBUTES.xfrm`.

### SGX Simulation Test

To make the client pass the ACL, we must run the client enclave in non-debug
mode. This requires configuring the `debug` field in the enclave's
`asylo::SgxLoadConfig`. You can set this field to `false` by passing
`--debug=false` in the command that runs the client enclave:

```bash
$ bazel run //asylo/examples/secure_grpc:grpc_client_sgx_sim -- \
  --word_to_translate="asylo" \
  --debug=false \
  --port=<PORT>
```

After these changes, you should observe that the client enclave is authorized to
make the RPC.

NOTE: The client enclave is just a software-simulated non-debug enclave, and not
a real non-debug enclave backed by SGX hardware.

### SGX Hardware Test

If your system supports launching non-debug enclaves[^1], then you can test this
ACL using a non-debug SGX hardware enclave. Compile both the server and client
targets that end instead with `_sgx_hw` and run the example.

```bash
$ bazel run //asylo/examples/secure_grpc:grpc_server_sgx_hw -- \
   --acl="$(cat asylo/examples/secure_grpc/acl_non_debug.textproto)"
```

```bash
$ bazel run //asylo/examples/secure_grpc:grpc_client_sgx_hw -- \
  --word_to_translate="asylo" \
  --debug=false \
  --port=<PORT>
```

After making these changes, you should observe that the client enclave is
authorized to make the RPC.

## Further Resources

*   See
    [Asylo gRPC AuthN and AuthZ](https://asylo.dev/docs/reference/grpc_auth.html)
    for a review of the concepts used in this example.
*   See [C++ reference](https://asylo.dev/doxygen) for APIs used in this
    example.
*   An explanation of
    [SGX local attestation](https://software.intel.com/en-us/node/702983).
*   See [A Formal Analysis of EKEP](https://github.com/google/ekep-analysis/)
    for a ProVerif-based security analysis of the EKEP protocol.

<!-- Footnotes themselves at the bottom. -->

## Notes

[^1]: Running non-debug enclaves requires access to SGX hardware that supports
    [Flexible Launch Control (FLC)](https://software.intel.com/en-us/blogs/2018/12/09/an-update-on-3rd-party-attestation),
    or a commercial license and allowlisted signing key on pre-FLC platforms.
    For more information, see Intel’s guide for
    [Registering your Production Enclave](https://software.intel.com/en-us/sgx/request-license).

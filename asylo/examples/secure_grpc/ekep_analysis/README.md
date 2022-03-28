# A Formal Analysis of EKEP

## Introduction

Trustworthy Computing requires trustworthy connections between remote parties.
Normally, remote parties base symmetric trust on public-key infrastructure
(PKI): certificates attest to the provenance of private keys held by each party
and key-exchange protocols bootstrap from that trust to establish a private
session key to use for communication. However, Trustworthy Computing supports a
stronger notion of trust: remote attestation, by which a party may demonstrate
not only that their key is trusted, but that the software using the key matches
known properties and is running on known hardware.

Key exchange and remote attestation compose naturally in sequence: a protocol
may require remote attestation as the first communication on a secure channel
and close the connection if attestation fails. However, this adds unnecessary
complexity and requires an external PKI to certify the original keys for the
exchange. Instead, the [Enclave Key Exchange
Protocol](https://asylo.dev/docs/concepts/ekep.html) (EKEP) integrates remote
attestation with key exchange to establish a channel with trust based entirely
on Trustworthy Computing.

Participants in EKEP create ephemeral public/private key pairs, attest to those
pairs using remote attestation technology like Intel's Software Guard
Extensions (SGX), and use those attestations to establish a session key for
communication.

To gain confidence in EKEP, we modeled it in
[ProVerif](https://bblanche.gitlabpages.inria.fr/proverif/), a tool for formal
verification in the [applied](https://arxiv.org/abs/1609.03003)
[π-calculus](https://en.wikipedia.org/wiki/%CE%A0-calculus). We used this model
to prove security properties of EKEP, including perfect forward secrecy (PFS).
As part of this work, we used the C preprocessor to implement macros for
modularization and convenient tuple data types and operations. We also added a
simple test framework that allows us to check library models independently of
the main protocol.

We chose ProVerif because there was an existing ProVerif analysis of the [ALTS
handshake](https://cloud.google.com/docs/security/encryption-in-transit/application-layer-transport-security#handshake_protocol)
by Bruno Blanchet; we started by working through this analysis to understand
the properties that it verified. Our analysis was initially inspired by that
analysis, though our final ProVerif model shares little with Blanchet's.


## An overview of EKEP

EKEP performs a handshake with 6 messages in (conceptually[^1]) 3 rounds:

1. Precommit: agree on attestation and session-key requirements.
2. Attestation: attest to identities and the keys used to establish the channel.
3. Finish: compute the session key.

The handshake may halt at any message due to inconsistencies or cryptographic
failures. The following sequence diagram (from the EKEP documentation) shows the
full handshake.

![EKEP Handshake](ekep-handshake.svg "The EKEP Handshake")

This protocol is originally based on the ALTS handshake with the
addition of attestation to ephemeral keys.

The derivation of record protocol secrets computes an `HMAC-SHA256` using a
derived key over input that includes a full transcript of the handshake through
the `CLIENT_FINISH` message. Our EKEP model includes a step that uses the
record key to send a fresh message.


## EKEP Events and Queries

ProVerif analysis is based on events that label points in a protocol.
Properties of protocols are modeled as relations between these events.

We define the following events in the protocol, where `G` is the group used for
Diffie-Hellman key exchange, and `Name` represents the identity of a party in
the protocol. `Transcript5` is a typed bitstring that represents the last
transcript sent in the protocol, and `bitstring` is the ProVerif built-in type
for uninterpreted strings.


```
(** The server says that its Transcript5 is |transcript| in a session with
the Diffie-Hellman shared key |dh|. *)
event serverTranscript5((*dh=*)G, Transcript5).

(** The client says that its Transcript5 is |transcript| in a session with
the Diffie-Hellman shared key |dh|. *)
event clientTranscript5((*dh=*)G, Transcript5).

(** The |client| says that it agreed on a |sharedSecret| with the |server|. *)
event clientBoundIdentity(
    (*server=*)Name, (*client=*)Name, (*sharedSecret=*)G).

(** The |server| says that it agreed on a |sharedSecret| with the |client|. *)
event serverBoundIdentity(
    (*server=*)Name, (*client=*)Name, (*sharedSecret=*)G).

(** The client sent |message| on a channel established by EKEP. *)
event clientSentMessage((*message=*)bitstring).

(** The server received |message| on a channel established by EKEP. *)
event serverReceivedMessage((*message=*)bitstring).
```


The `serverTranscript5` and `clientTranscript5` are the 6th transcript messages
(using 0-based indexing) from the beginning of the protocol, and they should
agree if the two parties saw the same messages. We represent this basic
correctness property in ProVerif as follows:


```
(** If the client and server compute |cTranscript| and |sTranscript|
respectively as the Transcript5 values in the same EKEP session (identified by
the Diffie-Hellman shared key |dh|), then the client and server computed the
same transcripts.
*)
query dh: G, cTranscript: Transcript5, sTranscript: Transcript5;
  (event(clientTranscript5(dh, cTranscript)) &&
   event(serverTranscript5(dh, sTranscript))) ==>
   (cTranscript = sTranscript).
```


The next property shows that EKEP protects against mis-identification attacks:
the server and client agree about identities that they got from a connection
using a given shared secret.


```
(** If the client and server get public identities from a given connection, then
those identities match. *)
query idS: Name, idC: Name, idXS: Name, idXC: Name, ss: G;
  (event(clientBoundIdentity(idXS, idC, ss)) &&
   event(serverBoundIdentity(idS, idXC, ss))) ==>
  (idXS = idS && idXC = idC).
```


Next, we show that the adversary cannot perform man-in-the-middle attacks: a
server that receives a message on an EKEP channel can be sure that it was sent
by the client (and, due to the previous properties, this means that the message
was sent by the client with the expected identity).


```
(** If the client and server establish a connection and the server receives a
message on that connects, then the client sent that message. *)
query ss: G, m: bitstring;
  event(serverReceivedMessage(m)) ==>
  inj-event(clientSentMessage(m)).
```


Finally, we show that an adversary cannot learn any messages sent on an
established channel. This kind of query is supported directly in ProVerif as
follows:


```
(** The attacker cannot obtain the unique secret message exchanged between
client and server. *)
query attacker(new message).
```


Note that we add a second phase to the protocol in which the long-term
identities from the first part of the protocol are leaked. In this case, those
long-term keys are represent as MAC keys used to represent SGX-based identity.
Even in this case, the adversary cannot learn the message from the previous
round. This demonstrates that EKEP satisfies Perfect Forward Secrecy.


## Representing Trustworthy Identities

Our model represents SGX with a new principal that provides SGX attestations
for the client, the server, and any other arbitrary party. It represents the
identities as secret HMAC keys: the client and server each provide a MAC on a
message they want attested as coming from their identity.


```
(** SgxAttestationForClient provides SGX signatures for clients. *)
let SgxAttestationForClient(clientSgxMacKey: HmacKey, sgxPrivKey: SigningKey) =
  in(c, (message: ClientSgxMessage, tag: HmacAuthTag));
  let kind = ClientSgxMessage_kind(message) in
  if kind = kClientId then
  if hmacClientSgxVerify(clientSgxMacKey, message, tag) then
  out(c, signClientSgx(sgxPrivKey, message)).

(** SgxAttestationForServer provides SGX signatures for servers. *)
let SgxAttestationForServer(serverSgxMacKey: HmacKey, sgxPrivKey: SigningKey) =
  in(c, (message: ServerSgxMessage, tag: HmacAuthTag));
  if ServerSgxMessage_kind(message) = kServerId then
  if hmacServerSgxVerify(serverSgxMacKey, message, tag) then
  out(c, signServerSgx(sgxPrivKey, message)).

(** SgxAttestationForOther provides SGX signatures for the adversary. *)
let SgxAttestationForOther(sgxPrivKey: SigningKey) =
  in(c, (name: Name, publicKey: G, transcript: bitstring));
  out(c, sign(sgxPrivKey, (name, kOtherId, publicKey, transcript))).
```


Note that these implementations are not secret: the adversary can call
`SgxAttestationForClient` and can even replay old tagged messages. But all this
gives the adversary is the same public attested (signed) message as before, and
it already gets this message when the client performs attestation normally. The
only secret is the MAC key that represents the party's identity.

Note also that this model is not exposed in the events or queries from the
previous section: it is critical to the security of the protocol, but it works
underneath the level of events and queries to guarantee the security of
identities and hence the security of the protocol.

Finally, note that while this implementation calls itself "SGX", it is an
abstraction that more generally represents a Trustworthy Computing system that
can cryptographically attest to statements by identified parties.


## Development and Testing

ProVerif has limited support for standard development methodologies. As part of
the EKEP modeling project, we added support for some utilities that are of
general interest: textual include files, macro-based named-tuple data types,
and unit testing.


### Include Files

ProVerif does not support modular development; there is a `-lib` flag for the
`proverif` binary that allows callers to specify a single file for textual
inclusion, but not multiple files. It also doesn't support recursive inclusion
of files. These facilities are standard in modern programming languages.

We created a simple run script that uses the C preprocessor to support textual
inclusion of ProVerif library files (`.pvl`) in ProVerif (`.pv`) and ProVerif
library files. This allowed us to develop libraries of cryptographic and
utility functions separately from the main EKEP model and kept the EKEP model
clean. Our current libraries are `diffie_hellman.pvl`,
`authenticated_encryption.pvl`, `named_tuples.pvl`, and `list.pvl`. We also
have an `ekep.pvl` file that implements separable parts of the EKEP protocol so
that the top-level implementation of the protocol is clear.


### Named Tuples

We also used the C preprocessor to create useful macros to implement data
structures. In particular, we implemented strongly-typed named tuples, which
allow callers to extract named fields from the tuples. This drastically
increases the readability of the model. Unfortunately, one limitation is that
the macros must be defined for each possible length of the named tuple.

For example, the following implementation shows how to implement 2-tuples in C
preprocessor macros.


```
#define REDUCE_FORALL2(TypeName, field, result, var0, type0, var1, type1) \
  reduc forall var0: type0, var1: type1; \
    TypeName##_##field(Build##TypeName(var0, var1)) = result

#define DEFINE_DATA_TYPE2(TypeName, var0, type0, var1, type1) \
  type TypeName. \
  fun Build##TypeName(type0, type1): TypeName [data]. \
  REDUCE_FORALL2(TypeName, var0, var0, var0, type0, var1, type1). \
  REDUCE_FORALL2(TypeName, var1, var1, var0, type0, var1, type1)
```


The `REDUCE_FORALL2` macro produces a reduction that provides a function to
extract a field with name `field` from a named tuple with type name `TypeName`.
The top-level macro `DEFINE_DATA_TYPE2` implements a new named-tuple type
`TypeName` with a `BuildTypeName` function to construct a new instance of the
tuple and reductions for accessing each of its fields.


### Unit Testing

After modularization, we wanted to test our libraries separately from their use
in the EKEP model. So, we devised a simple test framework: a test consists of a
set of processes, each of which uses the functionality provided by a library
and checks properties of the reductions exposed by the library. If the property
succeeds, then the process sends the message `Success` to the channel. If the
property fails, then the process sends the message `Fail` to the channel.

The sole query in the test file is the secrecy of the `Fail` message: if the
adversary can get `Fail` on the channel, then one of the properties of the
library does not hold, and the test has failed. The trace produced by ProVerif
shows which property failed.

Here is a sample, minimal test of some functionality from the `list.pvl`
library, using our `test_helpers.pvl` library that provides unit-test functions
like `EXPECT_EQ`.


```
#include "list.pvl"

#include "test_helpers.pvl"

free b0: bitstring.
free b1: bitstring.

(** Checks that List_elem works on List1. *)
let TestElemList1() =
  let l1_0 = List1(b0) in
  EXPECT_TRUE(List_elem(b0, l1_0));
  EXPECT_FALSE(List_elem(b1, l1_0)).

(** Checks that List_some_intersection works on List1, List1 arguments. *)
let TestFirstIntersection1_1() =
  let l1_0 = List1(b0) in
  EXPECT_EQ(b0, List_some_intersection(l1_0, l1_0)).

process
  ( TestElemList1()
  | TestFirstIntersection1_1()
  | TestEq1()
  | TestHasIntersection1()
  | TestIsSubset1()
  )
```



### Speed

Our current EKEP model performs its analysis in less than 1 second. Here is the
summary output of `time ./run_proverif.sh ekep.pv`:


```
--------------------------------------------------------------
Verification summary:

Query event(clientTranscript5(dh,cTranscript)) && event(serverTranscript5(dh,sTranscript)) ==> cTranscript = sTranscript is true.

Query event(clientBoundIdentity(idXS,idC,ss)) && event(serverBoundIdentity(idS,idXC,ss)) ==> idXS = idS && idXC = idC is true.

Query inj-event(serverReceivedMessage(m)) ==> inj-event(clientSentMessage(m)) is true.

Query not attacker_p1(message[]) is true.

--------------------------------------------------------------

./run_proverif.sh ekep.pv  0.29s user 0.04s system 98% cpu 0.332 total
```



### Utility

Changing the EKEP protocol to introduce some bugs causes ProVerif to catch
these bugs. For example, if we change the client to not check the
cryptographically validated origin of its messages, then properties fail.

More precisely, if we add the function `getClientSgxMessage` as follows:


```
reduc forall message: ClientSgxMessage, key: VerifyingKey, anyKey: SigningKey;
  getClientSgxMessage(key, signClientSgx(anyKey, message)) = message.
```


and we replace the client validation call `checkClientSgxSignature` with this
call (thus ignoring the signature and just extracting the message), we get the
following result from ProVerif:


```
--------------------------------------------------------------
Verification summary:

Query event(clientTranscript5(dh,cTranscript)) && event(serverTranscript5(dh,sTranscript)) ==> cTranscript = sTranscript is true.

Query event(clientBoundIdentity(idXS,idC,ss)) && event(serverBoundIdentity(idS,idXC,ss)) ==> idXS = idS && idXC = idC is false.

Query inj-event(serverReceivedMessage(m)) ==> inj-event(clientSentMessage(m)) is false.

Query not attacker_p1(message[]) is true.

--------------------------------------------------------------
```


These errors say that it's no longer the case that the client and server agree
on who they're talking to and that just because a client received a message, it
doesn't mean that the server sent that message. In other words, an adversary
can now forge messages in the protocol.


### Limitations

The main limitation of our EKEP model is that our list implementation only
supports lists of length 1.[^2] This means that the model does not test cases
where, for example, a client proposes multiple possible attestation methods,
and the server selects one.


## Conclusions

EKEP has been shown to satisfy strong security properties, including PFS. We
are releasing this model under the Apache 2 license, and we welcome
contributions and comments.


## Notes

[^1]:
     Other variants of this handshake are possible; this document only analyzes
     the public version of EKEP.

[^2]:
     ProVerif takes a very long time (hours to days) to complete when used in
     our analysis for lists of length 2 and appears to never terminate for
     lists of length 3 or more.


# Running the Analysis and Tests

To run a file in ProVerif, use the script `run_proverif.sh`. This script
assumes that ProVerif is installed on the local machine. The typical usage is:

```bash
$ ./run_proverif.sh list_test.pv
```

NOTE: You can only run `.pv` files, and not `.pvl` (library) files.

## Debugging syntax errors

If the ProVerif script has a syntax error, the output will refer to a line in
one of the generated files. The temporary files will be automatically cleaned up
after the script finishes. To disable this automatic cleanup, set the
environment variable `PROVERIF_NO_CLEANUP`. For example:

```bash
$ PROVERIF_NO_CLEANUP=1 ./run_proverif.sh list_test.pv
```

## Running ProVerif Interactively

The `run_proverif.sh` script supports an environment variable
`PROVERIF_INTERACT`. If this variable is set, then `run_proverif.sh` will call
`proverif_interact` on the generated file instead of `proverif`. This brings up
an interactive GUI that allows the user to act as the adversary in a protocol.
For example:

```bash
$ PROVERIF_INTERACT=1 ./run_proverif.sh ekep.pv
```

To facilitate the job of the adversary in interactive mode, the `ekep.pvl` file
conditionally defines helper functions that support generating some of the
messages that would otherwise be tedious and error-prone to type. See the
`ifdef ENABLE_DEBUG_FUNCTIONS` block in `ekep.pvl` for these functions.

The `run_proverif.sh` script always defines `ENABLE_DEBUG_FUNCTIONS` when
`PROVERIF_INTERACT` is set.

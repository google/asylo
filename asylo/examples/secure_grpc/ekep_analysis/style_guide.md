# ProVerif Style Guide

## Overview

ProVerif implements a version of the [applied
π-calculus](https://en.wikipedia.org/wiki/%CE%A0-calculus), a formal language
that is used to reason about cryptographic protocols (among other things). This
document provides guidelines for writing uniform, consistent ProVerif code.

## Details

### Spacing

The rules for spacing try to remain close to Google style for other programming
languages.

#### Indentation

Use two spaces for indentation.

```proverif
let MyProcess() =
  new b: bitstring;
  out(c, b).
```

#### Continued lines

Indent line continuations with 4 spaces, to distinguish between continuations
and subsequent lines in a new scope.

```proverif
if x <> ComputeSomeReallyLongValue(theFirstVariable, theSecondVariable,
    theThirdVariable) then (
  new b0: bitstring;
  out(c, b0)
) else (
  new b1: bitstring;
  out(c, b1)
).
```

The second half of a reduction should always be written on a new line, for
clarity, so it should only be indented by two spaces, not four.

```proverif
fun fst((*first=*)bitstring, (*second=*)bitstring): (*element=*)bitstring
reduc
  forall x0: bitstring, x1: bitstring;
    fst(x0, x1) = x0.
```

The following version indents by too many spaces.

```proverif {.bad}
fun fst((*first=*)bitstring, (*second=*)bitstring): (*element=*)bitstring
reduc
  forall x0: bitstring, x1: bitstring;
      (* Incorrect 4-space indentation. *)
      fst(x0, x1) = x0.
```

You may also align continued lines for clarity. In the following example, the
query aligns the `event` expressions in the same parenthesized expression.

```proverif {.good}
query x: FieldElt, y: FieldElt, idS: Identity, idC: Identity;
  (event(ClientKey(x)) && event(ServerKey(y)) &&
   event(ServerBinds(exp(g, mul(x, y)), idC, idS))) ==>
  event(ClientBinds(exp(g, mul(x, y)), idC, idS)).
```

#### Alignment

Do not add horizontal space to align columns of text.

```proverif
const d0: bitstring         [data].
const longerName: bitstring [data].
```

The following version correctly keeps regular spacing.

```proverif
const d0: bitstring [data].
const longerName: bitstring [data].
```

#### Type annotations

Separate the type name from the variable name and colon with one space.

```proverif
type Key.
new k: Key.

in(c, (k: key, m: bitstring)).
```

The following version does not include a space between the variable name, the
colon, and the type.

```proverif
type Key.
new k:Key.
```

### Naming

ProVerif has several kinds of non-keyword names: functions, events, processes,
variables. These names use the following styles

- PascalCase
  - types (`TypeName`)
  - events (`EventName`)
  - processes (`ProcessName`)
- camelCase
  - variables (`variableName`)
  - arguments (`argumentName`)
  - functions (`functionName`)

#### Acronyms and initialisms

This style guide follows the main Google convention for naming acronyms and
initialisms: treat them like words. This decision means that acronyms and
initialisms do not always have consistent case, but it matches the majority of
the languages used at Google.

```proverif
type AesKey.

let AesReceiver() =
  in(c, (aesUserKey: AesKey)).
```

The following incorrect version uses a style that is more like Go.

```proverif
type AESKey.

let AESReceiver() =
  in(c, (aesUserKey: AESKey)).
```

### Comments

#### Documentation comments

Comments on types, events, processes, and functions should follow OCaml
documentation style: start the comment with two stars instead of one.

```proverif
(** Computes an exponentiation of |base|^|exponent|. *)
fun exp((*base=*)GroupElt, (*exponent=*)FieldElt): GroupElt.
```

```proverif
(* Incorrect single-star comment on a function. *)

(* Computes an exponentiation of |base|^|exponent|. *)
fun exp((*base=*)GroupElt, (*exponent=*)FieldElt): GroupElt.
```

#### Process and function comments

Each process should have a documentation comment that starts with a verb in the
present tense. This is analogous to function comments in Google style for
languages like C++.

```proverif
(** Computes an exponentiation of |base|^|exponent|. *)
fun exp((*base=*)GroupElt, (*exponent=*)FieldElt): GroupElt.

(** Sends a fresh bitstring on channel |c|. *)
let Server() =
  new value: bitstring;
  out(c, value).
```

#### Event comments

ProVerif events are critical to its security modeling, and they have
correspondingly high requirements for the clarity of their comments. Event
comments should be formulated as "says" statements: a given principal "says" a
given fact. This style helps interpret the comments, especially in the context
of queries.

```proverif
(** The server says that a |secret| comes from communication between itself
(|serverId|) and |clientId|. *)
event ServerBinds((*secret=*)GroupElt, (*clientId=*)Identity,
    (*serverId=*)Identity).
```

The following incorrect example uses a function-style comment to describe an
event.

```proverif
(* Incorrect function-style comment. *)

(** Binds a secret to identities. *)
event ServerBinds((*secret=*)GroupElt, (*clientId=*)Identity,
    (*serverId=*)Identity).
```

#### End-of-line comments

As in other Google style guides, end-of-line comments should be separated from
the end of the line of code by 2 spaces.

```proverif
new k: Key.  (* A signing key for the server. *)
```

The following incorrect example only uses one space between the declaration and
its comment.

```proverif {.bad}
new k: Key. (* A signing key for the server. *)
```

#### Bitstring comments

ProVerif protocols often use uninterpreted bitstrings, and these can be hard
to interpret, especially in function definitions, where no argument names are
given. So, use inline comments to add argument names for all bitstring
arguments. Inline comments are allowed for other types if they improve the
readability of the function definition.

```proverif
fun sign(Key, (*message=*)bitstring): (*signature=*)bitstring.
```

The following definitions demonstrate incorrect ways to write comments in
functions.

```proverif
(* Superfluous comment on key repeats the type name. *)
fun sign((*key=*)Key, (*message=*)bitstring): (*signature=*)bitstring.

(* Lack of comments makes it hard to interpret. *)
fun sign(Key, bitstring): bitstring.
```

### Specific Constructions

#### Reductions

The set of possible reductions of a function are given after that function. If
the reduction only has one case, then it can be put on the same line as the
`reduc` keyword. Otherwise, it should be put on the next line, indented by two
spaces.

All instances of the `otherwise` keyword should be at the end of the line so
that the variable statements `forall` line up.

```proverif
fun sign(Key, (*message=*)bitstring): (*signature=*)bitstring.

fun checkSign(key, (*signature=*)bitstring): bool
reduc
  forall k: Key, m: bitstring;
    checkSign(publicKey(k), sign(k, m)) = true otherwise
  forall k: Key, s: bitstring;
    checkSign(k, s) = false.
```

#### Queries

Queries often have long lines. They are also conceptually similar to reductions
and should be visually similar. Like the `forall` in a reduction, the query
may be given on a single line if it is short enough. Otherwise, the statement of
the query should be given on a new line, indented with 2 spaces. The arrow in
the query (`==>`) should be at the end of the line.

```proverif
query x: FieldElt, y: FieldElt, idS: Identity, idC: Identity;
  (event(ClientKey(x)) && event(ServerKey(y)) &&
   event(ServerBinds(exp(g, mul(x, y)), idC, idS))) ==>
  event(ClientBinds(exp(g, mul(x, y)), idC, idS)).
```

The following examples demonstrate incorrect ways to write queries.

```proverif
(* Incorrect 4-space indentation for the query statement. *)
query x: FieldElt, y: FieldElt, idS: Identity, idC: Identity;
    (event(ClientKey(x)) && event(ServerKey(y)) &&
     event(ServerBinds(exp(g, mul(x, y)), idC, idS))) ==>
    event(ClientBinds(exp(g, mul(x, y)), idC, idS)).

(* Incorrect placement of the arrow. *)
query x: FieldElt, y: FieldElt, idS: Identity, idC: Identity;
  (event(ClientKey(x)) && event(ServerKey(y)) &&
   event(ServerBinds(exp(g, mul(x, y)), idC, idS)))
  ==>
  event(ClientBinds(exp(g, mul(x, y)), idC, idS)).
```

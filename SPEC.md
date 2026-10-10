# SCPP v2 — the message a card signs

SCPP is how a card authorises one payment. The terminal states the terms, the
card signs exactly those terms, and a verifier re-derives them and checks the
signature. That is the entire protocol.

It is deliberately small. A card decides **who says yes** — not whose money
moves, not where it settles. Everything downstream of a valid signature is the
payment network's concern and is outside this document.

## The shape of a tap

```
terminal                          card                      verifier
   |                               |                            |
   |-- select the payment applet ->|                            |
   |<------ card id, public key, counter                        |
   |                               |                            |
   | build the terms                                            |
   | challenge = SHA-256(encoded terms)                         |
   |                               |                            |
   |------ sign(challenge) ------->|                            |
   |<----- DER signature ----------|                            |
   |                               |                            |
   |----------- terms + signature ----------------------------->|
   |                                      re-encode the terms   |
   |                                      verify the signature  |
   |<---------------------- approved / refused -----------------|
```

The card never sees an amount, an account or a payment id. It is handed 32
bytes and asked to sign them. Everything the card contributes to security comes
from one property: the private key cannot leave it.

## The encoded message

BER-TLV, in a **fixed field order**. The order is part of the format, not an
implementation detail: the same values in a different order are different bytes
and a different signature.

| # | Field | Tag | Encoding |
|---|---|---|---|
| 1 | `amountAtomic` | `DF05` | 32-byte unsigned big-endian integer |
| 2 | `assetSymbol` | `DF04` | ASCII, 1–16 bytes |
| 3 | `transactionDate` | `9A` | n6 BCD, `YYMMDD`, UTC |
| 4 | `transactionTime` | `9F21` | n6 BCD, `HHMMSS`, UTC |
| 5 | `deviceId` | `DF06` | ASCII, 1–32 bytes |
| 6 | `receivingAccountId` | `DF07` | ASCII, 1–64 bytes |
| 7 | `version` | `DF01` | one byte, `0x02` |
| 8 | `counter` | `DF02` | uint32 big-endian |
| 9 | `unpredictableNumber` | `9F37` | 4 bytes, terminal-generated |
| 10 | `paymentId` | `DF10` | ASCII, 1–64 bytes |

Lengths use BER short form below 128 bytes and long form above.

### Why the amount is 32 bytes

A token quantity is a uint256 on chain, so it is carried at the width it
already has. `9F02`, the EMV authorised amount, is registered as n12 BCD, which
cannot hold it. Truncating a monetary value to fit an encoding is not a trade
anyone gets to make, so the amount takes a proprietary tag instead.

### Why the asset sits next to the amount

An atomic amount says nothing without the asset it counts. The two are signed
together or neither is worth signing.

## The tag rule

> An industry tag is used only where **both** the meaning and the encoding
> match. Where either differs, the field takes a proprietary tag.

The asymmetry is the reason. An unfamiliar proprietary tag fails loudly in a
reader, bridge or debugging tool that does not know it. A familiar industry tag
carrying something else does not fail at all: it decodes under the encoding the
registry defines and produces a plausible wrong answer. For a profile meant to
be published, the second is the dangerous one, so a tag that cannot be honoured
exactly is a tag this profile does not use.

Three industry tags survive that rule. `9A` and `9F21` are n6 BCD here exactly
as in the registry, and `9F37` carries four binary bytes of terminal-generated
unpredictability exactly as the registry defines it.

`9F37` is the tag this profile most wants to honour rather than approximate. It
is what makes the message one an EMV terminal already knows how to assemble,
and it is what removes the round trip: the terminal supplies the freshness
itself rather than asking a server for a nonce.

## Reserved tags

Defined, and never emitted by v2. Reserving one costs a line now and avoids a
second version of the profile later. An encoder handed one today fails loudly
rather than silently dropping a field a reader believed was signed.

| Tag | Held for |
|---|---|
| `DF13` | a PIN commitment, so a later version can bind a PIN to one authorisation |
| `5F2A` | a fiat currency code |
| `9F02` | a fiat amount, at its registered n12 BCD encoding |
| `9F1C` | a terminal identifier |
| `9F16` | a merchant identifier |
| `DF03`, `DF11`, `DF12` | retired v1 fields: server nonce, action id, expiry |

## The challenge

```
challenge = SHA-256(encoded message)
```

The hash is taken over the encoded bytes, never over a re-serialised object, so
a reader and a verifier agree by producing identical bytes rather than by
agreeing on a serialisation.

## Signing, and the double hash

The card is handed the 32-byte challenge and signs it with ECDSA on P-256,
producing a DER signature.

**A standard P-256 signing API hashes the message it is given.** So what is
actually signed is `SHA-256(challenge)`, and the challenge is itself
`SHA-256(encoded message)`. Two rounds of hashing is correct and deliberate.

A verifier must therefore verify the signature **over the challenge as a
message**, not as a pre-computed digest. Implementations that "fix" this into a
raw digest verification reject every genuine signature. This is the single most
likely thing to get wrong, and the test vectors below catch it immediately.

## Public keys

A card returns a raw uncompressed point: `04 || X || Y`, 65 bytes. Verifiers
wrap it in a P-256 `SubjectPublicKeyInfo` before use; the wrapper is constant.
Importing is also the curve check — a point not on P-256 is rejected there.

Signatures are canonicalised to low-S before comparison, so the same
authorisation has one representation.

## Response codes

A two-digit vocabulary a terminal, a receipt and an operator already read.

| Code | Meaning |
|---|---|
| `00` | approved |
| `51` | insufficient funds |
| `54` | expired |
| `55` | incorrect PIN |
| `62` | restricted card |
| `75` | PIN tries exceeded |
| `94` | duplicate |

The PIN codes are defined now for the same reason `DF13` is reserved: the set
is published with v2 so that adding PIN later adds no new code to agree on.

## Test vectors

`packages/scpp/src/vectors.ts` carries positive and negative vectors. An
implementation is correct when it reproduces every `encodedHex` and
`challengeHex` from the same field values, and agrees about which negative
cases fail.

They are literals on purpose. Computing the expected bytes from the encoder
they are meant to test would make the file agree with any bug that encoder
grows. **They were produced by a second encoder written from the profile table
alone**, and the implementation here is correct when it matches them.

The first vector, a one-USDC tap:

```
amountAtomic         1000000
assetSymbol          USDC
transactionDate      260401
transactionTime      143005
deviceId             reader-01
receivingAccountId   acct_01HZY8QK3MREADER
counter              1
unpredictableNumber  3f1a9c04
paymentId            pay_01HZY8QK3M7T2V

encoded (128 bytes)
df052000000000000000000000000000000000000000000000000000000000000f4240
df0404555344439a032604019f2103143005df06097265616465722d3031df07156163
63745f3031485a5938514b334d524541444552df010102df0204000000019f37043f1a
9c04df10127061795f3031485a5938514b334d37543256

challenge
c1acc0fd090851aa195072c5362faac7badd48a02a338b13bf445a6309eba2d4
```

## What this document does not specify

Card personalisation and issuance, key generation and storage inside a secure
element, the transport a reader uses to reach a card, and everything that
happens after a verifier approves a tap. See `SECURITY.md` for the division of
responsibility, and the note on scope in `README.md`.

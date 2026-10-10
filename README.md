# tap2pay

**An open protocol for authorising a stablecoin payment with a tap.**

A card is held to a reader. The reader states the terms, the card signs exactly
those terms, and a verifier re-derives them and checks the signature. One tap,
about a second, no payment session and nothing to poll.

This repository is the **authorisation layer**: the wire format, a reference
implementation, and the checks a verifier has to make. What happens after a
valid signature — settlement, ledger, custody — is Stableyard, and is not open
source.

## Run it, no hardware

```bash
npm install
npm run demo
```

A software card signs a real tap and a verifier approves it, then the same
signature is refused four ways:

```
  SCPP v2 — one tap, authorised
------------------------------------------------------------------------
  card          card_demo
  amount        5000000 atomic USDC
  to account    acct_01HZY8QK3MDEMO
  tap           #15
------------------------------------------------------------------------
  challenge     c6c6dc631cc45ff2770ef0a74df7113374efd98007824f26434548839b120784

  => APPROVED  response code 00

  SCPP v2 — the same signature, refused
------------------------------------------------------------------------
  amount raised to 50 USDC           refused  62  bad_signature
  receiver swapped                   refused  62  receiver_mismatch
  same tap presented twice           refused  94  counter_replayed
  another card's signature           refused  62  bad_signature
```

The refusals are the interesting half. Each presents a *valid* signature
against terms it does not cover, which is the shape of a redirected, re-priced
or replayed payment.

```bash
npm test        # 96 tests, including the vectors
npm run typecheck
```

## What is here

| | |
|---|---|
| [`SPEC.md`](SPEC.md) | the wire format: tags, order, encodings, the challenge |
| [`SECURITY.md`](SECURITY.md) | the three checks a verifier must make, and the failure with no retry |
| `packages/scpp/` | encode, decode, challenge, verify, and the test vectors |
| `examples/softcard/` | a P-256 key that speaks the protocol, so the demo needs no card |
| `examples/verifier/` | the complete authorisation decision, 60 lines |
| `examples/demo/` | one tap, then the four refusals |

## Three things worth a look

**No runtime dependencies.** Not one. The library is `node:crypto` and bytes.

**The test vectors were produced by a second encoder**, written from the
profile table alone, and stored as literals. Computing expected bytes from the
encoder under test would make the vectors agree with any bug it grows.

**Reserved tags carry a written reason each** — a PIN commitment, a fiat amount
and currency, terminal and merchant identifiers — defined now and never
emitted, so a later version extends the profile instead of forking it.

## The one rule the format is built on

> An industry tag is used only where **both** the meaning and the encoding
> match. Where either differs, the field takes a proprietary tag.

An unfamiliar proprietary tag fails loudly in a reader that does not know it. A
familiar industry tag carrying something else does not fail at all — it decodes
under the encoding the registry defines and produces a plausible wrong answer.
For a profile meant to be published, the second is the dangerous one.

## Scope

A card decides **who says yes**. It does not decide whose money moves or where
it settles — those follow the account being paid, exactly as they do for any
other way of authorising a payment.

So the protocol assumes very little: a card holds a P-256 private key that
cannot be exported, and something can hand it 32 bytes to sign. Card
personalisation, key storage inside a secure element, and the transport a
reader uses are all out of scope here.

## Status

The protocol and this implementation are v2 and stable enough to build against;
the vectors are the contract.

A plastic card and a phone have each tapped a terminal and settled a real
payment against a production backend, with a receipt printed. That ran on
DopePay, not on the Stableyard v2 settlement layer, which is still being built.
Attestation at enrolment is not implemented: a card is issued, so its key is
known from the start, but a phone currently asserts its own public key and
nothing checks that claim. Phone credentials stay internal until that lands.

## Licence

Apache 2.0.

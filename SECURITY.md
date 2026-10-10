# What a verifier must check

A valid signature says only that *the holder of this key agreed to some terms*.
It does not say the terms were these, that this account was the one named, or
that the tap has not already been spent. Three further checks decide that, and
a verifier that skips any of them is not safe to put money behind.

`examples/verifier/index.js` is the whole decision in 60 lines.

## 1. The signed receiver is the one that gets paid

Derive the receiver from the authenticated merchant, then require the signature
to cover that exact value. Never take it from the request.

Without this, a terminal can present somebody else's tap against its own
account and be paid for it. The signature is still valid — it just was not an
agreement to pay *them*.

## 2. The signed amount is the one charged

Re-encode the terms server-side and hash those bytes. Never verify against
bytes the reader supplied, or the reader chooses what was signed.

## 3. The counter only goes up, and is claimed atomically

Each card carries a counter that advances on every signature. A verifier
accepts a tap only when its counter is strictly greater than the highest one
seen for that card, and must claim it in a single atomic operation — a
compare-and-set, not a read followed by a write.

Without atomicity, two readers presenting the same tap concurrently can both
pass the comparison before either records it.

Gaps are normal and not suspicious: a tap that fails after the card has signed
advances the card without ever reaching a verifier.

## The failure that has no retry

If a card has signed and the verifier's answer never arrives, the terminal does
not know whether money moved. **Do not retry that tap.** The counter is already
spent, so the same card refuses the same counter — and if the payment did
commit, a second tap is a second payment.

Surface it as needing a human, with the reference, and stop. An interface that
offers a retry button in this state is a defect.

## Freshness

`9F37` is four bytes the terminal generates for one tap. It is what makes two
otherwise identical taps different messages, and it removes the round trip that
a server-issued nonce would require.

It is freshness, not authorisation. The replay defence is the counter.

## What this repository does not do

Everything after `approved`. Moving money, booking it, settling it, reporting
it, refunding it, reconciling it — all of that is the payment network's
problem, and none of it is here.

Also not here, and deliberately: card personalisation and issuance, key
generation and storage inside a secure element, and the transport a reader uses
to reach a card. The protocol assumes only that a card holds a P-256 private
key that cannot be exported, and that something can hand it 32 bytes.

## Reporting a problem

Open an issue for anything in the protocol or these implementations.

For a vulnerability in the hosted network rather than in this repository,
please report it privately through the contact on stableyard.fi rather than
filing publicly.

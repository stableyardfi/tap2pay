/**
 * What a verifier has to do before it believes a tap.
 *
 * The signature is necessary and nowhere near sufficient. A valid signature
 * only says "the holder of this key agreed to some terms". Three further checks
 * decide whether it agreed to THESE terms, for THIS account, once.
 *
 * This file is the complete authorisation decision and nothing else. What
 * happens after `approved` -- moving money, booking it, settling it, reporting
 * it -- is the payment network's problem and is not in this repository.
 */

import {
  decodeScppV2Message,
  encodeScppV2Message,
  scppV2Challenge,
  verifyScppSignature,
} from "@stableyard/scpp";

/**
 * @param {object} input
 * @param {object} input.terms        the terms the VERIFIER believes, never the ones the reader sent
 * @param {string} input.signatureDer hex DER signature produced by the card
 * @param {object} input.card         { publicKey, lastCounter, receivingAccountId }
 */
export function authoriseTap({ terms, signatureDer, card }) {
  /* 1. The receiver is the one the card signed.
        Derived from the card's own account, never taken from the request. This
        is what stops a terminal redirecting somebody else's tap to itself. */
  if (terms.receivingAccountId !== card.receivingAccountId) {
    return refuse("62", "receiver_mismatch", "this card did not authorise a payment to this account");
  }

  /* 2. The counter only goes up.
        A captured tap cannot be presented twice. In a real verifier this claim
        is atomic -- read and advance in one operation -- so two readers cannot
        spend the same tap concurrently. */
  if (!Number.isInteger(terms.counter) || terms.counter <= card.lastCounter) {
    return refuse("94", "counter_replayed", `counter ${terms.counter} is not above ${card.lastCounter}`);
  }

  /* 3. The signature covers exactly these terms.
        The verifier RE-ENCODES the terms it believes and hashes those. It never
        verifies against bytes the reader supplied, because then the reader
        would be choosing what was signed. */
  const encoded = encodeScppV2Message(terms);
  const challenge = scppV2Challenge(terms);
  const valid = verifyScppSignature({ publicKey: card.publicKey, challenge, signatureDer });
  if (!valid) {
    return refuse("62", "bad_signature", "the signature does not cover these terms");
  }

  return {
    approved: true,
    responseCode: "00",
    counter: terms.counter,
    encodedHex: Buffer.from(encoded).toString("hex"),
    challengeHex: Buffer.from(challenge).toString("hex"),
    /* Proof the bytes mean what we think: decode them back and show the fields. */
    decoded: decodeScppV2Message(encoded),
  };
}

function refuse(responseCode, code, reason) {
  return { approved: false, responseCode, code, reason };
}

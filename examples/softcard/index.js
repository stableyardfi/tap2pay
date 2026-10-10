/**
 * A card, in software.
 *
 * Holds a P-256 private key and signs a 32-byte challenge with it. That is the
 * whole of what a card does in this protocol: everything else -- which account
 * it belongs to, what it is allowed to spend, whether the payment settles -- is
 * decided by the verifier and by the network behind it.
 *
 * A real card keeps its key in a secure element and is reached over NFC. How it
 * does that is out of scope here and makes no difference to the bytes: the
 * challenge goes in, a DER signature comes out. This file exists so the demo
 * runs on a laptop with no hardware.
 */

import { createSign, generateKeyPairSync } from "node:crypto";

const UNCOMPRESSED_POINT_BYTES = 65;

export function createSoftCard({ cardId, counter = 0 } = {}) {
  const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "prime256v1" });

  /* A card hands back a raw uncompressed point: 04 || X || Y. */
  const point = publicKey
    .export({ format: "der", type: "spki" })
    .subarray(-UNCOMPRESSED_POINT_BYTES);

  let tapCounter = counter;

  return {
    cardId: cardId ?? `card_${point.subarray(1, 9).toString("hex")}`,
    publicKey: point.toString("hex"),
    /* Names which key this card signs with, so a replacement is never confused
       with the key it replaced. */
    publicKeyId: point.subarray(1, 5).toString("hex"),

    get counter() {
      return tapCounter;
    },

    /**
     * Sign one challenge, and advance.
     *
     * The counter moves whether or not the payment is ever settled. That is the
     * point of it: a tap that was signed is spent, even if the answer never
     * came back.
     */
    sign(challenge) {
      if (challenge.length !== 32) {
        throw new Error(`challenge must be 32 bytes, got ${challenge.length}`);
      }
      tapCounter += 1;
      /* A standard P-256 signer hashes the message it is handed. The challenge
         is already SHA-256 of the encoded message, so what is signed is
         SHA-256(challenge) -- see the note in verifyScppSignature. */
      return createSign("sha256")
        .update(Buffer.from(challenge))
        .sign({ key: privateKey, dsaEncoding: "der" })
        .toString("hex");
    },
  };
}

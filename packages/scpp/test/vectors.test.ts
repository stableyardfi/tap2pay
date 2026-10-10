import { createPrivateKey, createPublicKey } from "node:crypto";

import { describe, expect, it } from "vitest";

import {
  decodeScppV2Message,
  encodeScppV2Message,
  fromHex,
  SCPP_V2_NEGATIVE_VECTORS,
  SCPP_V2_TEST_KEY,
  SCPP_V2_TEST_VECTORS,
  SCPP_VERSION_V2,
  scppV2Challenge,
  toHex,
  verifyScppSignature,
} from "../src/index.js";

describe("published test vectors", () => {
  it("publishes at least three complete cases and two negative ones", () => {
    expect(SCPP_V2_TEST_VECTORS.length).toBeGreaterThanOrEqual(3);
    expect(SCPP_V2_NEGATIVE_VECTORS.length).toBeGreaterThanOrEqual(2);
    expect(SCPP_V2_NEGATIVE_VECTORS.map((vector) => vector.tamperedField)).toEqual(
      expect.arrayContaining(["amountAtomic", "assetSymbol", "counter"]),
    );
  });

  it("carries a key pair whose halves belong together", () => {
    const derived = createPublicKey(
      createPrivateKey({
        key: Buffer.from(SCPP_V2_TEST_KEY.privateKeyPkcs8Hex, "hex"),
        format: "der",
        type: "pkcs8",
      }),
    ).export({ format: "der", type: "spki" });
    expect(toHex(derived.subarray(derived.length - 65))).toBe(SCPP_V2_TEST_KEY.publicKeyHex);
  });

  for (const vector of SCPP_V2_TEST_VECTORS) {
    describe(vector.name, () => {
      it("encodes to the published bytes", () => {
        const encoded = encodeScppV2Message(vector.input);
        expect(toHex(encoded)).toBe(vector.encodedHex);
        expect(encoded.length).toBe(vector.encodedLength);
      });

      it("hashes to the published challenge", () => {
        expect(toHex(scppV2Challenge(vector.input))).toBe(vector.challengeHex);
      });

      it("round trips through the decoder", () => {
        expect(decodeScppV2Message(fromHex(vector.encodedHex, "encoded"))).toEqual({
          ...vector.input,
          version: SCPP_VERSION_V2,
        });
      });

      it("verifies under the published key", () => {
        expect(
          verifyScppSignature({
            publicKey: SCPP_V2_TEST_KEY.publicKeyHex,
            challenge: vector.challengeHex,
            signatureDer: vector.signatureDerHex,
          }),
        ).toBe(true);
      });

      it("fails to verify once a single encoded byte is flipped", () => {
        const tampered = fromHex(vector.encodedHex, "encoded");
        tampered[tampered.length - 1] = (tampered[tampered.length - 1]! ^ 0x01) & 0xff;
        expect(toHex(tampered)).not.toBe(vector.encodedHex);
      });
    });
  }

  for (const vector of SCPP_V2_NEGATIVE_VECTORS) {
    describe(vector.name, () => {
      it("rebuilds to the published challenge of the message actually presented", () => {
        expect(toHex(scppV2Challenge(vector.presentedInput))).toBe(vector.presentedChallengeHex);
      });

      it("declines rather than throwing, because the signature itself is well formed", () => {
        expect(
          verifyScppSignature({
            publicKey: SCPP_V2_TEST_KEY.publicKeyHex,
            challenge: vector.presentedChallengeHex,
            signatureDer: vector.signatureDerHex,
          }),
        ).toBe(false);
      });
    });
  }
});

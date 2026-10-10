import { createPrivateKey, generateKeyPairSync, sign } from "node:crypto";

import { describe, expect, it } from "vitest";

import {
  canonicalDerSignature,
  concatBytes,
  fromHex,
  importScppPublicKey,
  parseDerSignature,
  SCPP_V2_TEST_KEY,
  SCPP_V2_TEST_VECTORS,
  ScppError,
  scppV2Challenge,
  toHex,
  verifyScppSignature,
} from "../src/index.js";

const VECTOR = SCPP_V2_TEST_VECTORS[0]!;
const PUBLIC_KEY = SCPP_V2_TEST_KEY.publicKeyHex;

function codeOf(run: () => unknown): string {
  try {
    run();
  } catch (error) {
    if (error instanceof ScppError) {
      return error.code;
    }
    throw error;
  }
  throw new Error("expected the call to be rejected");
}

function privateKey() {
  return createPrivateKey({
    key: Buffer.from(SCPP_V2_TEST_KEY.privateKeyPkcs8Hex, "hex"),
    format: "der",
    type: "pkcs8",
  });
}

describe("public key import", () => {
  it("accepts a sixty-five byte uncompressed point", () => {
    expect(() => importScppPublicKey(PUBLIC_KEY)).not.toThrow();
    expect(() => importScppPublicKey(fromHex(PUBLIC_KEY, "publicKey"))).not.toThrow();
  });

  it("rejects the wrong length", () => {
    expect(codeOf(() => importScppPublicKey(PUBLIC_KEY.slice(0, 128)))).toBe("SCPP_INVALID_PUBLIC_KEY");
    expect(codeOf(() => importScppPublicKey(`${PUBLIC_KEY}00`))).toBe("SCPP_INVALID_PUBLIC_KEY");
  });

  it("rejects a compressed point", () => {
    expect(codeOf(() => importScppPublicKey(`02${PUBLIC_KEY.slice(2)}`))).toBe("SCPP_INVALID_PUBLIC_KEY");
  });

  it("rejects a point that is not on the curve", () => {
    const offCurve = fromHex(PUBLIC_KEY, "publicKey");
    offCurve[64] = (offCurve[64]! ^ 0x01) & 0xff;
    expect(codeOf(() => importScppPublicKey(offCurve))).toBe("SCPP_INVALID_PUBLIC_KEY");
  });

  it("rejects input that is neither bytes nor hexadecimal", () => {
    expect(codeOf(() => importScppPublicKey({} as unknown as string))).toBe("SCPP_INVALID_FIELD");
    expect(codeOf(() => importScppPublicKey("04zz"))).toBe("SCPP_INVALID_FIELD");
  });
});

describe("DER signature parsing", () => {
  it("reads a signature a card produced", () => {
    const parsed = parseDerSignature(VECTOR.signatureDerHex);
    expect(parsed.r).toBeGreaterThan(0n);
    expect(toHex(canonicalDerSignature(parsed))).toBe(VECTOR.signatureDerHex);
  });

  it("tolerates a component padded with more leading zeros than DER needs", () => {
    const bytes = fromHex(VECTOR.signatureDerHex, "signatureDer");
    const rLength = bytes[3]!;
    const inflated = concatBytes([
      Uint8Array.from([0x30, bytes[1]! + 1, 0x02, rLength + 1, 0x00]),
      bytes.subarray(4, 4 + rLength),
      bytes.subarray(4 + rLength),
    ]);
    expect(toHex(canonicalDerSignature(parseDerSignature(inflated)))).toBe(VECTOR.signatureDerHex);
    expect(
      verifyScppSignature({
        publicKey: PUBLIC_KEY,
        challenge: VECTOR.challengeHex,
        signatureDer: inflated,
      }),
    ).toBe(true);
  });

  it("rejects a component encoded as a negative integer", () => {
    expect(codeOf(() => parseDerSignature("300a02048000000102020102"))).toBe("SCPP_INVALID_SIGNATURE_ENCODING");
  });

  it("rejects a sequence whose declared length disagrees with the bytes present", () => {
    expect(codeOf(() => parseDerSignature(`${VECTOR.signatureDerHex}00`))).toBe("SCPP_INVALID_SIGNATURE_ENCODING");
    const truncated = VECTOR.signatureDerHex.slice(0, VECTOR.signatureDerHex.length - 2);
    expect(codeOf(() => parseDerSignature(truncated))).toBe("SCPP_INVALID_SIGNATURE_ENCODING");
  });

  it("rejects anything that is not a sequence of two integers", () => {
    for (const malformed of [
      "31450221",
      "3006020101040101",
      "30060201010202",
      "300602000202010101",
      "30",
      "",
    ]) {
      expect(codeOf(() => parseDerSignature(malformed))).toBe("SCPP_INVALID_SIGNATURE_ENCODING");
    }
  });

  it("rejects a long-form length, which no P-256 signature needs", () => {
    expect(codeOf(() => parseDerSignature("30810602010102010101"))).toBe("SCPP_INVALID_SIGNATURE_ENCODING");
  });

  it("rejects a scalar of zero or one at or beyond the group order", () => {
    expect(codeOf(() => parseDerSignature("3006020100020101"))).toBe("SCPP_INVALID_SIGNATURE_ENCODING");
    const order = "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551";
    expect(codeOf(() => parseDerSignature(`3027022100${order}020101`))).toBe("SCPP_INVALID_SIGNATURE_ENCODING");
  });
});

describe("signature verification", () => {
  it("verifies a genuine signature over the rebuilt challenge", () => {
    expect(
      verifyScppSignature({
        publicKey: PUBLIC_KEY,
        challenge: scppV2Challenge(VECTOR.input),
        signatureDer: VECTOR.signatureDerHex,
      }),
    ).toBe(true);
  });

  it("refuses a signature made over a different challenge", () => {
    const otherChallenge = scppV2Challenge({ ...VECTOR.input, amountAtomic: "1000001" });
    expect(
      verifyScppSignature({
        publicKey: PUBLIC_KEY,
        challenge: otherChallenge,
        signatureDer: VECTOR.signatureDerHex,
      }),
    ).toBe(false);
  });

  it("refuses a genuine signature presented against another card's key", () => {
    const foreign = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
    const spki = foreign.publicKey.export({ format: "der", type: "spki" });
    const foreignPoint = spki.subarray(spki.length - 65);
    expect(
      verifyScppSignature({
        publicKey: foreignPoint,
        challenge: VECTOR.challengeHex,
        signatureDer: VECTOR.signatureDerHex,
      }),
    ).toBe(false);
  });

  it("refuses a signature whose r and s were swapped", () => {
    const parsed = parseDerSignature(VECTOR.signatureDerHex);
    const swapped = canonicalDerSignature({ r: parsed.s, s: parsed.r });
    expect(
      verifyScppSignature({
        publicKey: PUBLIC_KEY,
        challenge: VECTOR.challengeHex,
        signatureDer: swapped,
      }),
    ).toBe(false);
  });

  it("throws rather than declining when the challenge is the wrong width", () => {
    expect(
      codeOf(() =>
        verifyScppSignature({
          publicKey: PUBLIC_KEY,
          challenge: VECTOR.challengeHex.slice(0, 62),
          signatureDer: VECTOR.signatureDerHex,
        }),
      ),
    ).toBe("SCPP_INVALID_CHALLENGE");
  });

  it("throws rather than declining when the signature is malformed", () => {
    expect(
      codeOf(() =>
        verifyScppSignature({
          publicKey: PUBLIC_KEY,
          challenge: VECTOR.challengeHex,
          signatureDer: "not-a-signature",
        }),
      ),
    ).toBe("SCPP_INVALID_FIELD");
    expect(
      codeOf(() =>
        verifyScppSignature({
          publicKey: PUBLIC_KEY,
          challenge: VECTOR.challengeHex,
          signatureDer: "300602010102",
        }),
      ),
    ).toBe("SCPP_INVALID_SIGNATURE_ENCODING");
  });

  it("verifies a signature this test made, so the vectors are not the only evidence", () => {
    const input = { ...VECTOR.input, counter: 99, paymentId: "pay_freshly_signed" };
    const challenge = scppV2Challenge(input);
    const signature = sign(null, Buffer.from(challenge), { key: privateKey(), dsaEncoding: "der" });
    expect(verifyScppSignature({ publicKey: PUBLIC_KEY, challenge, signatureDer: signature })).toBe(true);
    expect(
      verifyScppSignature({
        publicKey: PUBLIC_KEY,
        challenge: scppV2Challenge({ ...input, counter: 100 }),
        signatureDer: signature,
      }),
    ).toBe(false);
  });
});

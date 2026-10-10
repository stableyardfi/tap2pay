import { createPublicKey, verify as verifySignature, type KeyObject } from "node:crypto";

import { asBytes, concatBytes, type ByteInput } from "./bytes.js";
import { ScppError } from "./errors.js";

export const SCPP_PUBLIC_KEY_BYTES = 65;
export const SCPP_CHALLENGE_BYTES = 32;

/* The DER header of a prime256v1 SubjectPublicKeyInfo. A card hands back a raw
   uncompressed point and nothing else, so the wrapper is constant and is
   prepended rather than parsed: the only variable is the 65 byte point, and
   OpenSSL rejects a point that is not on the curve when the key is imported. */
const P256_SPKI_PREFIX = Uint8Array.from([
  0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
  0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
]);

const P256_ORDER = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;

/* A canonical component is at most 33 bytes: thirty-two of scalar plus the zero
   DER adds when the top bit is set. The bound here is looser because some cards
   pad further, and the group-order check below is what actually constrains the
   value. It exists only so a hostile caller cannot hand us an arbitrarily long
   integer to walk. */
const MAX_DER_INTEGER_BYTES = 40;

export function importScppPublicKey(publicKey: ByteInput): KeyObject {
  const point = asBytes(publicKey, "publicKey");
  if (point.length !== SCPP_PUBLIC_KEY_BYTES) {
    throw new ScppError(
      "SCPP_INVALID_PUBLIC_KEY",
      `publicKey must be ${SCPP_PUBLIC_KEY_BYTES} bytes and is ${point.length}`,
      "publicKey",
    );
  }
  if (point[0] !== 0x04) {
    throw new ScppError(
      "SCPP_INVALID_PUBLIC_KEY",
      "publicKey must be an uncompressed point beginning 0x04; compressed points are outside the profile",
      "publicKey",
    );
  }
  try {
    return createPublicKey({ key: Buffer.from(concatBytes([P256_SPKI_PREFIX, point])), format: "der", type: "spki" });
  } catch {
    throw new ScppError("SCPP_INVALID_PUBLIC_KEY", "publicKey is not a point on P-256", "publicKey");
  }
}

interface DerSignature {
  readonly r: bigint;
  readonly s: bigint;
}

function readUnsignedInteger(bytes: Uint8Array, offset: number, label: string): { value: bigint; next: number } {
  if (offset + 2 > bytes.length) {
    throw malformedSignature(`the ${label} integer header is truncated`);
  }
  if (bytes[offset] !== 0x02) {
    throw malformedSignature(`the ${label} component is not a DER INTEGER`);
  }
  const length = bytes[offset + 1] as number;
  if ((length & 0x80) !== 0) {
    throw malformedSignature(`the ${label} component uses a long-form length, which no P-256 signature needs`);
  }
  if (length === 0) {
    throw malformedSignature(`the ${label} component is empty`);
  }
  const start = offset + 2;
  const end = start + length;
  if (end > bytes.length) {
    throw malformedSignature(`the ${label} component runs past the end of the signature`);
  }
  const content = bytes.subarray(start, end);
  /* A leading byte with the high bit set is a negative DER INTEGER. Real cards
     pad such a value with 0x00, and some pad more than they need to, so extra
     leading zeros are tolerated; a genuinely negative component is not, because
     the only way to read it as a scalar is to guess. */
  if (((content[0] as number) & 0x80) !== 0) {
    throw malformedSignature(`the ${label} component is a negative integer`);
  }
  if (content.length > MAX_DER_INTEGER_BYTES) {
    throw malformedSignature(`the ${label} component is ${content.length} bytes and cannot be a P-256 scalar`);
  }
  let value = 0n;
  for (const byte of content) {
    value = (value << 8n) | BigInt(byte);
  }
  if (value === 0n || value >= P256_ORDER) {
    throw malformedSignature(`the ${label} component is outside the P-256 group order`);
  }
  return { value, next: end };
}

function malformedSignature(reason: string): ScppError {
  return new ScppError("SCPP_INVALID_SIGNATURE_ENCODING", `signatureDer is malformed: ${reason}`, "signatureDer");
}

export function parseDerSignature(signatureDer: ByteInput): DerSignature {
  const bytes = asBytes(signatureDer, "signatureDer");
  if (bytes.length < 8) {
    throw malformedSignature("it is too short to carry two integers");
  }
  if (bytes[0] !== 0x30) {
    throw malformedSignature("it does not begin with a DER SEQUENCE");
  }
  const declared = bytes[1] as number;
  if ((declared & 0x80) !== 0) {
    throw malformedSignature("the sequence uses a long-form length, which no P-256 signature needs");
  }
  if (declared + 2 !== bytes.length) {
    throw malformedSignature(`the sequence declares ${declared} bytes and ${bytes.length - 2} follow`);
  }
  const r = readUnsignedInteger(bytes, 2, "r");
  const s = readUnsignedInteger(bytes, r.next, "s");
  if (s.next !== bytes.length) {
    throw malformedSignature("trailing bytes follow the second integer");
  }
  return { r: r.value, s: s.value };
}

function encodeUnsignedInteger(value: bigint): Uint8Array {
  let hex = value.toString(16);
  if (hex.length % 2 === 1) {
    hex = `0${hex}`;
  }
  const magnitude = new Uint8Array(hex.length / 2);
  for (let index = 0; index < magnitude.length; index += 1) {
    magnitude[index] = Number.parseInt(hex.slice(index * 2, index * 2 + 2), 16);
  }
  const padded = ((magnitude[0] as number) & 0x80) !== 0 ? concatBytes([new Uint8Array([0x00]), magnitude]) : magnitude;
  return concatBytes([new Uint8Array([0x02, padded.length]), padded]);
}

/* A card that pads a component with more zeros than DER requires produces a
   signature OpenSSL refuses to parse even though the scalars are correct.
   Re-encoding from the parsed scalars is what makes such a card work without
   the verifier having to accept whatever bytes it is handed. */
export function canonicalDerSignature(signature: DerSignature): Uint8Array {
  const body = concatBytes([encodeUnsignedInteger(signature.r), encodeUnsignedInteger(signature.s)]);
  return concatBytes([new Uint8Array([0x30, body.length]), body]);
}

export interface VerifyScppSignatureInput {
  readonly publicKey: ByteInput;
  readonly challenge: ByteInput;
  readonly signatureDer: ByteInput;
}

/* Malformed input throws and a well formed signature that does not verify
   returns false. The distinction matters operationally: the first is a broken
   reader or a corrupted record and should be investigated, the second is a
   decline the cardholder is standing there waiting for. */
export function verifyScppSignature(input: VerifyScppSignatureInput): boolean {
  const key = importScppPublicKey(input.publicKey);
  const challenge = asBytes(input.challenge, "challenge");
  if (challenge.length !== SCPP_CHALLENGE_BYTES) {
    throw new ScppError(
      "SCPP_INVALID_CHALLENGE",
      `challenge must be ${SCPP_CHALLENGE_BYTES} bytes and is ${challenge.length}`,
      "challenge",
    );
  }
  const canonical = canonicalDerSignature(parseDerSignature(input.signatureDer));
  /* The challenge is passed as the message, not as a digest. A null algorithm
     applies the key's default digest -- SHA-256 for P-256 -- so this verifies
     the signature over SHA-256 of the challenge, and the challenge is itself
     the SHA-256 of the encoded message. Two rounds of hashing is correct and
     deliberate: a standard P-256 signing API hashes the message it is handed
     before signing it, so a card handed the challenge signs SHA-256 of it. Do not "fix" this into a raw
     digest verification: it would reject every genuine signature. */
  return verifySignature(null, Buffer.from(challenge), { key, dsaEncoding: "der" }, Buffer.from(canonical));
}

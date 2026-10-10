import { concatBytes, fromHex, toHex } from "./bytes.js";
import { ScppError } from "./errors.js";

/* The restricted profile, stated once and enforced everywhere below.

   This is deliberately not a BER implementation. A general parser accepts
   constructed tags, indefinite lengths, long-form lengths and tag numbers of
   any width, and every one of those is a second way to encode the same message
   -- which is the exact failure the profile exists to remove. Two
   implementations that both "speak TLV" must produce byte-identical output for
   identical field values, so anything outside the profile is rejected rather
   than parsed. */
export const TLV_MIN_TAG_BYTES = 1;
export const TLV_MAX_TAG_BYTES = 2;
export const TLV_MAX_VALUE_BYTES = 127;

export interface TlvField {
  readonly tag: string;
  readonly value: Uint8Array;
}

/* A one-byte tag whose low five bits are all set says "another tag byte
   follows" in BER; a two-byte tag must therefore have that marker, and a
   subsequent byte with the continuation bit set would mean a third byte, which
   the profile does not allow. */
export function assertProfileTag(tag: string): void {
  if (typeof tag !== "string" || !/^(?:[0-9A-F]{2}){1,2}$/.test(tag)) {
    throw new ScppError(
      "SCPP_TAG_OUT_OF_PROFILE",
      `tag ${String(tag)} must be one or two bytes of upper-case hexadecimal`,
    );
  }
  const bytes = fromHex(tag, "tag");
  const first = bytes[0] as number;
  if ((first & 0x1f) === 0x1f) {
    if (bytes.length !== 2) {
      throw new ScppError("SCPP_TAG_OUT_OF_PROFILE", `tag ${tag} announces a second tag byte that is absent`);
    }
    if (((bytes[1] as number) & 0x80) !== 0) {
      throw new ScppError("SCPP_TAG_OUT_OF_PROFILE", `tag ${tag} announces a third tag byte, which is outside the profile`);
    }
  } else if (bytes.length !== 1) {
    throw new ScppError("SCPP_TAG_OUT_OF_PROFILE", `tag ${tag} must be a single byte when it does not announce a second`);
  }
  if ((first & 0x20) !== 0) {
    throw new ScppError("SCPP_TAG_OUT_OF_PROFILE", `tag ${tag} is constructed, and the profile carries primitive values only`);
  }
}

export function encodeTlv(fields: readonly TlvField[]): Uint8Array {
  if (!Array.isArray(fields) || fields.length === 0) {
    throw new ScppError("SCPP_MALFORMED_TLV", "a TLV message must carry at least one field");
  }
  const seen = new Set<string>();
  const chunks: Uint8Array[] = [];
  for (const field of fields) {
    assertProfileTag(field.tag);
    if (seen.has(field.tag)) {
      throw new ScppError("SCPP_MALFORMED_TLV", `tag ${field.tag} appears more than once`);
    }
    seen.add(field.tag);
    if (!(field.value instanceof Uint8Array)) {
      throw new ScppError("SCPP_MALFORMED_TLV", `tag ${field.tag} must carry a Uint8Array value`);
    }
    if (field.value.length > TLV_MAX_VALUE_BYTES) {
      throw new ScppError(
        "SCPP_LENGTH_OUT_OF_PROFILE",
        `tag ${field.tag} carries ${field.value.length} bytes and the profile allows short-form lengths only (at most ${TLV_MAX_VALUE_BYTES})`,
      );
    }
    chunks.push(fromHex(field.tag, "tag"), new Uint8Array([field.value.length]), field.value);
  }
  return concatBytes(chunks);
}

/* The decoder exists so a round trip can prove the encoder lossless, and so a
   published vector can be checked field by field. Nothing on the payment path
   parses a message it did not build: the server rebuilds the message from the
   payment's own values and compares, it never trusts bytes from a reader. */
export function decodeTlv(bytes: Uint8Array): TlvField[] {
  if (!(bytes instanceof Uint8Array)) {
    throw new ScppError("SCPP_MALFORMED_TLV", "a TLV message must be a Uint8Array");
  }
  const fields: TlvField[] = [];
  const seen = new Set<string>();
  let offset = 0;
  while (offset < bytes.length) {
    const first = bytes[offset] as number;
    const tagLength = (first & 0x1f) === 0x1f ? 2 : 1;
    if (offset + tagLength > bytes.length) {
      throw new ScppError("SCPP_MALFORMED_TLV", `truncated tag at offset ${offset}`);
    }
    const tag = toHex(bytes.subarray(offset, offset + tagLength)).toUpperCase();
    assertProfileTag(tag);
    if (seen.has(tag)) {
      throw new ScppError("SCPP_MALFORMED_TLV", `tag ${tag} appears more than once`);
    }
    seen.add(tag);
    offset += tagLength;
    if (offset >= bytes.length) {
      throw new ScppError("SCPP_MALFORMED_TLV", `tag ${tag} has no length byte`);
    }
    const length = bytes[offset] as number;
    if (length > TLV_MAX_VALUE_BYTES) {
      throw new ScppError(
        "SCPP_LENGTH_OUT_OF_PROFILE",
        `tag ${tag} uses a long-form length byte 0x${length.toString(16)}, which is outside the profile`,
      );
    }
    offset += 1;
    if (offset + length > bytes.length) {
      throw new ScppError("SCPP_MALFORMED_TLV", `tag ${tag} claims ${length} bytes and the message ends early`);
    }
    fields.push({ tag, value: bytes.slice(offset, offset + length) });
    offset += length;
  }
  if (fields.length === 0) {
    throw new ScppError("SCPP_MALFORMED_TLV", "a TLV message must carry at least one field");
  }
  return fields;
}

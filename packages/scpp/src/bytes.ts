import { ScppError } from "./errors.js";

const HEX_PATTERN = /^(?:[0-9a-fA-F]{2})*$/;

export type ByteInput = Uint8Array | string;

export function fromHex(value: string, field: string): Uint8Array {
  if (!HEX_PATTERN.test(value)) {
    throw new ScppError("SCPP_INVALID_FIELD", `${field} must be an even-length hexadecimal string`, field);
  }
  const bytes = new Uint8Array(value.length / 2);
  for (let index = 0; index < bytes.length; index += 1) {
    bytes[index] = Number.parseInt(value.slice(index * 2, index * 2 + 2), 16);
  }
  return bytes;
}

export function toHex(bytes: Uint8Array): string {
  let hex = "";
  for (const byte of bytes) {
    hex += byte.toString(16).padStart(2, "0");
  }
  return hex;
}

/* Byte-carrying inputs arrive either from our own code (Uint8Array) or from a
   reader over JSON (hex). Both are accepted; anything else is rejected rather
   than coerced, because a silently stringified object would hash to a valid
   looking challenge that no card ever signed. */
export function asBytes(value: ByteInput, field: string): Uint8Array {
  if (value instanceof Uint8Array) {
    return value;
  }
  if (typeof value === "string") {
    return fromHex(value, field);
  }
  throw new ScppError("SCPP_INVALID_FIELD", `${field} must be a Uint8Array or a hexadecimal string`, field);
}

export function concatBytes(chunks: readonly Uint8Array[]): Uint8Array {
  let total = 0;
  for (const chunk of chunks) {
    total += chunk.length;
  }
  const out = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    out.set(chunk, offset);
    offset += chunk.length;
  }
  return out;
}

export function bytesEqual(left: Uint8Array, right: Uint8Array): boolean {
  if (left.length !== right.length) {
    return false;
  }
  for (let index = 0; index < left.length; index += 1) {
    if (left[index] !== right[index]) {
      return false;
    }
  }
  return true;
}

/* Binary coded decimal, one digit per nibble, because the industry tags in this
   profile (amount, currency, date, time) are numeric-compressed in EMV and a
   bridge to a conventional terminal must read them without a conversion step.
   The input is a digit string throughout: no numeric type is ever involved, so
   no monetary value passes through a JavaScript float. */
export function packBcd(digits: string, byteLength: number, field: string): Uint8Array {
  if (!/^\d*$/.test(digits)) {
    throw new ScppError("SCPP_INVALID_FIELD", `${field} must contain digits only`, field);
  }
  const width = byteLength * 2;
  if (digits.length > width) {
    throw new ScppError("SCPP_INVALID_FIELD", `${field} must be at most ${width} digits`, field);
  }
  const padded = digits.padStart(width, "0");
  const bytes = new Uint8Array(byteLength);
  for (let index = 0; index < byteLength; index += 1) {
    const high = Number.parseInt(padded[index * 2] as string, 10);
    const low = Number.parseInt(padded[index * 2 + 1] as string, 10);
    bytes[index] = (high << 4) | low;
  }
  return bytes;
}

export function unpackBcd(bytes: Uint8Array, field: string): string {
  let digits = "";
  for (const byte of bytes) {
    const high = byte >> 4;
    const low = byte & 0x0f;
    if (high > 9 || low > 9) {
      throw new ScppError("SCPP_INVALID_FIELD", `${field} is not valid binary coded decimal`, field);
    }
    digits += `${high}${low}`;
  }
  return digits;
}

/* An atomic token amount is a uint256 on chain, so it is carried as one:
   BigInt, never Number, so the value is exact at every width the chain admits.
   The input and output are decimal strings, and a value that does not fit the
   declared width is rejected -- a monetary value is never narrowed to make it
   fit. */
export function packUnsignedDecimal(value: string, byteLength: number, field: string): Uint8Array {
  let magnitude: bigint;
  try {
    magnitude = BigInt(value);
  } catch {
    throw new ScppError("SCPP_INVALID_FIELD", `${field} must be an unsigned integer string`, field);
  }
  if (magnitude < 0n || magnitude >= 1n << BigInt(byteLength * 8)) {
    throw new ScppError("SCPP_INVALID_FIELD", `${field} does not fit ${byteLength} bytes`, field);
  }
  const bytes = new Uint8Array(byteLength);
  for (let index = byteLength - 1; index >= 0; index -= 1) {
    bytes[index] = Number(magnitude & 0xffn);
    magnitude >>= 8n;
  }
  return bytes;
}

export function unpackUnsignedDecimal(bytes: Uint8Array): string {
  let magnitude = 0n;
  for (const byte of bytes) {
    magnitude = (magnitude << 8n) | BigInt(byte);
  }
  return magnitude.toString(10);
}

export function packUint32(value: number, field: string): Uint8Array {
  if (!Number.isInteger(value) || value < 0 || value > 0xffffffff) {
    throw new ScppError("SCPP_INVALID_FIELD", `${field} must be an integer between 0 and 4294967295`, field);
  }
  return new Uint8Array([(value >>> 24) & 0xff, (value >>> 16) & 0xff, (value >>> 8) & 0xff, value & 0xff]);
}

export function unpackUint32(bytes: Uint8Array): number {
  return ((bytes[0] as number) * 0x1000000) + (((bytes[1] as number) << 16) | ((bytes[2] as number) << 8) | (bytes[3] as number));
}

export function packAscii(value: string, field: string): Uint8Array {
  const bytes = new Uint8Array(value.length);
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code < 0x20 || code > 0x7e) {
      throw new ScppError("SCPP_INVALID_FIELD", `${field} must contain printable ASCII only`, field);
    }
    bytes[index] = code;
  }
  return bytes;
}

export function unpackAscii(bytes: Uint8Array, field: string): string {
  let value = "";
  for (const byte of bytes) {
    if (byte < 0x20 || byte > 0x7e) {
      throw new ScppError("SCPP_INVALID_FIELD", `${field} must contain printable ASCII only`, field);
    }
    value += String.fromCharCode(byte);
  }
  return value;
}

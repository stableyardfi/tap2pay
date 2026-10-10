import {
  packAscii,
  packBcd,
  packUint32,
  packUnsignedDecimal,
  unpackAscii,
  unpackBcd,
  unpackUint32,
  unpackUnsignedDecimal,
} from "./bytes.js";
import { ScppError, invalidField } from "./errors.js";
import { assertProfileTag } from "./tlv.js";

export const SCPP_VERSION_V2 = 2;

/* The rule this profile applies to every field, recorded here because it is the
   test to apply when extending it rather than a set of choices to infer.

   An industry tag is used only where BOTH the meaning and the encoding match,
   so that a conventional reader decodes the field correctly. Where either
   differs, the field takes a proprietary tag.

   The asymmetry is what makes the rule worth stating. An unfamiliar proprietary
   tag fails loudly in a reader, a bridge or a debugging tool that does not know
   it. A familiar industry tag carrying something else does not fail at all: it
   decodes under the encoding the registry defines and produces a plausible
   wrong answer. For a profile meant to be published, the second is the
   dangerous one, so a tag we cannot honour exactly is a tag we do not use. */

/* Tags held for a future profile that can honour them exactly, defined and
   never emitted in v2. Reserving one costs a line now and avoids a second
   version of the profile later; it also means an encoder handed one today
   fails loudly instead of silently dropping a field a reader believed was
   signed. This record is the single source of the reserved set, and
   assertProfileIsCoherent asserts every entry is absent from SCPP_TAGS. */
export const SCPP_RESERVED_TAGS = {
  pinCommitment: {
    tag: "DF13",
    reason:
      "reserved for the PIN commitment, so a later version can bind a PIN to one authorisation without a second profile",
  },
  fiatCurrency: {
    tag: "5F2A",
    reason:
      "the EMV transaction currency code, reserved because a Stableyard payment has no fiat currency to put in it: a payment session is denominated in a token end to end and carries no ISO 4217 code anywhere",
  },
  fiatAmount: {
    tag: "9F02",
    reason:
      "the EMV authorised amount, reserved because its registered encoding is n12 BCD and an atomic token amount is a 32-byte unsigned integer; a conventional reader would decode ours as a number and be wrong",
  },
  terminalId: {
    tag: "9F1C",
    reason:
      "the EMV terminal identification, reserved because its registered encoding is ans8 and a device identifier we do not issue does not fit eight characters",
  },
  merchantId: {
    tag: "9F16",
    reason:
      "the EMV merchant identifier, reserved because its registered encoding is ans15 and a Stableyard account identifier does not fit fifteen characters",
  },
  /* The three tags v1 emitted and v2 does not. They are retired rather than
     freed: reusing one would let a v1 message decode under v2 as a different
     field, which is the silent wrong answer the tag rule above exists to
     prevent. A v1 encoder pointed at a v2 verifier now fails by name. */
  serverNonceRetired: {
    tag: "DF03",
    reason:
      "retired with v1: the freshness value is now the terminal's unpredictable number under 9F37, because a server-issued nonce cost a round trip before the card could sign",
  },
  actionIdRetired: {
    tag: "DF11",
    reason:
      "retired with v1: the payment session in DF10 already names the attempt being approved, and binding the signed bytes to a server-created action is what forced the card to wait for one",
  },
  expiryRetired: {
    tag: "DF12",
    reason:
      "retired with v1: freshness is the card counter and the server's own authorisation window, neither of which a terminal-asserted expiry could strengthen",
  },
} as const;

export const SCPP_TAG_PIN_COMMITMENT_RESERVED = SCPP_RESERVED_TAGS.pinCommitment.tag;
export const SCPP_TAG_FIAT_CURRENCY_RESERVED = SCPP_RESERVED_TAGS.fiatCurrency.tag;
export const SCPP_TAG_FIAT_AMOUNT_RESERVED = SCPP_RESERVED_TAGS.fiatAmount.tag;
export const SCPP_TAG_TERMINAL_ID_RESERVED = SCPP_RESERVED_TAGS.terminalId.tag;
export const SCPP_TAG_MERCHANT_ID_RESERVED = SCPP_RESERVED_TAGS.merchantId.tag;

/* Three industry tags survive the rule above. 9A and 9F21 are n6 BCD here
   exactly as they are in the registry, and 9F37 carries four binary bytes of
   terminal-generated unpredictability exactly as the registry defines it, so a
   conventional reader decodes all three correctly. Everything else is
   proprietary.

   9F37 is the tag this profile most wants to honour rather than approximate:
   it is what makes the message one an EMV terminal already knows how to
   assemble, and it is what removes the round trip -- the terminal supplies the
   freshness itself instead of asking us for it.

   Proprietary allocation. DF01-DF0F carry the profile's own facts about the
   message and the money it binds; DF10-DF1F identify the one authorisation
   being approved -- which payment session, and later under which PIN. Within a
   block, tags are allocated in the order fields joined the profile, not in
   field order: the
   order is semantic and lives in SCPP_V2_FIELD_ORDER alone. */
export const SCPP_TAGS = {
  amountAtomic: "DF05",
  assetSymbol: "DF04",
  transactionDate: "9A",
  transactionTime: "9F21",
  deviceId: "DF06",
  receivingAccountId: "DF07",
  version: "DF01",
  counter: "DF02",
  unpredictableNumber: "9F37",
  paymentId: "DF10",
} as const;

export type ScppFieldName = keyof typeof SCPP_TAGS;

/* The field order is part of the profile, not an implementation detail: it is
   what makes the encoding of a given set of values a single byte string, and it
   is what an independent reader has to reproduce. This array is the only place
   it is written down, and every encoder, decoder and vector walks it.

   A reader who knows EMV will look for 9F02 and 5F2A in the first two places
   and find proprietary tags instead; the rule at the tag table says why. The
   asset stays adjacent to the amount because an atomic amount says nothing
   without the asset it counts, and the two must be signed together or neither
   is worth signing. */
export const SCPP_V2_FIELD_ORDER: readonly ScppFieldName[] = [
  "amountAtomic",
  "assetSymbol",
  "transactionDate",
  "transactionTime",
  "deviceId",
  "receivingAccountId",
  "version",
  "counter",
  "unpredictableNumber",
  "paymentId",
] as const;

/* The two-digit vocabulary a terminal, a receipt and an operator already read.
   The PIN codes are defined now for the same reason DF13 is reserved: the set
   is published with v2 so adding PIN adds no new code to agree on. */
export const SCPP_RESPONSE_CODES = {
  approved: "00",
  insufficientFunds: "51",
  restrictedCard: "62",
  expired: "54",
  duplicate: "94",
  incorrectPin: "55",
  pinTriesExceeded: "75",
} as const;

export type ScppResponseCode = (typeof SCPP_RESPONSE_CODES)[keyof typeof SCPP_RESPONSE_CODES];

/* The amount is a uint256 and is carried at the width the chain uses. That is
   the ceiling, and it is a real one rather than a chosen one: a token quantity
   larger than 2^256-1 cannot exist on any chain we settle on, so nothing that
   could be paid is refused, and a value above it is rejected rather than
   narrowed. */
export const SCPP_AMOUNT_BYTES = 32;
export const SCPP_AMOUNT_MAX_DIGITS = 78;
export const SCPP_AMOUNT_MAX_ATOMIC =
  "115792089237316195423570985008687907853269984665640564039457584007913129639935";
export const SCPP_ASSET_SYMBOL_MAX_LENGTH = 16;
export const SCPP_UNPREDICTABLE_NUMBER_BYTES = 4;
export const SCPP_DEVICE_ID_MAX_LENGTH = 32;
export const SCPP_ACCOUNT_ID_MAX_LENGTH = 64;
export const SCPP_IDENTIFIER_MAX_LENGTH = 64;

/* Underscore is in the set because our own identifiers use it (card_…, pay_…).
   The set is otherwise the house identifier charset: no whitespace, no control
   bytes, nothing that changes meaning between a URL, a log line and a receipt. */
const IDENTIFIER_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:@/_-]*$/;
const AMOUNT_PATTERN = /^(?:0|[1-9][0-9]*)$/;
const ASSET_SYMBOL_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]*$/;
const DIGITS_ONLY = /^[0-9]+$/;

function assertString(value: unknown, field: string): string {
  if (typeof value !== "string") {
    throw invalidField(field, "must be a string");
  }
  return value;
}

function assertIdentifier(value: unknown, field: string, maxLength: number): string {
  const text = assertString(value, field);
  if (text.length === 0 || text.length > maxLength) {
    throw invalidField(field, `must be between 1 and ${maxLength} characters`);
  }
  if (!IDENTIFIER_PATTERN.test(text)) {
    throw invalidField(field, "must start with an alphanumeric character and use only A-Z a-z 0-9 . _ - : @ /");
  }
  return text;
}

function assertDigits(value: unknown, field: string, length: number): string {
  const text = assertString(value, field);
  if (text.length !== length || !DIGITS_ONLY.test(text)) {
    throw invalidField(field, `must be exactly ${length} digits`);
  }
  return text;
}

const DAYS_IN_MONTH = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];

function isLeapYear(year: number): boolean {
  return (year % 4 === 0 && year % 100 !== 0) || year % 400 === 0;
}

function assertCalendarDate(year: number, month: number, day: number, field: string): void {
  if (month < 1 || month > 12) {
    throw invalidField(field, "carries a month outside 01-12");
  }
  const monthLength = month === 2 && isLeapYear(year) ? 29 : (DAYS_IN_MONTH[month - 1] as number);
  if (day < 1 || day > monthLength) {
    throw invalidField(field, `carries a day outside 01-${String(monthLength).padStart(2, "0")} for that month`);
  }
}

function assertClockTime(hour: number, minute: number, second: number, field: string): void {
  if (hour > 23 || minute > 59 || second > 59) {
    throw invalidField(field, "carries a time outside 000000-235959");
  }
}

export interface ScppFieldCodec {
  readonly tag: string;
  readonly encode: (value: unknown) => Uint8Array;
  readonly decode: (value: Uint8Array) => unknown;
}

/* The amount authorised, in the smallest indivisible unit of what is being
   paid, taken verbatim from the terms the terminal states. The meaning is
   the one 9F02 carries in the registry, but the encoding is not: twelve BCD
   digits cannot hold a token amount, and truncating a monetary value to fit an
   encoding is not a trade anyone gets to make. So the amount is a 32-byte
   unsigned big-endian integer -- the width it already has on chain -- under a
   proprietary tag, and 9F02 is reserved. A reader that knows 9F02 would decode
   these thirty-two bytes as n12 and hand someone a number; under DF05 it stops
   instead.

   The value is a decimal string from input to wire and back, converted through
   BigInt. No monetary value is ever a JavaScript number. */
const amountCodec: ScppFieldCodec = {
  tag: SCPP_TAGS.amountAtomic,
  encode(value) {
    const text = assertString(value, "amountAtomic");
    if (!AMOUNT_PATTERN.test(text)) {
      throw invalidField("amountAtomic", "must be an unsigned atomic integer string with no leading zeros");
    }
    if (text.length > SCPP_AMOUNT_MAX_DIGITS || BigInt(text) > BigInt(SCPP_AMOUNT_MAX_ATOMIC)) {
      throw invalidField("amountAtomic", `must be at most ${SCPP_AMOUNT_MAX_ATOMIC}, the largest amount a chain can hold`);
    }
    return packUnsignedDecimal(text, SCPP_AMOUNT_BYTES, "amountAtomic");
  },
  decode(value) {
    if (value.length !== SCPP_AMOUNT_BYTES) {
      throw invalidField("amountAtomic", `must be ${SCPP_AMOUNT_BYTES} bytes`);
    }
    return unpackUnsignedDecimal(value);
  },
};

/* The symbol the payment itself carries, byte for byte. It is not case folded
   and not mapped to any registry: the server rebuilds this field from the
   payment's own destinationAssetSymbol, so the only thing that has to be true
   is that the reader signed what the payment says. */
const assetSymbolCodec: ScppFieldCodec = {
  tag: SCPP_TAGS.assetSymbol,
  encode(value) {
    const text = assertString(value, "assetSymbol");
    if (text.length === 0 || text.length > SCPP_ASSET_SYMBOL_MAX_LENGTH) {
      throw invalidField("assetSymbol", `must be between 1 and ${SCPP_ASSET_SYMBOL_MAX_LENGTH} characters`);
    }
    if (!ASSET_SYMBOL_PATTERN.test(text)) {
      throw invalidField("assetSymbol", "must start with an alphanumeric character and use only A-Z a-z 0-9 . _ -");
    }
    return packAscii(text, "assetSymbol");
  },
  decode(value) {
    return unpackAscii(value, "assetSymbol");
  },
};

const dateCodec: ScppFieldCodec = {
  tag: SCPP_TAGS.transactionDate,
  encode(value) {
    const text = assertDigits(value, "transactionDate", 6);
    assertCalendarDate(
      2000 + Number(text.slice(0, 2)),
      Number(text.slice(2, 4)),
      Number(text.slice(4, 6)),
      "transactionDate",
    );
    return packBcd(text, 3, "transactionDate");
  },
  decode(value) {
    return unpackBcd(value, "transactionDate");
  },
};

const timeCodec: ScppFieldCodec = {
  tag: SCPP_TAGS.transactionTime,
  encode(value) {
    const text = assertDigits(value, "transactionTime", 6);
    assertClockTime(Number(text.slice(0, 2)), Number(text.slice(2, 4)), Number(text.slice(4, 6)), "transactionTime");
    return packBcd(text, 3, "transactionTime");
  },
  decode(value) {
    return unpackBcd(value, "transactionTime");
  },
};

/* The device identifier is self-asserted by the reader and carries no authority
   whatsoever. It cannot redirect money, because the destination is the
   receiving account, which comes from the payment we created. What signing it
   buys is that the reader is committed to whatever it claimed to be, which is
   what a receipt and a dispute need.

   Both this field and the receiving account below are proprietary for the same
   reason as the amount: the industry tags that carry these meanings, 9F1C and
   9F16, are registered as ans8 and ans15, and neither a device identifier we do
   not issue nor a Stableyard account identifier fits those widths. A future
   bridge derives its own eight- and fifteen-character values for the industry
   tags rather than changing what is signed here. */
const deviceIdCodec: ScppFieldCodec = {
  tag: SCPP_TAGS.deviceId,
  encode(value) {
    return packAscii(assertIdentifier(value, "deviceId", SCPP_DEVICE_ID_MAX_LENGTH), "deviceId");
  },
  decode(value) {
    return unpackAscii(value, "deviceId");
  },
};

const receivingAccountCodec: ScppFieldCodec = {
  tag: SCPP_TAGS.receivingAccountId,
  encode(value) {
    return packAscii(assertIdentifier(value, "receivingAccountId", SCPP_ACCOUNT_ID_MAX_LENGTH), "receivingAccountId");
  },
  decode(value) {
    return unpackAscii(value, "receivingAccountId");
  },
};

const versionCodec: ScppFieldCodec = {
  tag: SCPP_TAGS.version,
  encode(value) {
    if (value !== SCPP_VERSION_V2) {
      throw invalidField("version", `must be ${SCPP_VERSION_V2} for this profile`);
    }
    return new Uint8Array([SCPP_VERSION_V2]);
  },
  decode(value) {
    if (value.length !== 1) {
      throw invalidField("version", "must be a single byte");
    }
    return value[0] as number;
  },
};

/* Four bytes, not the two an EMV application transaction counter uses. The
   industry width exists because cards were small; a counter that wraps is a
   counter that lets a signature be replayed, and the verification rule is
   strictly-greater-than, so wrapping would strand the card instead. */
const counterCodec: ScppFieldCodec = {
  tag: SCPP_TAGS.counter,
  encode(value) {
    if (typeof value !== "number") {
      throw invalidField("counter", "must be a number");
    }
    return packUint32(value, "counter");
  },
  decode(value) {
    if (value.length !== 4) {
      throw invalidField("counter", "must be four bytes");
    }
    return unpackUint32(value);
  },
};

/* Four bytes of terminal-generated randomness, the EMV unpredictable number at
   its registered tag, width and encoding.

   It is generated by the reader rather than by us, and that single fact is what
   makes a tap one round trip instead of two: a server-issued nonce cannot exist
   before the server has been told who is paying, and at a counter the card is
   what tells it. The freshness lost by moving the value to the reader is not
   the value that was protecting anything -- replay is refused by the card
   counter, which is monotonic and checked globally per card. What the
   unpredictable number buys is the other property: a reader that cannot predict
   what it will be asked to sign cannot have a card sign future transactions
   during brief physical access. EMV settled here for the same reason, on the
   same four bytes.

   Narrower than the thirty-two bytes v1 used, and deliberately so: the width is
   the registry's, and a value this profile could not encode exactly is a value
   it would have to carry under a proprietary tag, which is what the tag rule
   above exists to avoid. */
const unpredictableNumberCodec: ScppFieldCodec = {
  tag: SCPP_TAGS.unpredictableNumber,
  encode(value) {
    const text = assertString(value, "unpredictableNumber");
    if (!new RegExp(`^[0-9a-fA-F]{${SCPP_UNPREDICTABLE_NUMBER_BYTES * 2}}$`).test(text)) {
      throw invalidField(
        "unpredictableNumber",
        `must be ${SCPP_UNPREDICTABLE_NUMBER_BYTES * 2} hexadecimal characters`,
      );
    }
    const bytes = new Uint8Array(SCPP_UNPREDICTABLE_NUMBER_BYTES);
    for (let index = 0; index < SCPP_UNPREDICTABLE_NUMBER_BYTES; index += 1) {
      bytes[index] = Number.parseInt(text.slice(index * 2, index * 2 + 2), 16);
    }
    return bytes;
  },
  decode(value) {
    if (value.length !== SCPP_UNPREDICTABLE_NUMBER_BYTES) {
      throw invalidField("unpredictableNumber", `must be ${SCPP_UNPREDICTABLE_NUMBER_BYTES} bytes`);
    }
    let hex = "";
    for (const byte of value) {
      hex += byte.toString(16).padStart(2, "0");
    }
    return hex;
  },
};

const paymentIdCodec: ScppFieldCodec = {
  tag: SCPP_TAGS.paymentId,
  encode(value) {
    return packAscii(assertIdentifier(value, "paymentId", SCPP_IDENTIFIER_MAX_LENGTH), "paymentId");
  },
  decode(value) {
    return unpackAscii(value, "paymentId");
  },
};

export const SCPP_V2_FIELD_CODECS: Readonly<Record<ScppFieldName, ScppFieldCodec>> = {
  amountAtomic: amountCodec,
  assetSymbol: assetSymbolCodec,
  transactionDate: dateCodec,
  transactionTime: timeCodec,
  deviceId: deviceIdCodec,
  receivingAccountId: receivingAccountCodec,
  version: versionCodec,
  counter: counterCodec,
  unpredictableNumber: unpredictableNumberCodec,
  paymentId: paymentIdCodec,
};

export function assertProfileIsCoherent(): void {
  const names = new Set(SCPP_V2_FIELD_ORDER);
  if (names.size !== SCPP_V2_FIELD_ORDER.length) {
    throw new ScppError("SCPP_MALFORMED_TLV", "the field order repeats a field");
  }
  for (const name of Object.keys(SCPP_TAGS) as ScppFieldName[]) {
    if (!names.has(name)) {
      throw new ScppError("SCPP_MISSING_FIELD", `${name} has a tag but no place in the field order`);
    }
    assertProfileTag(SCPP_TAGS[name]);
  }
  for (const { tag, reason } of Object.values(SCPP_RESERVED_TAGS)) {
    assertProfileTag(tag);
    if ((Object.values(SCPP_TAGS) as string[]).includes(tag)) {
      throw new ScppError("SCPP_RESERVED_TAG", `${tag} is ${reason}, and must not be emitted`);
    }
  }
}

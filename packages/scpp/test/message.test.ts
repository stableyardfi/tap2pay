import { createHash } from "node:crypto";

import { describe, expect, it } from "vitest";

import {
  assertProfileIsCoherent,
  buildScppV2Message,
  decodeScppV2Message,
  decodeTlv,
  encodeScppV2Message,
  fromHex,
  SCPP_RESERVED_TAGS,
  SCPP_TAG_FIAT_CURRENCY_RESERVED,
  SCPP_TAG_PIN_COMMITMENT_RESERVED,
  SCPP_TAGS,
  SCPP_AMOUNT_MAX_ATOMIC,
  SCPP_V2_FIELD_ORDER,
  SCPP_VERSION_V2,
  ScppError,
  scppV2Challenge,
  toHex,
  type ScppV2MessageInput,
} from "../src/index.js";

const BASE: ScppV2MessageInput = {
  amountAtomic: "1000000",
  assetSymbol: "USDC",
  transactionDate: "260401",
  transactionTime: "143005",
  deviceId: "reader-01",
  receivingAccountId: "acct_01HZY8QK3MREADER",
  counter: 1,
  unpredictableNumber: "3f1a9c04",
  paymentId: "pay_01HZY8QK3M7T2V",
};

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

function withField<K extends keyof ScppV2MessageInput>(field: K, value: unknown): ScppV2MessageInput {
  return { ...BASE, [field]: value } as ScppV2MessageInput;
}

describe("the profile itself", () => {
  it("gives every tagged field a place in the single declared order", () => {
    expect(() => assertProfileIsCoherent()).not.toThrow();
    expect([...SCPP_V2_FIELD_ORDER]).toEqual([
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
    ]);
  });

  it("uses the tags the profile publishes", () => {
    expect(SCPP_TAGS).toEqual({
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
    });
  });

  it("reserves every tag it cannot honour exactly and emits none of them", () => {
    expect(Object.values(SCPP_RESERVED_TAGS).map((entry) => entry.tag).sort()).toEqual([
      "5F2A",
      "9F02",
      "9F16",
      "9F1C",
      "DF03",
      "DF11",
      "DF12",
      "DF13",
    ]);
    expect(SCPP_TAG_PIN_COMMITMENT_RESERVED).toBe("DF13");
    expect(SCPP_TAG_FIAT_CURRENCY_RESERVED).toBe("5F2A");
    const encoded = toHex(encodeScppV2Message(BASE));
    for (const { tag } of Object.values(SCPP_RESERVED_TAGS)) {
      expect(Object.values(SCPP_TAGS)).not.toContain(tag);
      expect(encoded).not.toContain(tag.toLowerCase());
    }
  });

  /* The rule the profile states: an industry tag is used only where both the
     meaning and the encoding match. 9A and 9F21 are n6 BCD and 9F37 is four
     binary bytes, each exactly as the registry defines them; every other field
     is proprietary, so nothing that knows the registry can decode one of ours
     into a plausible wrong answer. */
  it("uses an industry tag only where the registry encoding is honoured exactly", () => {
    const industryTags = Object.values(SCPP_TAGS).filter((tag) => !tag.startsWith("DF"));
    expect(industryTags.sort()).toEqual(["9A", "9F21", "9F37"]);
    const fields = decodeTlv(encodeScppV2Message(BASE));
    for (const name of ["transactionDate", "transactionTime"] as const) {
      expect(fields.find((field) => field.tag === SCPP_TAGS[name])?.value).toHaveLength(3);
    }
    expect(fields.find((field) => field.tag === SCPP_TAGS.unpredictableNumber)?.value).toHaveLength(4);
  });

  it("denominates the amount in an asset the payment carries, not in a fiat currency", () => {
    expect(SCPP_TAGS.assetSymbol.startsWith("DF")).toBe(true);
    expect(SCPP_V2_FIELD_ORDER.indexOf("assetSymbol")).toBe(SCPP_V2_FIELD_ORDER.indexOf("amountAtomic") + 1);
  });
});

describe("encoding", () => {
  /* Built by hand from the tag table rather than from the encoder, so a change
     to how the encoder walks its fields cannot quietly redefine the wire
     format. */
  it("matches a message assembled field by field", () => {
    const expected = [
      "df05", "20", "00000000000000000000000000000000000000000000000000000000000f4240",
      "df04", "04", Buffer.from("USDC", "ascii").toString("hex"),
      "9a", "03", "260401",
      "9f21", "03", "143005",
      "df06", "09", Buffer.from("reader-01", "ascii").toString("hex"),
      "df07", "15", Buffer.from("acct_01HZY8QK3MREADER", "ascii").toString("hex"),
      "df01", "01", "02",
      "df02", "04", "00000001",
      "9f37", "04", BASE.unpredictableNumber,
      "df10", "12", Buffer.from("pay_01HZY8QK3M7T2V", "ascii").toString("hex"),
    ].join("");
    expect(toHex(encodeScppV2Message(BASE))).toBe(expected);
  });

  it("is deterministic across repeated calls and across key order in the input", () => {
    const first = toHex(encodeScppV2Message(BASE));
    for (let attempt = 0; attempt < 64; attempt += 1) {
      expect(toHex(encodeScppV2Message(BASE))).toBe(first);
    }
    const reordered = Object.fromEntries(
      Object.entries(BASE as unknown as Record<string, unknown>).reverse(),
    ) as unknown as ScppV2MessageInput;
    expect(toHex(encodeScppV2Message(reordered))).toBe(first);
  });

  it("emits the fields in the declared order", () => {
    const tags = decodeTlv(encodeScppV2Message(BASE)).map((field) => field.tag);
    expect(tags).toEqual(SCPP_V2_FIELD_ORDER.map((name) => SCPP_TAGS[name]));
  });

  it("keeps every value inside the short-form length limit at maximum widths", () => {
    const widest = {
      ...BASE,
      amountAtomic: SCPP_AMOUNT_MAX_ATOMIC,
      assetSymbol: "wstETH-0.12_TEST",
      deviceId: "abcdefghijklmnopqrstuvwxyz012345",
      receivingAccountId: `acct_${"a".repeat(59)}`,
      paymentId: `pay_${"a".repeat(60)}`,
      counter: 4294967295,
    };
    for (const field of decodeTlv(encodeScppV2Message(widest))) {
      expect(field.value.length).toBeLessThanOrEqual(127);
    }
  });
});

describe("input validation", () => {
  it("rejects an unknown field rather than ignoring it", () => {
    expect(codeOf(() => encodeScppV2Message({ ...BASE, tipMinor: "100" } as unknown as ScppV2MessageInput))).toBe(
      "SCPP_UNKNOWN_FIELD",
    );
  });

  it("rejects a missing field, because the profile has no optional fields", () => {
    const { paymentId, ...withoutPaymentId } = BASE;
    expect(codeOf(() => encodeScppV2Message(withoutPaymentId as unknown as ScppV2MessageInput))).toBe(
      "SCPP_MISSING_FIELD",
    );
  });

  it("rejects the reserved fiat currency field by name", () => {
    expect(codeOf(() => encodeScppV2Message({ ...BASE, currencyNumeric: "840" } as unknown as ScppV2MessageInput))).toBe(
      "SCPP_RESERVED_TAG",
    );
    expect(codeOf(() => encodeScppV2Message({ ...BASE, "5F2A": "0840" } as unknown as ScppV2MessageInput))).toBe(
      "SCPP_RESERVED_TAG",
    );
  });

  it("rejects every reserved tag sent as a field name", () => {
    for (const { tag } of Object.values(SCPP_RESERVED_TAGS)) {
      expect(codeOf(() => encodeScppV2Message({ ...BASE, [tag]: "00" } as unknown as ScppV2MessageInput))).toBe(
        "SCPP_RESERVED_TAG",
      );
    }
  });

  it("rejects the reserved PIN commitment and a caller-supplied version", () => {
    expect(codeOf(() => encodeScppV2Message({ ...BASE, pinCommitment: "00" } as unknown as ScppV2MessageInput))).toBe(
      "SCPP_RESERVED_TAG",
    );
    expect(codeOf(() => encodeScppV2Message({ ...BASE, DF13: "00" } as unknown as ScppV2MessageInput))).toBe(
      "SCPP_RESERVED_TAG",
    );
    expect(codeOf(() => encodeScppV2Message({ ...BASE, version: 1 } as unknown as ScppV2MessageInput))).toBe(
      "SCPP_RESERVED_TAG",
    );
  });

  it("rejects anything that is not an object", () => {
    for (const input of [null, undefined, 42, "message", [BASE]]) {
      expect(codeOf(() => encodeScppV2Message(input as unknown as ScppV2MessageInput))).toBe("SCPP_INVALID_FIELD");
    }
  });

  it("rejects an amount that is not an atomic integer string", () => {
    for (const amount of [10.5, 1000, "10.00", "1e3", "01000", "-1", "", " 1000", "1000 ", 10n]) {
      expect(codeOf(() => encodeScppV2Message(withField("amountAtomic", amount)))).toBe("SCPP_INVALID_FIELD");
    }
  });

  it("carries an amount as wide as a chain can hold and rejects the next one up rather than truncating", () => {
    expect(() => encodeScppV2Message(withField("amountAtomic", SCPP_AMOUNT_MAX_ATOMIC))).not.toThrow();
    const overCeiling = (BigInt(SCPP_AMOUNT_MAX_ATOMIC) + 1n).toString(10);
    expect(codeOf(() => encodeScppV2Message(withField("amountAtomic", overCeiling)))).toBe("SCPP_INVALID_FIELD");
    expect(codeOf(() => encodeScppV2Message(withField("amountAtomic", "9".repeat(79))))).toBe("SCPP_INVALID_FIELD");
  });

  it("keeps a wide amount exact rather than rounding it the way a float would", () => {
    /* Past 2^53 a JavaScript number cannot tell these two amounts apart. */
    const lower = "9007199254740993";
    const upper = "9007199254740992";
    expect(toHex(encodeScppV2Message(withField("amountAtomic", lower)))).not.toBe(
      toHex(encodeScppV2Message(withField("amountAtomic", upper))),
    );
    expect(buildScppV2Message(withField("amountAtomic", SCPP_AMOUNT_MAX_ATOMIC)).amountAtomic).toBe(
      SCPP_AMOUNT_MAX_ATOMIC,
    );
  });

  it("rejects an asset symbol that is empty, over-long or outside the symbol charset", () => {
    for (const symbol of ["", "a".repeat(17), "US DC", "USD$", "US\nDC", ".USDC", 840, null]) {
      expect(codeOf(() => encodeScppV2Message(withField("assetSymbol", symbol)))).toBe("SCPP_INVALID_FIELD");
    }
    for (const symbol of ["A", "USDC", "wstETH-0.12_TEST", "1INCH", "cUSDCv3"]) {
      expect(() => encodeScppV2Message(withField("assetSymbol", symbol))).not.toThrow();
    }
  });

  it("rejects a date that is not a real day and a time that is not a real clock reading", () => {
    for (const date of ["261301", "260431", "260229", "2604011", "26-4-1"]) {
      expect(codeOf(() => encodeScppV2Message(withField("transactionDate", date)))).toBe("SCPP_INVALID_FIELD");
    }
    expect(() => encodeScppV2Message(withField("transactionDate", "280229"))).not.toThrow();
    for (const time of ["240000", "146005", "143060", "14300"]) {
      expect(codeOf(() => encodeScppV2Message(withField("transactionTime", time)))).toBe("SCPP_INVALID_FIELD");
    }
  });

  it("rejects a counter that is not a whole number inside the four byte field", () => {
    for (const counter of [-1, 1.5, 4294967296, "1", Number.NaN, Number.POSITIVE_INFINITY]) {
      expect(codeOf(() => encodeScppV2Message(withField("counter", counter)))).toBe("SCPP_INVALID_FIELD");
    }
    expect(() => encodeScppV2Message(withField("counter", 0))).not.toThrow();
    expect(() => encodeScppV2Message(withField("counter", 4294967295))).not.toThrow();
  });

  it("rejects an unpredictable number that is not four bytes of hexadecimal", () => {
    for (const value of ["", "3f1a9c", "3f1a9c040", "3f1a9c0", "3f1a9czz", "0x3f1a9c04"]) {
      expect(codeOf(() => encodeScppV2Message(withField("unpredictableNumber", value)))).toBe("SCPP_INVALID_FIELD");
    }
    expect(() => encodeScppV2Message(withField("unpredictableNumber", "FFFFFFFF"))).not.toThrow();
  });

  /* A v1 reader names three fields v2 does not carry. Each is refused by name
     rather than as an unknown field, because every one of them was a field of
     this profile one version ago and "unknown" would send the integrator
     looking for a typo. */
  it("refuses the fields v1 carried and v2 does not, by name", () => {
    for (const [field, value] of [
      ["nonce", "3f1a9c04d7b62e58a10f4c7d9b3e6215c8074af91d52be3607c4a18d5f92e3b0"],
      ["actionId", "act_01HZY8QK3M7T2W"],
      ["expiry", "20260401143305"],
    ] as const) {
      expect(codeOf(() => encodeScppV2Message({ ...BASE, [field]: value } as unknown as ScppV2MessageInput))).toBe(
        "SCPP_RESERVED_TAG",
      );
    }
  });

  it("rejects identifiers that are empty, over-long or outside the identifier charset", () => {
    expect(codeOf(() => encodeScppV2Message(withField("deviceId", "")))).toBe("SCPP_INVALID_FIELD");
    expect(codeOf(() => encodeScppV2Message(withField("deviceId", "a".repeat(33))))).toBe("SCPP_INVALID_FIELD");
    expect(() => encodeScppV2Message(withField("deviceId", "a".repeat(32)))).not.toThrow();
    expect(codeOf(() => encodeScppV2Message(withField("receivingAccountId", "a".repeat(65))))).toBe(
      "SCPP_INVALID_FIELD",
    );
    for (const value of ["reader 01", "reader\n01", "réader", "_leading", "réader"]) {
      expect(codeOf(() => encodeScppV2Message(withField("deviceId", value)))).toBe("SCPP_INVALID_FIELD");
    }
  });
});

describe("challenge", () => {
  it("is the SHA-256 of the encoded bytes and nothing else", () => {
    const encoded = encodeScppV2Message(BASE);
    const challenge = scppV2Challenge(BASE);
    expect(challenge).toHaveLength(32);
    expect(toHex(challenge)).toBe(createHash("sha256").update(Buffer.from(encoded)).digest("hex"));
  });

  it("changes when any field changes", () => {
    const original = toHex(scppV2Challenge(BASE));
    const mutations: ScppV2MessageInput[] = [
      withField("amountAtomic", "1000001"),
      withField("assetSymbol", "WETH"),
      withField("transactionDate", "260402"),
      withField("transactionTime", "143006"),
      withField("deviceId", "reader-02"),
      withField("receivingAccountId", "acct_01HZY8QK3MOTHER"),
      withField("counter", 2),
      withField("unpredictableNumber", "3f1a9c05"),
      withField("paymentId", "pay_01HZY8QK3M7T2X"),
    ];
    const seen = new Set([original]);
    for (const mutation of mutations) {
      const challenge = toHex(scppV2Challenge(mutation));
      expect(seen.has(challenge)).toBe(false);
      seen.add(challenge);
    }
  });
});

describe("decoding a message", () => {
  it("round trips every field, including the version the encoder supplied", () => {
    const decoded = decodeScppV2Message(encodeScppV2Message(BASE));
    expect(decoded).toEqual({ ...BASE, version: SCPP_VERSION_V2 });
  });

  it("normalises the same values through the builder", () => {
    expect(buildScppV2Message(BASE)).toEqual({ ...BASE, version: SCPP_VERSION_V2 });
  });

  it("rejects a message whose fields are out of the declared order", () => {
    const encoded = encodeScppV2Message(BASE);
    const swapped = new Uint8Array(encoded);
    /* The first two fields are DF05 (2 + 1 + 32 bytes) and DF04 (2 + 1 + 4). */
    swapped.set(encoded.subarray(35, 42), 0);
    swapped.set(encoded.subarray(0, 35), 7);
    expect(codeOf(() => decodeScppV2Message(swapped))).toBe("SCPP_MALFORMED_TLV");
  });

  it("rejects a message with a field missing or added", () => {
    const encoded = encodeScppV2Message(BASE);
    expect(codeOf(() => decodeScppV2Message(encoded.subarray(0, encoded.length - 10)))).toBe("SCPP_MALFORMED_TLV");
    const withExtra = new Uint8Array(encoded.length + 3);
    withExtra.set(encoded, 0);
    withExtra.set(fromHex("DF20", "tag"), encoded.length);
    withExtra[encoded.length + 2] = 0;
    expect(codeOf(() => decodeScppV2Message(withExtra))).toBe("SCPP_MALFORMED_TLV");
  });

  /* Version 1 is the case that matters: it is the one a reader built against
     the previous profile actually emits, and the field count alone would not
     catch it if that reader also dropped the three retired fields. */
  it("rejects a message announcing another version", () => {
    const encoded = encodeScppV2Message(BASE);
    const versionTagOffset = toHex(encoded).indexOf("df010102");
    expect(versionTagOffset).toBeGreaterThanOrEqual(0);
    for (const version of [0x01, 0x03, 0xff]) {
      const otherVersion = new Uint8Array(encoded);
      otherVersion[versionTagOffset / 2 + 3] = version;
      expect(codeOf(() => decodeScppV2Message(otherVersion))).toBe("SCPP_INVALID_FIELD");
    }
  });
});

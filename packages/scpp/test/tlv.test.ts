import { describe, expect, it } from "vitest";

import {
  assertProfileTag,
  decodeTlv,
  encodeTlv,
  fromHex,
  ScppError,
  TLV_MAX_VALUE_BYTES,
  toHex,
} from "../src/index.js";

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

describe("restricted TLV encoder", () => {
  it("encodes tag, short-form length and value in the order given", () => {
    const bytes = encodeTlv([
      { tag: "9A", value: fromHex("260401", "value") },
      { tag: "DF01", value: Uint8Array.from([0x01]) },
    ]);
    expect(toHex(bytes)).toBe("9a03260401df010101");
  });

  it("produces identical bytes for identical input on every call", () => {
    const fields = [{ tag: "9F02", value: fromHex("000000001000", "value") }];
    const first = toHex(encodeTlv(fields));
    for (let attempt = 0; attempt < 32; attempt += 1) {
      expect(toHex(encodeTlv(fields))).toBe(first);
    }
  });

  it("accepts a value at the short-form boundary and rejects the byte past it", () => {
    const atBoundary = new Uint8Array(TLV_MAX_VALUE_BYTES);
    expect(encodeTlv([{ tag: "DF10", value: atBoundary }])[2]).toBe(TLV_MAX_VALUE_BYTES);
    expect(codeOf(() => encodeTlv([{ tag: "DF10", value: new Uint8Array(TLV_MAX_VALUE_BYTES + 1) }]))).toBe(
      "SCPP_LENGTH_OUT_OF_PROFILE",
    );
  });

  it("rejects an empty message", () => {
    expect(codeOf(() => encodeTlv([]))).toBe("SCPP_MALFORMED_TLV");
  });

  it("rejects a repeated tag", () => {
    expect(
      codeOf(() =>
        encodeTlv([
          { tag: "DF01", value: Uint8Array.from([0x01]) },
          { tag: "DF01", value: Uint8Array.from([0x02]) },
        ]),
      ),
    ).toBe("SCPP_MALFORMED_TLV");
  });

  it("rejects a value that is not a byte array", () => {
    expect(codeOf(() => encodeTlv([{ tag: "DF01", value: "01" as unknown as Uint8Array }]))).toBe("SCPP_MALFORMED_TLV");
  });
});

describe("tag profile", () => {
  it("accepts the one- and two-byte primitive tags the profile uses", () => {
    for (const tag of ["9A", "9F02", "5F2A", "DF01", "DF13"]) {
      expect(() => assertProfileTag(tag)).not.toThrow();
    }
  });

  it("rejects a three-byte tag", () => {
    expect(codeOf(() => assertProfileTag("9F8102"))).toBe("SCPP_TAG_OUT_OF_PROFILE");
  });

  it("rejects a two-byte tag that announces a third byte", () => {
    expect(codeOf(() => assertProfileTag("9F81"))).toBe("SCPP_TAG_OUT_OF_PROFILE");
  });

  it("rejects a one-byte tag that announces a second byte it does not carry", () => {
    expect(codeOf(() => assertProfileTag("9F"))).toBe("SCPP_TAG_OUT_OF_PROFILE");
  });

  it("rejects a constructed tag", () => {
    expect(codeOf(() => assertProfileTag("70"))).toBe("SCPP_TAG_OUT_OF_PROFILE");
  });

  it("rejects lower-case and non-hexadecimal tags", () => {
    expect(codeOf(() => assertProfileTag("9f02"))).toBe("SCPP_TAG_OUT_OF_PROFILE");
    expect(codeOf(() => assertProfileTag("ZZ"))).toBe("SCPP_TAG_OUT_OF_PROFILE");
    expect(codeOf(() => assertProfileTag(2 as unknown as string))).toBe("SCPP_TAG_OUT_OF_PROFILE");
  });
});

describe("strict TLV decoder", () => {
  it("round trips every field of a message", () => {
    const fields = [
      { tag: "9A", value: fromHex("260401", "value") },
      { tag: "9F1C", value: fromHex("7265616465722d3031", "value") },
      { tag: "DF03", value: new Uint8Array(32).fill(0xab) },
    ];
    const decoded = decodeTlv(encodeTlv(fields));
    expect(decoded.map((field) => field.tag)).toEqual(["9A", "9F1C", "DF03"]);
    decoded.forEach((field, index) => {
      expect(toHex(field.value)).toBe(toHex(fields[index]!.value));
    });
  });

  it("rejects a long-form length byte", () => {
    expect(codeOf(() => decodeTlv(fromHex("df01810101", "message")))).toBe("SCPP_LENGTH_OUT_OF_PROFILE");
  });

  it("rejects a value that runs past the end of the message", () => {
    expect(codeOf(() => decodeTlv(fromHex("df0105010203", "message")))).toBe("SCPP_MALFORMED_TLV");
  });

  it("rejects a tag with no length byte", () => {
    expect(codeOf(() => decodeTlv(fromHex("df01", "message")))).toBe("SCPP_MALFORMED_TLV");
  });

  it("rejects a truncated two-byte tag", () => {
    expect(codeOf(() => decodeTlv(fromHex("9f", "message")))).toBe("SCPP_MALFORMED_TLV");
  });

  it("rejects an empty message and a non-array input", () => {
    expect(codeOf(() => decodeTlv(new Uint8Array(0)))).toBe("SCPP_MALFORMED_TLV");
    expect(codeOf(() => decodeTlv("df010101" as unknown as Uint8Array))).toBe("SCPP_MALFORMED_TLV");
  });

  it("rejects a repeated tag", () => {
    expect(codeOf(() => decodeTlv(fromHex("df010101df010102", "message")))).toBe("SCPP_MALFORMED_TLV");
  });
});

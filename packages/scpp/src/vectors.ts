import type { ScppV2MessageInput } from "./message.js";

/* These vectors are the contract. An independent implementation of this
   profile is correct when it reproduces every encodedHex
   and challengeHex below from the same field values, and when it agrees with
   this package about which of the negative cases verify.

   They are literals on purpose. Computing the expected bytes from the encoder
   they are meant to test would make the file agree with any bug the encoder
   grows. These were produced by a second encoder written from the profile
   table alone, and the TS encoder is correct when it matches them.

   v2 carries ten fields where v1 carried twelve: the server nonce, the action
   id and the expiry are gone, and the freshness value is the reader's own
   four-byte unpredictable number under 9F37. Every vector below is therefore
   new -- a v1 vector cannot be adjusted into a v2 one. */

export interface ScppV2TestVector {
  readonly name: string;
  readonly description: string;
  readonly input: ScppV2MessageInput;
  readonly encodedHex: string;
  readonly encodedLength: number;
  readonly challengeHex: string;
  readonly signatureDerHex: string;
}

export interface ScppV2NegativeVector {
  readonly name: string;
  readonly description: string;
  /* The field whose value differs between what was signed and what is
     presented. */
  readonly tamperedField: string;
  readonly presentedInput: ScppV2MessageInput;
  readonly presentedChallengeHex: string;
  readonly signatureDerHex: string;
}

/* A key pair generated for this file and for nothing else. It has never been
   personalised onto a card and never will be: a published profile needs a
   published key so two implementations can check they agree, and a key that can
   authorise a payment must never leave a secure element. The private half is
   here so an independent implementation can produce its own signatures over
   these same messages. */
export const SCPP_V2_TEST_KEY = {
  publicKeyHex: "04eb44292068c6d228b467f49e15e37ed43adc7c3f0a910455db0fee0bb872b3f2aaf07f04e9b4c9b49244aa9a8901cd801b1199767e67a51fb891404e48e76b55",
  privateKeyPkcs8Hex:
    "308187020100301306072a8648ce3d020106082a8648ce3d030107046d306b02010104208bdaae78ef9f73babf3e2a7e0ff87ab640be150ef1baab03dae29f0fdc7f54b3a14403420004eb44292068c6d228b467f49e15e37ed43adc7c3f0a910455db0fee0bb872b3f2aaf07f04e9b4c9b49244aa9a8901cd801b1199767e67a51fb891404e48e76b55",
} as const;

export const SCPP_V2_TEST_VECTORS: readonly ScppV2TestVector[] = [
  {
    name: "typical_usdc_tap",
    description: "A one USDC tap at a named reader: six decimals, so 1000000 atomic units. The shape most taps take.",
    input: {
      amountAtomic: "1000000",
      assetSymbol: "USDC",
      transactionDate: "260401",
      transactionTime: "143005",
      deviceId: "reader-01",
      receivingAccountId: "acct_01HZY8QK3MREADER",
      counter: 1,
      unpredictableNumber: "3f1a9c04",
      paymentId: "pay_01HZY8QK3M7T2V"
    },
    encodedHex: "df052000000000000000000000000000000000000000000000000000000000000f4240df0404555344439a032604019f2103143005df06097265616465722d3031df0715616363745f3031485a5938514b334d524541444552df010102df0204000000019f37043f1a9c04df10127061795f3031485a5938514b334d37543256",
    encodedLength: 128,
    challengeHex: "c1acc0fd090851aa195072c5362faac7badd48a02a338b13bf445a6309eba2d4",
    signatureDerHex: "30450220766ddbecb4fc44b3f308c3d2f3f07f364a3608eacfe5376c046c40822b6b95fc022100b16721a9424e6a93fac6e8343fa3f4c47ca6fc58b396e996a68cd9f40012d267"
  },
  {
    name: "minimum_widths",
    description: "Every variable-width field at its shortest and every counter and amount at its floor.",
    input: {
      amountAtomic: "1",
      assetSymbol: "A",
      transactionDate: "000101",
      transactionTime: "000000",
      deviceId: "R",
      receivingAccountId: "a",
      counter: 0,
      unpredictableNumber: "00000001",
      paymentId: "p"
    },
    encodedHex: "df05200000000000000000000000000000000000000000000000000000000000000001df0401419a030001019f2103000000df060152df070161df010102df0204000000009f370400000001df100170",
    encodedLength: 80,
    challengeHex: "2e9c6213629ea9e8a904d654de9524e2956446fcb20a1646ff5f78bdbbbdf83f",
    signatureDerHex: "304502202220a5d48ddbb4191a3be434899560a4e0bf173d92d5d9a5a2cd55b964e885c6022100e0955529c331c995f149613d5361c9be2ec2384127c1a4f6c582dacbc5007267"
  },
  {
    name: "maximum_widths_leap_day",
    description: "Every variable-width field at its longest, the largest atomic amount and counter the profile admits, on a leap day.",
    input: {
      amountAtomic: "115792089237316195423570985008687907853269984665640564039457584007913129639935",
      assetSymbol: "wstETH-0.12_TEST",
      transactionDate: "280229",
      transactionTime: "235959",
      deviceId: "abcdefghijklmnopqrstuvwxyz012345",
      receivingAccountId: "acct_0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVW",
      counter: 4294967295,
      unpredictableNumber: "ffffffff",
      paymentId: "pay_0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWX"
    },
    encodedHex: "df0520ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffdf04107773744554482d302e31325f544553549a032802299f2103235959df06206162636465666768696a6b6c6d6e6f707172737475767778797a303132333435df0740616363745f303132333435363738396162636465666768696a6b6c6d6e6f707172737475767778797a4142434445464748494a4b4c4d4e4f5051525354555657df010102df0204ffffffff9f3704ffffffffdf10407061795f303132333435363738396162636465666768696a6b6c6d6e6f707172737475767778797a4142434445464748494a4b4c4d4e4f505152535455565758",
    encodedLength: 252,
    challengeHex: "ef8aae9c3fbe11c319a4839941450f3e75539d12bfec5b06841060c3fbf842a9",
    signatureDerHex: "304502201919d9e1e2a6a1e7fafcc392f8b1790cedb27bcab3c4359567bc45a7fa84d06f02210082aba95ecd6bd417be3912b1e6be34c4b858746e01763b2a769c7f3d70744497"
  }
] as const;

/* Each negative case presents a genuine signature over one message against a
   different message. Verification must return false; none of them is malformed
   input, so none of them throws. */
export const SCPP_V2_NEGATIVE_VECTORS: readonly ScppV2NegativeVector[] = [
  {
    name: "tampered_amount",
    description: "The signature from typical_usdc_tap presented against a message whose atomic amount was raised after signing.",
    tamperedField: "amountAtomic",
    presentedInput: {
      amountAtomic: "100000000",
      assetSymbol: "USDC",
      transactionDate: "260401",
      transactionTime: "143005",
      deviceId: "reader-01",
      receivingAccountId: "acct_01HZY8QK3MREADER",
      counter: 1,
      unpredictableNumber: "3f1a9c04",
      paymentId: "pay_01HZY8QK3M7T2V"
    },
    presentedChallengeHex: "276a4b37c46c026f633f16dacdfaff75c8b76ce16b5c9b0db3520ac4a57351c8",
    signatureDerHex: "30450220766ddbecb4fc44b3f308c3d2f3f07f364a3608eacfe5376c046c40822b6b95fc022100b16721a9424e6a93fac6e8343fa3f4c47ca6fc58b396e996a68cd9f40012d267"
  },
  {
    name: "tampered_asset",
    description: "The signature from typical_usdc_tap presented against a message that keeps the atomic amount and swaps the asset it counts, which is a different sum of money entirely.",
    tamperedField: "assetSymbol",
    presentedInput: {
      amountAtomic: "1000000",
      assetSymbol: "WETH",
      transactionDate: "260401",
      transactionTime: "143005",
      deviceId: "reader-01",
      receivingAccountId: "acct_01HZY8QK3MREADER",
      counter: 1,
      unpredictableNumber: "3f1a9c04",
      paymentId: "pay_01HZY8QK3M7T2V"
    },
    presentedChallengeHex: "a1a135d05f3ce781b7b8d76a1007338c83bd54ff8ca9089bf33047cfad059ad2",
    signatureDerHex: "30450220766ddbecb4fc44b3f308c3d2f3f07f364a3608eacfe5376c046c40822b6b95fc022100b16721a9424e6a93fac6e8343fa3f4c47ca6fc58b396e996a68cd9f40012d267"
  },
  {
    name: "wrong_counter",
    description: "The signature from typical_usdc_tap presented with a different card counter, which is what a replay of an earlier tap looks like.",
    tamperedField: "counter",
    presentedInput: {
      amountAtomic: "1000000",
      assetSymbol: "USDC",
      transactionDate: "260401",
      transactionTime: "143005",
      deviceId: "reader-01",
      receivingAccountId: "acct_01HZY8QK3MREADER",
      counter: 2,
      unpredictableNumber: "3f1a9c04",
      paymentId: "pay_01HZY8QK3M7T2V"
    },
    presentedChallengeHex: "03b1eb11b63adcd0b865b9b80075c78595f1dd8117bb06ef5fef443532c37968",
    signatureDerHex: "30450220766ddbecb4fc44b3f308c3d2f3f07f364a3608eacfe5376c046c40822b6b95fc022100b16721a9424e6a93fac6e8343fa3f4c47ca6fc58b396e996a68cd9f40012d267"
  },
  {
    name: "tampered_receiving_account",
    description: "The signature from typical_usdc_tap presented against a message redirected to another receiving account.",
    tamperedField: "receivingAccountId",
    presentedInput: {
      amountAtomic: "1000000",
      assetSymbol: "USDC",
      transactionDate: "260401",
      transactionTime: "143005",
      deviceId: "reader-01",
      receivingAccountId: "acct_01HZY8QK3MATTACKER",
      counter: 1,
      unpredictableNumber: "3f1a9c04",
      paymentId: "pay_01HZY8QK3M7T2V"
    },
    presentedChallengeHex: "af8c903ec24f11651b97345d17b371d5f0457a9360993dfe362bdd86f54c754c",
    signatureDerHex: "30450220766ddbecb4fc44b3f308c3d2f3f07f364a3608eacfe5376c046c40822b6b95fc022100b16721a9424e6a93fac6e8343fa3f4c47ca6fc58b396e996a68cd9f40012d267"
  },
  {
    name: "tampered_unpredictable_number",
    description: "The signature from typical_usdc_tap presented with a different unpredictable number. A reader generates that value itself, so this is the case that proves it is signed rather than merely sent alongside.",
    tamperedField: "unpredictableNumber",
    presentedInput: {
      amountAtomic: "1000000",
      assetSymbol: "USDC",
      transactionDate: "260401",
      transactionTime: "143005",
      deviceId: "reader-01",
      receivingAccountId: "acct_01HZY8QK3MREADER",
      counter: 1,
      unpredictableNumber: "3f1a9c05",
      paymentId: "pay_01HZY8QK3M7T2V"
    },
    presentedChallengeHex: "6fd6c84d6e2e0e11ddd28e29e132439d5010186d33ba227b00ab4598ccd8d7fd",
    signatureDerHex: "30450220766ddbecb4fc44b3f308c3d2f3f07f364a3608eacfe5376c046c40822b6b95fc022100b16721a9424e6a93fac6e8343fa3f4c47ca6fc58b396e996a68cd9f40012d267"
  }
] as const;

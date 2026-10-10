/**
 * One tap, end to end, on a laptop with no hardware.
 *
 * Prints the approved tap, then the four ways it is refused: a changed amount,
 * a changed receiver, a replayed counter, and another card's signature over the
 * same terms. The refusals are the interesting half.
 */

import { randomBytes } from "node:crypto";

import { scppV2Challenge } from "@stableyard/scpp";

import { createSoftCard } from "../softcard/index.js";
import { authoriseTap } from "../verifier/index.js";

const card = createSoftCard({ cardId: "card_demo", counter: 14 });

/* What the verifier knows about this card, independent of anything a reader
   sends it. The account is the card's, not the request's. */
const onFile = {
  publicKey: card.publicKey,
  lastCounter: card.counter,
  receivingAccountId: "acct_01HZY8QK3MDEMO",
};

/* The terms the terminal states. The unpredictable number is the terminal's
   own freshness for this one tap -- there is no round trip to ask for it. */
const terms = {
  amountAtomic: "5000000",
  assetSymbol: "USDC",
  transactionDate: "261010",
  transactionTime: "143005",
  deviceId: "reader-01",
  receivingAccountId: "acct_01HZY8QK3MDEMO",
  counter: card.counter + 1,
  unpredictableNumber: randomBytes(4).toString("hex"),
  paymentId: "pay_01HZY8QK3M7T2V",
};

const line = (s = "") => console.log(s);
const rule = () => line("-".repeat(72));

line();
line("  SCPP v2 — one tap, authorised");
rule();
line(`  card          ${card.cardId}`);
line(`  public key    ${card.publicKey.slice(0, 32)}…`);
line(`  amount        ${terms.amountAtomic} atomic ${terms.assetSymbol}`);
line(`  to account    ${terms.receivingAccountId}`);
line(`  tap           #${terms.counter}`);
line(`  unpredictable ${terms.unpredictableNumber}`);
rule();

/* The card is handed the challenge and nothing else. It never sees an amount,
   an account or a payment id -- only 32 bytes it is asked to sign. */
const signatureDer = card.sign(scppV2Challenge(terms));
const result = authoriseTap({ terms, signatureDer, card: onFile });

line(`  signed bytes  ${result.encodedHex.length / 2} (${result.encodedHex.slice(0, 44)}…)`);
line(`  challenge     ${result.challengeHex}`);
line(`  signature     ${signatureDer.slice(0, 44)}…`);
line();
line(`  => ${result.approved ? "APPROVED" : "REFUSED"}  response code ${result.responseCode}`);
line();
line("  decoded back out of the signed bytes:");
for (const [key, value] of Object.entries(result.decoded)) {
  line(`    ${key.padEnd(22)} ${value}`);
}

line();
line("  SCPP v2 — the same signature, refused");
rule();

/* Each of these presents the SAME signature against different terms, which is
   the shape of a redirected, re-priced or replayed payment. */
for (const [label, attempt] of attacks()) {
  const verdict = authoriseTap(attempt);
  const outcome = verdict.approved ? "APPROVED" : `refused  ${verdict.responseCode}  ${verdict.code}`;
  line(`  ${label.padEnd(34)} ${outcome}`);
}
line();

function attacks() {
  const other = createSoftCard({ cardId: "card_other" });
  return [
    ["amount raised to 50 USDC", {
      terms: { ...terms, amountAtomic: "50000000" }, signatureDer, card: onFile,
    }],
    ["receiver swapped", {
      terms: { ...terms, receivingAccountId: "acct_01HZY8QK3MATTACKER" }, signatureDer, card: onFile,
    }],
    ["same tap presented twice", {
      terms, signatureDer, card: { ...onFile, lastCounter: terms.counter },
    }],
    ["another card's signature", {
      terms, signatureDer: other.sign(scppV2Challenge(terms)), card: onFile,
    }],
  ];
}

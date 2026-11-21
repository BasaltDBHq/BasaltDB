// Runs with `node --test web/lib/*.test.mjs` (make web-check). What the
// approval and revert pages say of the receipt in an approve or apply
// answer on a session (CONTRACT.md, Vault channel, Receipts, In the page):
// checked against the session's own key, shown with its fingerprint and
// the request to compare it with the chat, and never called verified.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import { engineIdOf, fingerprint } from "./channel.js";
import { RECEIPT_REFUSED, receiptLine } from "./page.js";

const vectors = JSON.parse(readFileSync(new URL("../../api/mcp/vault/testdata/receipt.json", import.meta.url), "utf8")).cases;
const byName = (name) => vectors.find((c) => c.name === name);

async function session(engineKey) {
  return { transport: "RELAY", engine: { engineKey, engineId: await engineIdOf(engineKey) } };
}

test("a receipt is shown with the session's fingerprint and the ask to compare, never as verified", async () => {
  for (const name of ["an approval", "a revert with its change"]) {
    const c = byName(name);
    const s = await session(c.engineKey);
    const text = await receiptLine({ receipt: c.token }, s);
    const payload = JSON.parse(c.payloadJson);
    assert.ok(text.includes(fingerprint(s.engine.engineId)), name);
    assert.ok(text.includes(payload.headline), name);
    assert.ok(text.includes(payload.itemId), name);
    assert.match(text, /Compare this fingerprint with the one the agent showed you in the chat/);
    assert.doesNotMatch(text, /verif|confirmed|trusted|genuine/i);
  }
});

test("a receipt that does not check against the session's key shows nothing from it", async () => {
  for (const c of vectors.filter((v) => v.expect === "REFUSE")) {
    const text = await receiptLine({ receipt: c.token }, await session(c.engineKey));
    assert.equal(text, RECEIPT_REFUSED, c.name);
  }
  // A good receipt, read on a session to another engine key.
  const pair = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  const spki = Buffer.from(await crypto.subtle.exportKey("spki", pair.publicKey)).toString("base64url");
  assert.equal(await receiptLine({ receipt: byName("an approval").token }, await session(spki)), RECEIPT_REFUSED);
});

test("an answer without a receipt says why, and a same-origin page says nothing", async () => {
  const s = await session(byName("an approval").engineKey);
  assert.match(await receiptLine({ noReceipt: "KEY_ERROR" }, s), /^No receipt: the engine's key file is refused/);
  assert.match(await receiptLine({ noReceipt: "WIDENED" }, s), /^No receipt: the revert's scope was changed/);
  assert.equal(await receiptLine({}, s), "");
  assert.equal(await receiptLine({ receipt: byName("an approval").token }, { transport: "SAME_ORIGIN" }), "");
});

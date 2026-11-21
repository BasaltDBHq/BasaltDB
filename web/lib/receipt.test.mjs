// Runs with `node --test web/lib/*.test.mjs` (make web-check). What the
// approval and revert pages say of the receipt in an approve or apply
// answer on a session (CONTRACT.md, Vault channel, Receipts, In the page):
// checked against the session's own key, shown with its fingerprint and
// the request to compare it with the chat, and never called verified.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import { engineIdOf, fingerprint } from "./channel.js";
import { visibleText } from "./codec.js";
import { RECEIPT_REFUSED, receiptLine, receiptText } from "./page.js";

const vectors = JSON.parse(readFileSync(new URL("../../api/mcp/vault/testdata/receipt.json", import.meta.url), "utf8")).cases;
const byName = (name) => vectors.find((c) => c.name === name);

// expectOf is what the page signed for vector c: its kind, item and rows.
function expectOf(c) {
  const p = JSON.parse(c.payloadJson);
  return { kind: p.kind, itemId: p.itemId, rowsHash: p.rowsHash };
}

async function session(engineKey) {
  return { transport: "RELAY", engine: { engineKey, engineId: await engineIdOf(engineKey) } };
}

test("a receipt is shown with the session's fingerprint and the ask to compare, never as verified", async () => {
  for (const name of ["an approval", "a revert with its change"]) {
    const c = byName(name);
    const s = await session(c.engineKey);
    const text = await receiptLine({ receipt: c.token }, s, expectOf(c));
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
    const text = await receiptLine({ receipt: c.token }, await session(c.engineKey), c.payloadJson ? expectOf(c) : expectOf(byName("an approval")));
    assert.equal(text, RECEIPT_REFUSED, c.name);
  }
  // A good receipt, read on a session to another engine key.
  const pair = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  const spki = Buffer.from(await crypto.subtle.exportKey("spki", pair.publicKey)).toString("base64url");
  assert.equal(await receiptLine({ receipt: byName("an approval").token }, await session(spki), expectOf(byName("an approval"))), RECEIPT_REFUSED);
});

test("an answer without a receipt says why, and a same-origin page says nothing", async () => {
  const s = await session(byName("an approval").engineKey);
  assert.match(await receiptLine({ noReceipt: "KEY_ERROR" }, s), /^No receipt: the engine's key file is refused/);
  assert.equal(
    await receiptLine({ noReceipt: "WIDENED", rows: 7 }, s),
    "No receipt: the revert's scope was changed on the signing page (7 rows restored). If you did not change it, tell the agent at once.",
  );
  assert.match(await receiptLine({ noReceipt: "WIDENED", batched: true, pending: 300 }, s), /\(300 rows to restore in batches\)/);
  assert.equal(await receiptLine({ noReceipt: "NEW\u202eREASON" }, s), visibleText("No receipt: NEW\u202eREASON."));
  assert.equal(await receiptLine({}, s), "");
  assert.equal(await receiptLine({ receipt: byName("an approval").token }, { transport: "SAME_ORIGIN" }, expectOf(byName("an approval"))), "");
});

test("a valid receipt for another item, kind or set of rows is refused", async () => {
  for (const name of ["an approval", "a revert with its change"]) {
    const c = byName(name);
    const s = await session(c.engineKey);
    const want = expectOf(c);
    for (const [why, expect] of [
      ["another item", { ...want, itemId: "0192f3a0-7c1e-7b2a-9c4d-000000000000" }],
      ["another kind", { ...want, kind: want.kind === "APPROVAL" ? "REVERT" : "APPROVAL" }],
      ["other rows", { ...want, rowsHash: "0".repeat(64) }],
      ["nothing to compare with", undefined],
    ]) {
      assert.equal(await receiptLine({ receipt: c.token }, s, expect), RECEIPT_REFUSED, `${name}: ${why}`);
    }
  }
});

test("the engine's headline is shown as visible text", () => {
  const headline = "Update 3 rows\u202e in public.orders\u0007";
  const text = receiptText({ kind: "APPROVAL", itemId: "x", status: "APPROVED", headline }, "AAAA BBBB CCCC DDDD");
  assert.ok(text.includes(visibleText(headline)));
  assert.ok(!text.includes("\u202e") && !text.includes("\u0007"));
});

// Runs with `node --test web/lib/*.test.mjs` (make web-check). The Update
// check's words: the rows of the check screen, the passkey list and the
// browser's hint after a removal (CONTRACT.md, The Update check).
import { test } from "node:test";
import assert from "node:assert/strict";

import { checkView, columnName, fixQueue, passkeyItems, passkeyLine, signalRemoved, usedText } from "./doctor.js";

const ORIGIN = "http://localhost:8787";
const local = (label, extra = {}) => ({ credentialId: label, label, rpId: "localhost", origin: ORIGIN, createdAt: "2026-11-03T12:00:00Z", ...extra });
const good = {
  database: "shop_db", guard: { state: "CURRENT" }, certificate: { state: "OK" },
  labels: { state: "OK", count: 0, columns: [] }, passkeys: { state: "OK", items: [local("a"), local("b")] },
};

test("nothing wrong is All good, with the passkeys to manage", () => {
  const v = checkView(good, ORIGIN);
  assert.equal(v.title, "All good");
  assert.equal(v.sub, "BasaltDB is running and your agents can connect.");
  assert.deepEqual(v.rows.map((r) => `${r.mark} ${r.title} ${r.text} ${r.action}`.trim()), [
    "✓ Every column has a label",
    "✓ Database certificate checked",
    "✓ Passkeys 2 devices can approve Manage",
  ]);
  assert.deepEqual(fixQueue(good, ORIGIN), []);
});

test("each finding is a row with its words and action, in the contract's order", () => {
  const d = {
    ...good,
    certificate: { state: "MISMATCH" },
    guard: { state: "OUTDATED", from: 1, to: 2 },
    labels: { state: "UNLABELED", count: 22, columns: Array.from({ length: 20 }, (_, i) => `public.orders.c${i}`) },
    passkeys: { state: "NONE", items: [] },
  };
  const v = checkView(d, ORIGIN);
  assert.equal(v.title, "4 things need you");
  assert.equal(v.sub, "Everything else is working.");
  assert.deepEqual(v.rows.map((r) => [r.title, r.action]), [
    ["The certificate BasaltDB trusts doesn't match its records", "Check"],
    ["BasaltDB needs an update in your database", "Update"],
    ["22 new columns have no label", "Label"],
    ["No passkey can approve", "Add"],
  ]);
  assert.equal(v.rows[1].text, "A newer BasaltDB is running than the one installed in shop_db.");
  assert.match(v.rows[2].text, /^orders\.c0, orders\.c1, .*orders\.c19, …$/);
  assert.deepEqual(fixQueue(d, ORIGIN), ["TRUST", "UPDATE", "LABELS", "PASSKEY_ADD"]);
  const one = checkView({ ...good, labels: { state: "UNLABELED", count: 1, columns: ["s.t.c"] } }, ORIGIN);
  assert.equal(one.title, "1 thing needs you");
  assert.equal(one.rows[0].title, "1 new column has no label");
});

test("an agent that cannot log in: REPAIR for a refused credential, the message otherwise", () => {
  const off = { database: undefined, guard: { state: "UNKNOWN" }, certificate: { state: "OK" }, labels: { state: "UNKNOWN" }, passkeys: { state: "UNKNOWN" } };
  const v = checkView({ ...off, login: { code: "CREDENTIAL_REJECTED", message: "m" } }, ORIGIN);
  assert.equal(v.rows[0].title, "Your agent can't log in");
  assert.equal(v.rows[0].text, "Its database password was changed or removed.");
  assert.equal(v.rows[0].action, "Fix");
  assert.equal(v.sub, "The rest is checked once BasaltDB can connect.");
  assert.deepEqual(v.rows.slice(1).map((r) => [r.title, r.text]), [
    ["Column labels", "Checked once BasaltDB can connect."],
    ["Passkeys", "Checked once BasaltDB can connect."],
  ]);
  const other = checkView({ ...off, login: { code: "DATABASE_UNREACHABLE", message: "The database cannot be reached." } }, ORIGIN);
  assert.equal(other.rows[0].text, "The database cannot be reached.");
  assert.equal(other.rows[0].action, "", "its fix is in the agent's status");
  assert.deepEqual(fixQueue(other, ORIGIN), []);
});

test("a passkey's line says when it was added, where it signs and when it was used", () => {
  const now = new Date("2026-11-22T12:00:00");
  assert.equal(usedText(null, now), "never");
  assert.equal(usedText("2026-11-22T08:00:00", now), "today");
  assert.equal(usedText("2026-11-21T20:00:00", now), "1 day ago");
  assert.equal(usedText("2026-11-17T12:00:00", now), "5 days ago");
  assert.equal(usedText("2026-11-15T12:00:00", now), "1 week ago");
  assert.equal(usedText("2026-11-01T12:00:00", now), "3 weeks ago");
  assert.equal(passkeyLine(local("a", { lastUsedAt: "2026-11-22T09:00:00" }), ORIGIN, now), "Added 3 Nov · used today");
  const portal = { ...local("b"), rpId: "basaltvault.app", origin: "https://portal.basaltvault.app" };
  assert.equal(passkeyLine(portal, ORIGIN, now), "Added 3 Nov on portal.basaltvault.app · used never");
  const items = passkeyItems({ items: [local("a"), { label: "no id" }, { ...local(""), label: "" }] }, ORIGIN, now);
  assert.deepEqual(items.map((k) => k.label), ["a", "Passkey"], "an item without an id is not listed; a blank label reads Passkey");
  assert.equal(columnName("public.orders.phone"), "orders.phone");
  assert.equal(columnName("sales.orders.phone"), "sales.orders.phone");
  assert.equal(checkView({ ...good, passkeys: { state: "OK", items: [local("a"), portal] } }, ORIGIN).rows[2].text, "1 device can approve", "only this origin's count");
});

test("the browser is told of a removed passkey only when it can be", async () => {
  const calls = [];
  assert.equal(await signalRemoved({ signalUnknownCredential: async (o) => calls.push(o) }, "localhost", "aWQ"), true);
  assert.deepEqual(calls, [{ rpId: "localhost", credentialId: "aWQ" }]);
  assert.equal(await signalRemoved(undefined, "localhost", "aWQ"), false);
  assert.equal(await signalRemoved({}, "localhost", "aWQ"), false);
  assert.equal(await signalRemoved({ signalUnknownCredential: async () => { throw new Error("no"); } }, "localhost", "aWQ"), false, "a failed call is a no-op");
});

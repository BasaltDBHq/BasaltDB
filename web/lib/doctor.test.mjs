// Runs with `node --test web/lib/*.test.mjs` (make web-check). The Update
// check's words: the rows of the check screen, the passkey list and the
// browser's hint after a removal (CONTRACT.md, The Update check).
import { test } from "node:test";
import assert from "node:assert/strict";

import { checkView, columnKey, columnName, fixQueue, laterText, passkeyItems, passkeyLine, signalRemoved, usedText } from "./doctor.js";

const ORIGIN = "http://localhost:8787";
const local = (label, extra = {}) => ({ credentialId: label, label, rpId: "localhost", origin: ORIGIN, createdAt: "2026-11-03T12:00:00Z", ...extra });
const good = {
  database: "shop_db", guard: { state: "CURRENT" }, certificate: { state: "OK" },
  labels: { state: "OK", count: 0, columns: [] }, passkeys: { state: "OK", items: [local("a"), local("b")] },
};

test("nothing critical is Ready, with Done enabled and the passkeys to manage", () => {
  const v = checkView(good, ORIGIN);
  assert.equal(v.title, "Ready");
  assert.equal(v.sub, "BasaltDB is running and your agents can connect.");
  assert.deepEqual(v.done, { enabled: true, why: "" });
  assert.deepEqual(v.rows.map((r) => `${r.mark} ${r.title} ${r.text} ${r.action}`.trim()), [
    "✓ Every column has a label",
    "✓ Database certificate checked",
    "✓ Passkeys 2 devices can approve Manage",
  ]);
  assert.deepEqual(v.allSet, { lines: ["Every column has a label", "Database certificate checked", "Passkeys: 2 devices can approve"], later: [] });
  assert.deepEqual(fixQueue(good, ORIGIN), []);
});

test("critical rows carry their own fix and block Done, in the contract's order", () => {
  const d = {
    ...good,
    certificate: { state: "MISMATCH" },
    guard: { state: "OUTDATED", from: 1, to: 2 },
    labels: { state: "UNLABELED", count: 22, columns: Array.from({ length: 20 }, (_, i) => `public.orders.c${i}`) },
    passkeys: { state: "NONE", items: [] },
  };
  const v = checkView(d, ORIGIN);
  assert.equal(v.title, "3 things need you");
  assert.equal(v.sub, "Fix it to finish setup.");
  assert.deepEqual(v.rows.filter((r) => r.tone !== "good").map((r) => [r.tone, r.title, r.action]), [
    ["critical", "The certificate BasaltDB trusts doesn't match its records", "Check"],
    ["critical", "BasaltDB needs an update in your database", "Update"],
    ["critical", "No passkey can approve", "Add a passkey"],
    ["warning", "22 columns have no label", "Label"],
  ]);
  assert.equal(v.rows[1].text, "A newer BasaltDB is running than the one installed in shop_db.");
  assert.equal(v.need, 3, "the warning is not counted");
  assert.equal(v.done.enabled, false);
  assert.equal(v.done.why, "Check the certificate to finish. Until then, BasaltDB may not connect.");
  assert.deepEqual(fixQueue(d, ORIGIN), ["TRUST", "UPDATE", "PASSKEY_ADD"]);
  const key = checkView({ ...good, passkeys: { state: "NONE", items: [] } }, ORIGIN);
  assert.equal(key.done.why, "Add a passkey to finish. Until then, writes over 10 rows wait.");
  assert.equal(key.title, "1 thing needs you");
});

test("unlabeled columns are a warning that never blocks; a saved choice is said", () => {
  const labels = { state: "UNLABELED", count: 2, columns: ["public.orders.a", "public.orders.b"] };
  const v = checkView({ ...good, labels }, ORIGIN);
  assert.equal(v.title, "Ready", "no warning count in the title");
  assert.equal(v.need, 0);
  assert.equal(v.done.enabled, true);
  assert.deepEqual([v.rows[0].tone, v.rows[0].mark, v.rows[0].title, v.rows[0].text, v.rows[0].action], ["warning", "!", "2 columns have no label", "orders.a, orders.b", "Label"]);
  assert.deepEqual(v.allSet.later, ["2 columns have no label"]);
  assert.equal(laterText(v.allSet.later), "Left for later: 2 columns have no label. To change this, ask your agent to run basalt init.");
  assert.equal(laterText([]), "");
  const chosen = checkView({ ...good, labels }, ORIGIN, ["public.orders.a", "public.orders.b"]);
  assert.equal(chosen.rows[0].text, "orders.a, orders.b · you chose to leave them for now");
  const partly = checkView({ ...good, labels }, ORIGIN, ["public.orders.a"]);
  assert.equal(partly.rows[0].text, "orders.a, orders.b", "a column the person did not choose is new");
  assert.equal(checkView({ ...good, labels: { ...labels, count: 1, columns: ["s.t.c"] } }, ORIGIN).rows[0].title, "1 column has no label");
  assert.deepEqual(fixQueue({ ...good, labels }, ORIGIN), [], "Fix these never walks the labels");
});

test("a database BasaltDB cannot read yet is critical, never Ready", () => {
  const d = { ...good, database: undefined, labels: { state: "UNKNOWN" }, passkeys: { state: "UNKNOWN" } };
  const v = checkView(d, ORIGIN);
  assert.equal(v.title, "1 thing needs you");
  assert.equal(v.sub, "The rest is checked once BasaltDB can connect.");
  assert.deepEqual(v.rows.map((r) => [r.tone, r.title, r.text, r.action]), [["critical", "BasaltDB can't check your database yet", "The rest is checked once BasaltDB can connect.", ""]]);
  assert.deepEqual(v.done, { enabled: false, why: "BasaltDB has to reach your database before setup is done." });
});

test("the labels page's columns match doctor's names, so the saved choice is said", () => {
  const saved = [columnKey("public.leads", "id"), columnKey("leads", "name")];
  assert.deepEqual(saved, ["public.leads.id", "public.leads.name"]);
  assert.equal(columnKey("sales.orders", "id"), "sales.orders.id");
  const labels = { state: "UNLABELED", count: 2, columns: ["public.leads.id", "public.leads.name"] };
  const v = checkView({ ...good, labels }, ORIGIN, saved);
  assert.ok(v.rows[0].text.endsWith("you chose to leave them for now"));
});

test("more than 3 warnings fold the rest", () => {
  const v = checkView(good, ORIGIN);
  assert.deepEqual(v.more, []);
});

test("a renewed certificate is one row naming the database, its fix the confirm step", () => {
  const d = { ...good, database: undefined, certificate: { state: "CHANGED", database: "shop_db" }, labels: { state: "UNKNOWN" }, passkeys: { state: "UNKNOWN" } };
  const v = checkView(d, ORIGIN);
  assert.deepEqual([v.rows[0].mark, v.rows[0].title, v.rows[0].text, v.rows[0].action], ["✕", "shop_db renewed its security certificate", "Your agents are paused until you confirm.", "Check"]);
  assert.equal(v.title, "1 thing needs you");
  assert.deepEqual(fixQueue(d, ORIGIN), ["TRUST"]);
  assert.equal(checkView({ ...d, certificate: { state: "CHANGED" } }, ORIGIN).rows[0].title, "Your database renewed its security certificate");
});

test("an agent that cannot log in: REPAIR for a refused credential, the message otherwise", () => {
  const off = { database: undefined, guard: { state: "UNKNOWN" }, certificate: { state: "OK" }, labels: { state: "UNKNOWN" }, passkeys: { state: "UNKNOWN" } };
  const v = checkView({ ...off, login: { code: "CREDENTIAL_REJECTED", message: "m" } }, ORIGIN);
  assert.equal(v.rows[0].title, "Your agent can't log in");
  assert.equal(v.rows[0].text, "Its database password was changed or removed.");
  assert.equal(v.rows[0].action, "Fix");
  assert.equal(v.sub, "The rest is checked once BasaltDB can connect.");
  assert.deepEqual(v.rows.slice(1).map((r) => [r.title, r.text]), [
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
  assert.equal(checkView({ ...good, passkeys: { state: "OK", items: [local("a"), portal] } }, ORIGIN).rows.find((r) => r.title === "Passkeys").text, "1 device can approve", "only this origin's count");
});

test("the browser is told of a removed passkey only when it can be", async () => {
  const calls = [];
  assert.equal(await signalRemoved({ signalUnknownCredential: async (o) => calls.push(o) }, "localhost", "aWQ"), true);
  assert.deepEqual(calls, [{ rpId: "localhost", credentialId: "aWQ" }]);
  assert.equal(await signalRemoved(undefined, "localhost", "aWQ"), false);
  assert.equal(await signalRemoved({}, "localhost", "aWQ"), false);
  assert.equal(await signalRemoved({ signalUnknownCredential: async () => { throw new Error("no"); } }, "localhost", "aWQ"), false, "a failed call is a no-op");
});

test("a certificate not checked is a warning with its own fix: the page still says Ready", () => {
  const d = { ...good, certificate: { state: "NOT_CHECKED", host: "db.abc.supabase.co", port: 5432, sslMode: "require", provider: "Supabase" } };
  const v = checkView(d, ORIGIN, [], "demo_bot");
  assert.equal(v.title, "Ready");
  assert.deepEqual(v.done, { enabled: true, why: "" });
  assert.deepEqual(v.rows.map((r) => `${r.mark} ${r.title} | ${r.text} | ${r.action}`), [
    "! Certificate not checked | demo_bot connects with sslmode=require. Encrypted, but not proven to be Supabase. | Check it",
    "✓ Every column has a label |  | ",
    "✓ Passkeys | 2 devices can approve | Manage",
  ]);
  assert.equal(v.rows[0].job, "TRUST");
  assert.deepEqual(v.allSet.later, ["Certificate not checked"]);
  assert.deepEqual(fixQueue(d, ORIGIN), [], "a warning is no critical fix");
  const own = checkView({ ...d, certificate: { state: "NOT_CHECKED", sslMode: "verify-ca" } }, ORIGIN, [], "demo_bot");
  assert.equal(own.rows[0].text, "demo_bot connects with sslmode=verify-ca. Encrypted, but nothing checks the certificate is your database's.");
});

test("a connection not encrypted is a warning: Check it on a provider's host, words only elsewhere", () => {
  const d = { ...good, certificate: { state: "NOT_ENCRYPTED", host: "db.abc.supabase.co", port: 5432, sslMode: "disable", provider: "Supabase" } };
  const v = checkView(d, ORIGIN, [], "demo_bot");
  assert.equal(v.title, "Ready");
  assert.deepEqual([v.rows[0].mark, v.rows[0].title, v.rows[0].text, v.rows[0].action, v.rows[0].job], ["!", "Connection not encrypted", "demo_bot connects with sslmode=disable. Its data and queries travel unencrypted.", "Check it", "TRUST"]);
  assert.ok(!v.rows.some((r) => r.title === "Database certificate checked"));
  const local = checkView({ ...d, certificate: { state: "NOT_ENCRYPTED", host: "localhost", sslMode: "disable" } }, ORIGIN, [], "demo_bot");
  assert.equal(local.rows[0].action, "", "no built-in roots: nothing to click");
  assert.match(local.rows[0].text, /Use a connection string with sslmode=verify-full\.$/);
  assert.deepEqual(fixQueue(d, ORIGIN), []);
});

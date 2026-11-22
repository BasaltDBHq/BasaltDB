// Runs with `node --test web/lib/*.test.mjs` (make web-check). The words of
// the connect page's Update check (CONTRACT.md, Update on the connect page,
// and The Update check for the local page's copy).
import { test } from "node:test";
import assert from "node:assert/strict";

import { ADD_AGAIN, MAX_NAMED, checkView, dayMonth, passkeyLine, pinView, portalCount, revokeLines, signalRemoved, unlabeledColumns, usedText } from "./connectupdate.js";

const NOW = Date.parse("2026-11-22T12:00:00Z");
const portal = (id, extra = {}) => ({ credentialId: id, label: id, rpId: "basaltvault.app", createdAt: "2026-11-03T09:00:00Z", ...extra });

test("unlabeled columns are those with no class or UNCLASSIFIED", () => {
  const cols = [{ table: "public.a", column: "x" }, { table: "public.a", column: "y", class: "UNCLASSIFIED" }, { table: "public.a", column: "z", class: "PUBLIC" }, { column: "bad" }];
  assert.deepEqual(unlabeledColumns(cols).map((c) => c.column), ["x", "y"]);
  assert.deepEqual(unlabeledColumns(null), []);
});

test("the check screen counts what needs the person, with the local page's words", () => {
  const one = checkView({ columns: [{ table: "public.orders", column: "phone" }], passkeys: [portal("a"), portal("b")] });
  assert.equal(one.title, "1 thing needs you");
  assert.equal(one.sub, "Everything else is working.");
  assert.equal(one.button, "Fix these");
  assert.deepEqual(one.rows.map((r) => [r.mark, r.title, r.text, r.action]), [
    ["warn", "1 new column has no label", "orders.phone", "Label"],
    ["good", "Passkeys", "2 devices can approve", "Manage"],
  ]);

  const none = checkView({ columns: [], passkeys: [{ ...portal("l"), rpId: "localhost" }] });
  assert.equal(none.title, "1 thing needs you");
  assert.deepEqual(none.rows.map((r) => r.title), ["No passkey can approve"], "no portal passkey: no Passkeys row to manage");
  assert.equal(none.rows[0].text, "Your agents' larger writes wait until you add one.");

  const many = Array.from({ length: MAX_NAMED + 3 }, (_, i) => ({ table: "crm.t", column: `c${i}` }));
  const v = checkView({ columns: many, passkeys: [] });
  assert.equal(v.title, "2 things need you");
  assert.equal(v.rows[0].title, `${MAX_NAMED + 3} new columns have no label`);
  assert.ok(v.rows[0].text.endsWith(`crm.t.c${MAX_NAMED - 1}, …`));

  const good = checkView({ columns: [{ table: "public.a", column: "x", class: "SECRET" }], passkeys: [portal("a")] });
  assert.equal(good.title, "All good");
  assert.equal(good.sub, "BasaltDB is running and your agents can connect.");
  assert.equal(good.button, "Continue");
  assert.deepEqual(good.rows.map((r) => r.title), ["Every column has a label", "Database certificate checked", "Passkeys"]);
  assert.equal(good.rows[2].text, "1 device can approve");
});

test("a passkey's line: the day it was added, its site when not the portal's, and when it was used", () => {
  assert.equal(dayMonth("2026-11-03T23:30:00Z"), "3 Nov");
  assert.equal(usedText("", NOW), "never");
  assert.equal(usedText("2026-11-22T01:00:00Z", NOW), "today");
  assert.equal(usedText("2026-11-21T11:00:00Z", NOW), "1 day ago");
  assert.equal(usedText("2026-11-12T12:00:00Z", NOW), "10 days ago");
  assert.equal(usedText("2026-11-01T12:00:00Z", NOW), "3 weeks ago");
  assert.equal(passkeyLine(portal("a", { lastUsedAt: "2026-11-22T08:00:00Z" }), NOW), "Added 3 Nov · used today");
  assert.equal(passkeyLine({ ...portal("b"), rpId: "localhost" }, NOW), "Added 3 Nov on localhost · used never");
  assert.equal(portalCount([portal("a"), { ...portal("b"), rpId: "localhost" }, { label: "no id" }]), 1);
});

test("removing names the passkey, and warns when it is the site's last", () => {
  const a = portal("a");
  const b = portal("b");
  assert.equal(revokeLines(a, [a, b]).length, 1);
  assert.deepEqual(revokeLines(a, [a, { ...b, rpId: "localhost" }]), [
    "This removes the passkey a, added 3 Nov. It can no longer approve writes or sign undos.",
    "It is the last passkey for this site: until you add one, your agents' held writes and undos wait.",
  ]);
  assert.equal(ADD_AGAIN, "Add a passkey so your agents can be approved again.");
});

test("the bot's pin: a match, a new certificate, or the plain question", () => {
  const asking = { subject: "CN=Root", sha256: "ab".repeat(32), expiresAt: "2035-01-31T00:00:00Z" };
  assert.deepEqual(pinView("ab".repeat(32), asking), { state: "MATCH", fingerprint: Array(32).fill("AB").join(":") });
  const changed = pinView("cd".repeat(32), asking);
  assert.equal(changed.state, "CHANGED");
  assert.equal(changed.now, Array(32).fill("AB").join(":"));
  assert.equal(changed.was, Array(32).fill("CD").join(":"));
  assert.equal(changed.detail, "CN=Root, valid until 2035-01-31");
  for (const bad of ["", "AB".repeat(32), "ab".repeat(31), undefined]) assert.equal(pinView(bad, asking), null, String(bad));
  assert.equal(pinView("ab".repeat(32), null), null);
});

test("the browser is told only of a removed portal passkey, where it can be", async () => {
  const seen = [];
  const pkc = { signalUnknownCredential: async (a) => seen.push(a) };
  assert.equal(await signalRemoved(pkc, portal("a")), true);
  assert.deepEqual(seen, [{ rpId: "basaltvault.app", credentialId: "a" }]);
  assert.equal(await signalRemoved(pkc, { ...portal("b"), rpId: "localhost" }), false);
  assert.equal(await signalRemoved(undefined, portal("c")), false);
  assert.equal(await signalRemoved({ signalUnknownCredential: async () => { throw new Error("no"); } }, portal("d")), false);
  assert.equal(seen.length, 1);
});

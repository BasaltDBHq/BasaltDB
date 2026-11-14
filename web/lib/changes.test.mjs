// Runs with `node --test web/lib/*.test.mjs` (make web-check). The Changes
// panel: one table per table, hidden rows as dots until the person reveals
// them, then their values labelled as shown to them only.
import { test } from "node:test";
import assert from "node:assert/strict";

import { countText, HIDDEN_CHIP, HIDDEN_VALUE, SHOWN_CHIP } from "./changes.js";
import { OPEN_FROM_ENGINE, SECRET_VALUE } from "./reveal.js";
// Imported before any document exists, so the page's main() does not run.
import { approveLabel, lineGroups } from "./approve.js";
import { summarize } from "./summary.js";

function fakeElement(tag) {
  return {
    tag,
    className: "",
    textContent: "",
    children: [],
    append(...nodes) {
      this.children.push(...nodes);
    },
  };
}

const lead = {
  op: "DELETE", table: "public.leads", cascaded: false, redacted: false, rowHash: null,
  key: { id: 4 }, old: { id: 4, name: "Dana" }, set: null, texts: null,
};
const hidden = (n) => ({
  op: "DELETE", table: "public.lead_notes", cascaded: true, redacted: true, rowHash: String(n).repeat(64),
  key: null, old: null, set: null, texts: null,
});

const texts = (g) => g.children.map((c) => c.textContent);
const head = (g) => g.children[0].children.map((c) => [c.className, c.textContent]);
const table = (g) => g.children.find((c) => c.className === "scroll").children[0];
const rows = (g) => table(g).children.map((r) => r.children.map((c) => c.textContent));

test("rows group by table, cascaded rows apart, in the order they come", () => {
  globalThis.document = { createElement: fakeElement };
  const groups = lineGroups([lead, hidden(1), hidden(2)]);
  assert.equal(groups.length, 2);
  assert.deepEqual(head(groups[0]), [["table-name", "public.leads"], ["count", "1 row"]]);
  assert.deepEqual(rows(groups[0]), [["", "id", "name"], ["−", "4", "Dana"]]);
  assert.deepEqual(head(groups[1]), [
    ["table-name", "public.lead_notes"], ["count", "2 rows"], ["tag", "cascaded"], ["tag", HIDDEN_CHIP],
  ]);
});

test("a hidden row shows dots, never an empty cell, and a long link says where to see it", () => {
  globalThis.document = { createElement: fakeElement };
  const [g] = lineGroups([hidden(1)], new Map(), false);
  assert.deepEqual(rows(g), [["", "values"], ["−", HIDDEN_VALUE]]);
  assert.ok(!texts(g).includes(OPEN_FROM_ENGINE));
  const [long] = lineGroups([hidden(1)], new Map(), true);
  assert.ok(texts(long).includes(OPEN_FROM_ENGINE));
  assert.equal(OPEN_FROM_ENGINE, "Values are hidden on this link. Open the short link to see them.");
});

test("revealed values are shown to the person only; a secret column is withheld and its row not checked", () => {
  globalThis.document = { createElement: fakeElement };
  const shown = new Map([
    [0, { checked: true, values: [{ id: 7 }, { id: 7, body: "Called" }, null], texts: [[], [], []], secretColumns: [] }],
    [1, { checked: false, values: [{ id: 8 }, { id: 8, body: null }, null], texts: [[], [["body", "null"]], []], secretColumns: ["body"] }],
  ]);
  const [g] = lineGroups([hidden(1), hidden(2)], shown);
  assert.deepEqual(head(g).at(-1), ["tag shown", SHOWN_CHIP]);
  assert.deepEqual(rows(g), [["", "id", "body"], ["−", "7", "Called"], ["−", "8", SECRET_VALUE]]);
  const [, , secretRow] = table(g).children;
  assert.equal(secretRow.className, "del unchecked");
  assert.equal(secretRow.children[2].className, "secret");
  assert.ok(texts(g).includes("Row id = 8 has a secret column, so this page can't check it against what you sign."));
});

test("an update shows the row before and after, the set columns highlighted", () => {
  globalThis.document = { createElement: fakeElement };
  const update = { ...lead, op: "UPDATE", set: { name: "Dana W" } };
  const [g] = lineGroups([update]);
  const [, was, now] = table(g).children;
  assert.deepEqual(was.children.map((c) => [c.className, c.textContent]), [["mk", "−"], ["", "4"], ["was", "Dana"]]);
  assert.deepEqual(now.children.map((c) => [c.className, c.textContent]), [["mk", "+"], ["", "4"], ["set", "Dana W"]]);
});

test("the count names each kind of change", () => {
  assert.deepEqual(countText([lead, hidden(1), { ...lead, op: "INSERT" }]), [
    { op: "DELETE", text: "−2 rows" },
    { op: "INSERT", text: "+1 row" },
  ]);
  assert.deepEqual(countText([lead, { ...lead, op: "MERGE" }]), [{ op: "DELETE", text: "\u22121 row" }], "another op is not counted");
});

test("rows list by key, numbers as numbers, the table's own rows before cascaded ones", () => {
  globalThis.document = { createElement: fakeElement };
  const row = (id, extra = {}) => ({ ...lead, key: { id }, old: { id, name: `n${id}` }, ...extra });
  const groups = lineGroups([hidden(1), row(10), row(9), row(100), { ...row(5), table: "public.a_first" }]);
  assert.deepEqual(groups.map((g) => g.children[0].children[0].textContent), ["public.a_first", "public.leads", "public.lead_notes"]);
  assert.deepEqual(rows(groups[1]).slice(1).map((r) => r[1]), ["9", "10", "100"]);
  const big = [row(9007199254740993), row(9007199254740992)];
  big[0].texts = { key: new Map([["id", "9007199254740993"]]), old: new Map([["id", "9007199254740993"]]) };
  big[1].texts = { key: new Map([["id", "9007199254740992"]]), old: new Map([["id", "9007199254740992"]]) };
  assert.deepEqual(rows(lineGroups(big)[0]).slice(1).map((r) => r[1]), ["9007199254740992", "9007199254740993"], "past 2^53 by the exact text");
  const words = lineGroups([row("b"), row("B"), row("a")]);
  assert.deepEqual(rows(words[0]).slice(1).map((r) => r[1]), ["B", "a", "b"], "text by code point, not locale");
});

test("the approve button counts the write's own rows, and the cascade apart", () => {
  const one = { ...lead, key: { id: 5 }, old: { id: 5 } };
  assert.equal(approveLabel(summarize([lead])), "Sign with your passkey: delete 1 row");
  assert.equal(approveLabel(summarize([lead, one])), "Sign with your passkey: delete 2 rows");
  assert.equal(approveLabel(summarize([lead, hidden(1), hidden(2)])), "Sign with your passkey: delete 1 row + 2 cascaded", "not 3 rows");
  assert.equal(approveLabel(summarize([lead, hidden(1)])), "Sign with your passkey: delete 1 row + 1 cascaded");
  const update = { ...lead, op: "UPDATE", set: { name: "x" } };
  assert.equal(approveLabel(summarize([update, { ...update, key: { id: 5 } }])), "Sign with your passkey: update 2 rows");
});

test("columns follow the table's order when the engine sends it, unlisted ones last; the rows' order without it", () => {
  globalThis.document = { createElement: fakeElement };
  const row = { ...lead, old: { id: 4, name: "Dana", score: 3, status: "open", extra: "x" } };
  const order = new Map([["public.leads", ["id", "name", "status", "score", "gone"]]]);
  assert.deepEqual(rows(lineGroups([row], new Map(), false, order)[0])[0], ["", "id", "name", "status", "score", "extra"]);
  assert.deepEqual(rows(lineGroups([row])[0])[0], ["", "id", "name", "score", "status", "extra"], "a long link keeps the rows' order");
});

test("a value over 1 MiB of text shows by size and sha256, the hash filled in once computed", async () => {
  globalThis.document = { createElement: fakeElement };
  const big = "a".repeat((1 << 20) + 1);
  const row = { ...lead, old: { id: 4, body: big }, texts: null };
  const [g] = lineGroups([row]);
  const cell = table(g).children[1].children[2];
  assert.equal(cell.className, "large");
  assert.match(cell.textContent, /^too large to show: 1\.0 MiB, sha256 (…|[0-9a-f]{64})\nYour signature covers the full value\.$/);
  const { largeHash } = await import("./large.js");
  const hash = await largeHash(big);
  await new Promise((r) => setTimeout(r, 0));
  assert.equal(cell.textContent, `too large to show: 1.0 MiB, sha256 ${hash}\nYour signature covers the full value.`);
  // Exactly 1 MiB is drawn.
  const [h] = lineGroups([{ ...lead, old: { id: 4, body: "a".repeat(1 << 20) } }]);
  assert.equal(table(h).children[1].children[2].textContent.length, 1 << 20);
});

// Runs with `node --test web/lib/*.test.mjs` (make web-check). The Changes
// panel: one table per table, hidden rows as dots until the person reveals
// them, then their values labelled as shown to them only.
import { test } from "node:test";
import assert from "node:assert/strict";

import { countText, HIDDEN_CHIP, HIDDEN_VALUE, SHOWN_CHIP } from "./changes.js";
import { NOT_CHECKED, OPEN_FROM_ENGINE, SECRET_VALUE } from "./reveal.js";
// Imported before any document exists, so the page's main() does not run.
import { lineGroups } from "./approve.js";

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
  assert.ok(texts(g).includes(`Row id = 8. ${NOT_CHECKED}`));
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

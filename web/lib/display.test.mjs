// Runs with `node --test web/lib/*.test.mjs` (make web-check). What the
// approval and revert pages show must be what the passkey signs: exact
// numbers, and no character that hides or reorders text.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import { paramsText, parseBinding, parseLine, parseRevertLine, visibleText } from "./codec.js";
// Imported before any document exists, so the pages' main() does not run.
import { lineGroups as approvalGroups } from "./approve.js";
import { lineGroups as revertGroups } from "./revert.js";

const BINDING =
  '{"kind": "APPROVE", "rows": 1, "agent": "agent:bot", "runId": "0190a3f2-7c1e-7000-8000-000000000003", ' +
  '"store": {"kind": "POSTGRES", "name": "app"}, "intent": "fix", ' +
  '"request": {"kind": "SQL", "params": [9007199254740993, 1e400, "0001\u202e", {"n": 12345678901234567891}], "statement": "UPDATE t SET a = $1"}, ' +
  '"rowsHash": "14caa48f26bad4a8e9febd038704ee65a3922fad6a0a1b5f30d16a49cb27db80", ' +
  '"expiresAt": "2026-11-11T07:02:11.123456Z", ' +
  '"approvalId": "0190a3f2-7c1e-7000-8000-000000000001", "assignedFields": ["a"]}';

test("params show as the signed text, not as JSON.parse rounds them", () => {
  const b = parseBinding(BINDING);
  assert.equal(JSON.stringify(b.request.params[0]), "9007199254740992", "JSON.parse rounds past 2^53");
  assert.equal(JSON.stringify(b.request.params[1]), "null", "and turns 1e400 into Infinity, printed as null");
  const shown = visibleText(paramsText(BINDING));
  assert.equal(shown, '[9007199254740993, 1e400, "0001<U+202E>", {"n": 12345678901234567891}]');
  assert.equal(paramsText('{"kind": "APPROVE", "request": {"kind": "SQL", "params": []}}'), "[]");
});

test("visibleText escapes bidi, invisible and C1 characters and keeps the rest", () => {
  assert.equal(visibleText("0001\u202e"), "0001<U+202E>");
  assert.equal(visibleText("a\u200bb"), "a<U+200B>b");
  assert.equal(visibleText("a\u009bb"), "a<U+009B>b");
  assert.equal(visibleText("a\nb\tc\x1b[31m"), "a<U+000A>b<U+0009>c<U+001B>[31m");
  assert.equal(visibleText("a\u00a0b\u2028c\u3164"), "a<U+00A0>b<U+2028>c<U+3164>");
  assert.equal(visibleText("lone \ud800"), "lone <U+D800>");
  assert.equal(visibleText("tag \u{e0041}"), "tag <U+E0041>");
  assert.equal(visibleText("note 5 — 日本 🚀 José"), "note 5 — 日本 🚀 José");
  assert.equal(visibleText("SELECT 1\n\tFROM t\r", { lines: true }), "SELECT 1\n\tFROM t<U+000D>");
});

const cp = (...points) => String.fromCodePoint(...points);

// selectorsWith lists the selectors of every rule in style.css whose body
// holds all of the given declarations.
function selectorsWith(css, ...declarations) {
  const out = new Set();
  for (const [, selectors, body] of css.replace(/\/\*[\s\S]*?\*\//g, "").matchAll(/([^{}]+)\{([^}]*)\}/g)) {
    if (!declarations.every((d) => body.includes(d))) continue;
    for (const s of selectors.split(",")) out.add(s.trim());
  }
  return out;
}

test("the stylesheet pins agent-written text to stored order and clips what overflows", () => {
  const css = readFileSync(new URL("../style.css", import.meta.url), "utf8");
  const pinned = selectorsWith(css, "direction: ltr", "unicode-bidi: isolate-override");
  for (const s of [".values td", "#params", "#statement", "#intent"]) assert.ok(pinned.has(s), `${s} is not isolate-override`);
  const clipped = selectorsWith(css, "overflow: hidden");
  for (const s of [".values td", ".summary dd"]) assert.ok(clipped.has(s), `${s} does not clip overflow`);
});

test("a short value's cell is never capped, so a 32-code-point CJK value cannot clip", () => {
  const css = readFileSync(new URL("../style.css", import.meta.url), "utf8").replace(/\/\*[\s\S]*?\*\//g, "");
  assert.ok(selectorsWith(css, "max-width: none").has(".values td:not(.long)"), "short cells must lift the 32ch cap");
  // The cap (.values td) must only reach cells marked long.
  assert.ok(selectorsWith(css, "max-width: 32ch").has(".values td"));
  const cjk = "漢".repeat(32);
  assert.equal([...cjk].length, 32);
  assert.ok(!([...cjk].length > 32), "32 code points is not long, so it takes the uncapped path");
});

test("visibleText escapes every default-ignorable character, variation selectors included", () => {
  assert.equal(visibleText(`a${cp(0xfe0f)}b`), "a<U+FE0F>b");
  assert.equal(visibleText(`a${cp(0xe0100)}b`), "a<U+E0100>b");
  assert.equal(visibleText(`a${cp(0x180b)}b`), "a<U+180B>b");
});

test("visibleText keeps two combining marks in a row and escapes the rest", () => {
  const mark = cp(0x353);
  assert.equal(visibleText(`e${cp(0x301)}`), `e${cp(0x301)}`);
  assert.equal(visibleText(`0${mark}${mark}${mark}x${mark}`), `0${mark}${mark}<U+0353>x${mark}`);
  assert.equal(visibleText(`0${mark.repeat(300)}`), `0${mark}${mark}${"<U+0353>".repeat(298)}`);
});

// A minimal DOM: enough for el() and the row tables.
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

// cells reads the one table of rendered groups back as the page shows it:
// the header, then per row its cell texts.
function cells(groups) {
  assert.equal(groups.length, 1);
  const table = groups[0].children.find((c) => c.className === "scroll").children[0];
  return table.children.map((r) => r.children.map((c) => c.textContent));
}

test("the approval page shows hidden characters in values and columns as escapes, and exact numbers", () => {
  globalThis.document = { createElement: fakeElement };
  const line = parseLine(
    '{"op": "UPDATE", "key": {"id": 9007199254740993}, "old": {"code": "1000", "n": 1e400}, ' +
      '"set": {"code": "0001\u202e\u200b\u009b", "n\u202e": 9007199254740993}, "shape": "RECORD", "store": {"kind": "POSTGRES", "verb": "UPDATE"}, "cascaded": false, "resource": "public.leads"}',
  );
  assert.deepEqual(cells(approvalGroups([line])), [
    ["", "id", "code", "n", "n<U+202E>"],
    ["\u2212", "9007199254740993", "1000", "1e400", ""],
    ["+", "9007199254740993", "0001<U+202E><U+200B><U+009B>", "1e400", "9007199254740993"],
  ]);
});

test("the revert page shows hidden characters in values as escapes", () => {
  globalThis.document = { createElement: fakeElement };
  const line = parseRevertLine(
    '{"op": "UPDATE", "key": {"id": 1}, "now": {"code": "1000"}, "set": {"code": "0001\u202e"}, "shape": "RECORD", ' +
      '"store": {"code": null, "kind": "POSTGRES", "verb": "UPDATE"}, "action": "RESTORE", "cascaded": false, "conflict": null, ' +
      '"resource": "public.leads", "changeIds": ["0190a3f2-7c1e-7000-8000-000000000002"]}',
  );
  assert.deepEqual(cells(revertGroups([{ line, index: 0 }])), [
    ["", "id", "code"],
    ["\u2212", "1", "1000"],
    ["+", "1", "0001<U+202E>"],
  ]);
});

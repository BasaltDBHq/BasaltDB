// Runs with `node --test web/lib/*.test.mjs` (make web-check). Runs format
// 2's shared vectors (api/mcp/links/compact-request.json), which Go's
// internal/core/linkcodec writes and runs too, through the pages' decoders.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { deflateRawSync } from "node:zlib";

import { CodeError, b64urlEncode, displayValue, parseApprovalRequest, parseLine, parseRevertLine, parseRevertRequest } from "./codec.js";
import { CompactError, quote, rebuildTexts } from "./compact.js";

const vectors = JSON.parse(
  readFileSync(new URL("../../api/mcp/links/compact-request.json", import.meta.url), "utf8"),
);

const parsers = { APPROVE: parseApprovalRequest, REVERT: parseRevertRequest };

for (const v of vectors.valid) {
  test(`format 2 decodes: ${v.name}`, async () => {
    const req = await parsers[v.kind]("#" + v.fragment);
    assert.equal(req.bindingText, v.binding);
    assert.deepEqual(req.lines.length, v.lines.length);
    assert.deepEqual(req.credentialIds.map(b64urlEncode), v.credentialIds ?? [], "the link's credential ids, or none");
    assert.deepEqual(rebuildTexts(v.payload, v.lines.length + 1), [v.binding, ...v.lines]);
  });
}

for (const v of vectors.invalid) {
  test(`format 2 refuses: ${v.name}`, async () => {
    await assert.rejects(parsers[v.kind](v.fragment), CodeError);
  });
}

test("the ids come from the binding", async () => {
  const [approval] = vectors.valid.filter((v) => v.kind === "APPROVE");
  const [revert] = vectors.valid.filter((v) => v.kind === "REVERT");
  assert.equal((await parseApprovalRequest(approval.fragment)).approvalId, JSON.parse(approval.binding).approvalId);
  assert.equal((await parseRevertRequest(revert.fragment)).revertId, JSON.parse(revert.binding).revertId);
});

test("quote escapes as Postgres's escape_json", () => {
  assert.equal(quote('a"b\\c\b\f\n\r\t\u0001\u001f é 🚀 \u007f'), '"a\\"b\\\\c\\b\\f\\n\\r\\t\\u0001\\u001f é 🚀 \u007f"');
});

test("numbers rebuild as Go rebuilds them", () => {
  assert.deepEqual(rebuildTexts([[["a", "b", "c"]], [[0, 1.0, 1e2, -7]]], 1), ['{"a": 1, "b": 100, "c": -7}']);
  assert.throws(() => rebuildTexts([[["a"]], [[0, -0]]], 1), CompactError);
  assert.throws(() => rebuildTexts([[["a"]], [[0, 2 ** 53]]], 1), CompactError);
});

test("a format 2 fragment that is cut short reads as truncated", async () => {
  const [v] = vectors.valid;
  await assert.rejects(parseApprovalRequest(v.fragment.slice(0, 40)), { name: "TruncatedLinkError" });
  await assert.rejects(parseApprovalRequest("#2."), { name: "TruncatedLinkError" });
});

test("a large format 2 request stays within the caps", async () => {
  const name = "n".repeat(30_000);
  const payload = [[[name]], Array.from({ length: 40 }, () => [0, 1])];
  const fragment = "2." + b64urlEncode(deflateRawSync(Buffer.from(JSON.stringify(payload))));
  assert.ok(fragment.length < 2000, "a small link");
  await assert.rejects(parseApprovalRequest(fragment), /past 1 MiB/);
});

test("the page shows each value as the line carries it, not as JSON.parse rounds it", async () => {
  const v = vectors.valid.find((c) => c.name.startsWith("every kind of value"));
  const req = await parseApprovalRequest(v.fragment);
  const line = req.lines.find((l) => l.table === "public.items");
  const shown = (member, col) => displayValue(line[member][col], line.texts[member].get(col));
  assert.equal(line.old.big, 9007199254740992, "JSON.parse rounds it");
  assert.equal(shown("old", "big"), "9007199254740993");
  assert.equal(shown("old", "price"), "1.50");
  assert.equal(shown("set", "price"), "2.00");
  assert.equal(shown("old", "doc"), '{"a": [1, 2], "b": null}');
  assert.equal(shown("old", "tags"), '["x", "y", []]');
  assert.equal(shown("old", "note"), line.old.note, "a string shows as itself");
  assert.equal(shown("old", "neg"), "-42");
  assert.equal(shown("old", "flag"), "true");
  assert.ok(v.lines.some((l) => l.includes('"big": 9007199254740993')), "the hashed text holds the exact value");
});

test("revert lines keep each value's text too", () => {
  const text = '{"op": "UPDATE", "key": {"id": 1}, "now": {"id": 1, "n": 12345678901234567890}, "set": {"id": 1, "n": 0.10}, "table": "public.t", "action": "RESTORE", "cascaded": false, "conflict": null, "sqlState": null, "changeIds": ["0193a4c2-7d1e-7c3a-9f00-0000000000e1"]}';
  const line = parseRevertLine(text);
  assert.equal(displayValue(line.now.n, line.texts.now.get("n")), "12345678901234567890");
  assert.equal(displayValue(line.set.n, line.texts.set.get("n")), "0.10");
  assert.equal(parseLine('{"op": "DELETE", "table": "public.t", "rowHash": "ab", "cascaded": true, "redacted": true}').texts, null);
});

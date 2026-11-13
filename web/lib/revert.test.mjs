// Runs with `node --test web/lib/*.test.mjs` (make web-check). Reads the
// fixtures the Go tests write, so the revert page and internal/revert agree.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { deflateRawSync, inflateRawSync } from "node:zlib";

import {
  CodeError,
  MAX_REVERT_BATCH,
  MAX_REVERT_LINES,
  REVERT_APPLY_HOURS,
  REVERT_SAMPLE_SHARE,
  b64urlDecode,
  b64urlEncode,
  checkRevertRequest,
  encodeRevertResponse,
  parseApprovalRequest,
  parseRevertBinding,
  parseRevertLine,
  parseRevertRequest,
  revertSampleCounts,
  revertShown,
  rowsHash,
} from "./codec.js";
// Imported before any document exists, so the page's main() does not run.
import { agentTag, lineGroups, rowKeyText } from "./revert.js";

const fixtures = JSON.parse(
  readFileSync(new URL("../../internal/revert/testdata/fixtures.json", import.meta.url), "utf8"),
);

function requestFragment(obj) {
  return "1." + b64urlEncode(deflateRawSync(Buffer.from(JSON.stringify(obj))));
}

test("revert request from Go decodes and checks", async () => {
  const f = fixtures.request;
  const req = await parseRevertRequest("#" + f.fragment);
  assert.equal(req.revertId, f.revertId);
  assert.equal(req.bindingText, f.binding);
  assert.equal(req.binding.select.scope, "RUN");
  assert.equal(req.binding.widened, false);
  assert.equal(req.binding.rows, 3);
  assert.equal(req.binding.skipped, 1);
  assert.deepEqual(req.binding.select.agents, ["basalt_agent_bot"]);
  assert.equal(req.binding.expiresAt.toISOString(), "2026-11-11T07:02:11.123Z");
  assert.equal(b64urlEncode(req.challenge), f.challenge);
  assert.deepEqual(req.credentialIds.map(b64urlEncode), f.credentialIds);
  assert.equal(await rowsHash(f.lines), f.rowsHash);

  assert.equal(req.lines[0].redacted, true);
  assert.equal(req.lines[0].action, "RESTORE");
  assert.equal(req.lines[1].op, "INSERT");
  assert.equal(req.lines[1].set.note, "note 5 — 日本 🚀");
  assert.equal(req.lines[2].now.status, "merged");
  assert.equal(req.lines[2].set.status, "open");
  assert.deepEqual(req.lines[2].changeIds.length, 2);
  assert.equal(req.lines[3].action, "SKIP");
  assert.equal(req.lines[3].conflict, "CHANGED_AFTER");
});

test("the engine's revert request may carry the next widen's nonce; a long link may not", async () => {
  const f = fixtures.request;
  const base = { revertId: f.revertId, binding: f.binding, lines: f.lines };
  const nonce = "AAECAwQFBgcICQoLDA0ODw";
  const req = await checkRevertRequest({ ...base, rescopeNonce: nonce });
  assert.equal(req.rescopeNonce, nonce);
  assert.equal((await checkRevertRequest(base)).rescopeNonce, null);
  await assert.rejects(checkRevertRequest({ ...base, rescopeNonce: "short" }), /rescopeNonce/);
  await assert.rejects(parseRevertRequest(requestFragment({ ...base, rescopeNonce: nonce })), /unknown field/);
});

test("revert request refuses anything that does not match the binding", async () => {
  const f = fixtures.request;
  const base = { revertId: f.revertId, binding: f.binding, lines: f.lines };
  const changed = [...f.lines];
  changed[3] = changed[3].replace('"won"', '"lost"');
  const unskipped = [...f.lines];
  unskipped[3] = unskipped[3].replace('"SKIP"', '"RESTORE"').replace('"CHANGED_AFTER"', "null");
  const cases = [
    ["a line changed", { ...base, lines: changed }, /rowsHash/],
    ["a skipped row turned into a restore", { ...base, lines: unskipped }, /rowsHash/],
    ["a line dropped", { ...base, lines: f.lines.slice(0, 3) }, /3 lines, binding 4/],
    ["lines reordered", { ...base, lines: [f.lines[1], f.lines[0], f.lines[2], f.lines[3]] }, /rowsHash/],
    ["another revert", { ...base, revertId: "0193a4c2-7d1e-7c3a-9f00-0000000000b2" }, /binding for/],
    ["unknown field", { ...base, extra: 1 }, /unknown field/],
    ["approval binding", { ...base, binding: f.binding.replace('"REVERT"', '"APPROVE"') }, /kind/],
    [
      "restore count",
      { ...base, binding: f.binding.replace('"rows": 3', '"rows": 2').replace('"skipped": 1', '"skipped": 2') },
      /RESTORE lines/,
    ],
  ];
  for (const [name, obj, want] of cases) {
    await assert.rejects(parseRevertRequest(requestFragment(obj)), (err) => {
      assert.ok(err instanceof CodeError, name);
      assert.match(err.message, want, name);
      return true;
    });
  }
  await assert.rejects(parseRevertRequest("3." + f.fragment.slice(2)), /must start with/);
  await assert.rejects(parseRevertRequest("1.@@"), /base64url/);
});

test("a revert link is not an approval link and the other way round", async () => {
  await assert.rejects(parseApprovalRequest(fixtures.request.fragment), /unknown field|missing/);
  const approvals = JSON.parse(
    readFileSync(new URL("../../internal/approval/testdata/fixtures.json", import.meta.url), "utf8"),
  );
  await assert.rejects(parseRevertRequest(approvals.request.fragment), /unknown field|missing/);
});

test("revert binding limits", () => {
  const b = fixtures.request.binding;
  assert.throws(() => parseRevertBinding(b.replace('"skipped": 1', '"skipped": 998')), /out of 1..1000/);
  assert.throws(() => parseRevertBinding(b.replace('"rows": 3', '"rows": 0')), /rows 0/);
  assert.throws(() => parseRevertBinding(b.replace('"RUN"', '"DATABASE"')), /scope/);
  assert.throws(() => parseRevertBinding(b.replace('["basalt_agent_bot"]', "[]")), /agents/);
  assert.throws(() => parseRevertBinding(b.replace('"widened": false', '"widened": false, "scope": "RUN"')), /unknown field "scope"/);
  assert.throws(() => parseRevertBinding(b.replace('"tables": null', '"tables": null, "store": "x"')), /unknown field "store"/);
  assert.throws(() => parseRevertBinding(b.replace('"runs": null', `"runs": ["${fixtures.request.revertId}"]`)), /lists runs/);
  assert.throws(() => parseRevertBinding(b.replace('["basalt_agent_bot"]', '["basalt_agent_bot", "basalt_agent_sync"]')), /widened false/);
  assert.throws(() => parseRevertBinding(b.replace('"widened": false', '"widened": false, "agentRows": {"x": 1}')), /agentRows/);
  assert.throws(() => parseRevertBinding(b.replace('"rows": 3', '"rows": 0').replace('"skipped": 1', '"skipped": 0')), /rows 0/);
  assert.equal(MAX_REVERT_LINES, 1000);
});

test("a widened select and an empty task proposal parse", () => {
  const b = fixtures.request.binding;
  const widened = parseRevertBinding(b.replace('["basalt_agent_bot"]', "null")
    .replace('"widened": false', '"widened": true, "agentRows": {"basalt_agent_bot": 3, "basalt_agent_sync": 1}'));
  assert.equal(widened.select.agents, null);
  assert.deepEqual(Object.keys(widened.agentRows), ["basalt_agent_bot", "basalt_agent_sync"]);
  const empty = parseRevertBinding(b.replace('"scope": "RUN"', '"scope": "TASK"').replace('"rows": 3', '"rows": 0')
    .replace('"skipped": 1', '"skipped": 0'));
  assert.equal(empty.rows + empty.skipped, 0);
});

test("a large plan's link carries its sample (N12-4)", async () => {
  const f = fixtures.batched;
  const req = await parseRevertRequest("#" + f.fragment);
  assert.equal(req.binding.batched, true);
  assert.equal(req.binding.rows + req.binding.skipped, f.lines);
  assert.equal(req.binding.sampleHash, f.sampleHash);
  assert.equal(req.lines.length, MAX_REVERT_LINES);
  assert.ok(req.lines.slice(0, f.skipped).every((l) => l.action === "SKIP"));
  assert.ok(req.lines.slice(f.skipped).every((l) => l.action === "RESTORE"));
  assert.equal(MAX_REVERT_BATCH, 200);
  assert.equal(REVERT_APPLY_HOURS, 24);

  const decoded = JSON.parse(inflateRawSync(Buffer.from(f.fragment.slice(2), "base64url")).toString("utf8"));
  const changed = [...decoded.lines];
  changed[500] = changed[500].replace('"agent"', '"person"');
  const reordered = [decoded.lines[f.skipped], ...decoded.lines.slice(0, f.skipped), ...decoded.lines.slice(f.skipped + 1)];
  const cases = [
    ["a sample line changed", { ...decoded, lines: changed }, /sampleHash/],
    ["a line short", { ...decoded, lines: decoded.lines.slice(1) }, /sample has 1000/],
    ["not batched", { ...decoded, binding: f.binding.replace('"batched": true, ', "") }, /not batched/],
    ["restores first", { ...decoded, lines: reordered }, /sampleHash/],
  ];
  for (const [name, obj, want] of cases) {
    await assert.rejects(parseRevertRequest(requestFragment(obj)), (err) => {
      assert.ok(err instanceof CodeError, name);
      assert.match(err.message, want, name);
      return true;
    });
  }
  assert.throws(() => parseRevertBinding(f.binding.replace('"rows": 1490', '"rows": 990')), /only a plan of more than 1000/);
  assert.throws(() => parseRevertBinding(f.binding.replace('"batched": true', '"batched": false')), /must be true/);
});

test("a large plan's sample keeps room for restored rows (RSS-1)", async () => {
  assert.equal(REVERT_SAMPLE_SHARE, 500);
  assert.deepEqual(revertSampleCounts(1500, 50), { skips: 950, restores: 50 });
  assert.deepEqual(revertSampleCounts(2000, 2000), { skips: 500, restores: 500 });
  assert.deepEqual(revertSampleCounts(10, 3000), { skips: 10, restores: 990 });
  assert.deepEqual(revertSampleCounts(3000, 0), { skips: 1000, restores: 0 });

  // Go built this sample from 1500 SKIP and 50 RESTORE lines: the page
  // accepts it and shows every RESTORE line.
  const f = fixtures.batchedSkips;
  const req = await parseRevertRequest("#" + f.fragment);
  assert.equal(req.binding.rows, f.rows);
  assert.equal(req.binding.skipped, f.skipped);
  assert.equal(req.lines.filter((l) => l.action === "RESTORE").length, 50);
  assert.equal(req.lines.filter((l) => l.action === "SKIP").length, 950);

  // The sample before RSS-1 (1000 SKIP lines, no RESTORE line) is refused,
  // even with a binding whose sampleHash matches it.
  const decoded = JSON.parse(inflateRawSync(Buffer.from(f.fragment.slice(2), "base64url")).toString("utf8"));
  const skips = decoded.lines.filter((l) => l.includes('"action": "SKIP"'));
  const old = [...skips, ...skips.slice(0, 50)];
  const binding = decoded.binding.replace(/"sampleHash": "[0-9a-f]+"/, `"sampleHash": "${await rowsHash(old)}"`);
  await assert.rejects(
    parseRevertRequest(requestFragment({ ...decoded, binding, lines: old })),
    /request has 1000 SKIP lines, the binding's sample 950/,
  );
});

test("the batchedSkips sample round-trips in format 2 (RSS-1)", async () => {
  const f = fixtures.batchedSkips;
  assert.ok(f.fragment2.startsWith("2."));
  const v1 = await parseRevertRequest("#" + f.fragment);
  const v2 = await parseRevertRequest("#" + f.fragment2);
  assert.equal(v2.bindingText, v1.bindingText);
  assert.deepEqual(v2.lines, v1.lines);
  assert.deepEqual(v2.credentialIds, [], "format 2 carries no credential ids");
  assert.deepEqual(revertShown(v2), { restoreShown: 50, skipShown: 950, restoreHidden: 0, skipHidden: 550 });
});

test("hidden counts come only from signed data", async () => {
  const req = await parseRevertRequest("#" + fixtures.batchedSkips.fragment);
  // The binding's totals less the lines that hash to sampleHash.
  assert.deepEqual(revertShown(req), { restoreShown: 50, skipShown: 950, restoreHidden: 0, skipHidden: 550 });
  const big = await parseRevertRequest("#" + fixtures.batched.fragment);
  assert.deepEqual(revertShown(big), { restoreShown: 990, skipShown: 10, restoreHidden: 500, skipHidden: 0 });

  // A link cannot add its own coverage figures: the request is strict, so
  // an unsigned field such as sampleCoverage is refused before anything is
  // shown, and revertShown reads only the binding and the checked lines.
  const decoded = JSON.parse(inflateRawSync(Buffer.from(fixtures.batchedSkips.fragment.slice(2), "base64url")).toString("utf8"));
  const forged = { ...decoded, sampleCoverage: { hiddenRestores: 0, hiddenSkips: 0 } };
  await assert.rejects(parseRevertRequest(requestFragment(forged)), /sampleCoverage|unknown field/);
  const extra = { ...req, sampleCoverage: { hiddenRestores: 0, hiddenSkips: 0 } };
  assert.deepEqual(revertShown(extra), revertShown(req));
});

test("revert lines", () => {
  const ok = fixtures.request.lines[2];
  assert.throws(() => parseRevertLine(ok.replace('"op": "UPDATE"', '"op": "MERGE"')), /op/);
  assert.throws(() => parseRevertLine(ok.replace('"RESTORE"', '"MAYBE"')), /action/);
  assert.throws(() => parseRevertLine(ok.replace('"conflict": null', '"conflict": "ROW_GONE"')), /RESTORE line/);
  assert.throws(() => parseRevertLine(ok.replace('"RESTORE"', '"SKIP"')), /SKIP line/);
  assert.throws(() => parseRevertLine(ok.replace('"table": "public.leads", ', "")), /missing/);
  assert.throws(
    () => parseRevertLine('{"op": "DELETE", "key": {"id": 3}, "old": {"id": 3}, "set": null, "table": "t", "cascaded": false}'),
    /unknown field|missing/,
  );
});

test("revert response matches Go byte for byte", () => {
  const f = fixtures.response;
  const code = encodeRevertResponse({
    revertId: f.revertId,
    credentialId: b64urlDecode(f.credentialId),
    authenticatorData: b64urlDecode(f.authenticatorData),
    clientDataJson: b64urlDecode(f.clientDataJson),
    signature: b64urlDecode(f.signature),
  });
  assert.equal(code, f.code);
  assert.ok(code.startsWith("basalt-revert.1."));
});

// A minimal DOM: enough for el() and the row table.
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

// tableRows reads the one rendered table of a line back as the page shows
// it: the header cells and, per row, its class, cell texts and cell classes.
function tableRows(line) {
  const groups = lineGroups([{ line, index: 0 }]);
  assert.equal(groups.length, 1);
  const table = groups[0].children.find((c) => c.className === "scroll").children[0];
  const [head, ...rows] = table.children;
  return {
    header: head.children.map((c) => c.textContent),
    rows: rows.map((r) => ({ className: r.className, cells: r.children.map((c) => c.textContent), classes: r.children.map((c) => c.className) })),
  };
}

test("a restored row shows now (\u2212) and after the revert (+); a skipped row only now, with why", async () => {
  globalThis.document = { createElement: fakeElement };
  const req = await parseRevertRequest("#" + fixtures.request.fragment);
  const restore = req.lines[2];
  const skip = req.lines[3];
  assert.equal(restore.action, "RESTORE");
  assert.equal(skip.action, "SKIP");

  const restored = tableRows(restore);
  assert.deepEqual(restored.rows.map((r) => [r.className, r.cells[0]]), [["del", "\u2212"], ["add", "+"]]);
  const status = restored.header.indexOf("status");
  assert.ok(status > 0);
  assert.notEqual(restored.rows[0].cells[status], restored.rows[1].cells[status]);
  assert.ok(!restored.header.includes("Why"));

  const skipped = tableRows(skip);
  assert.equal(skipped.header.at(-1), "Why");
  assert.equal(skipped.rows.length, 1);
  assert.equal(skipped.rows[0].className, "keep");
  assert.equal(skipped.rows[0].cells[0], "=");
  const shown = skipped.rows[0].cells;
  assert.ok(shown.includes("Edited by a person"));
  assert.ok(!shown.includes("Lead 7"), "the value the revert would have written is not shown");
  assert.equal(shown.at(-1), "Changed after the agent. Kept as it is now.");
});

test("a skipped row that is gone shows its key, not empty cells", async () => {
  globalThis.document = { createElement: fakeElement };
  const req = await parseRevertRequest("#" + fixtures.request.fragment);
  const skip = req.lines[3];
  const gone = { ...skip, conflict: "ROW_GONE", now: null };
  const text = rowKeyText(gone);
  assert.ok(text.startsWith("Row "), text);
  for (const col of Object.keys(skip.key)) {
    assert.ok(text.includes(col), `${text} names ${col}`);
  }
  assert.deepEqual(tableRows(gone).rows[0].cells, ["=", text, "No longer there, or not visible to the revert."]);
  assert.equal(rowKeyText({ ...gone, key: null }), "Row key not recorded.");
});

test("a skipped re-insert whose key is taken shows the row that holds the key now", async () => {
  globalThis.document = { createElement: fakeElement };
  const req = await parseRevertRequest("#" + fixtures.request.fragment);
  const skip = req.lines[3];
  const taken = { ...skip, op: "INSERT", conflict: "KEY_TAKEN" };
  const t = tableRows(taken);
  assert.equal(t.rows.length, 1);
  assert.equal(t.rows[0].className, "keep");
  assert.ok(t.rows[0].cells.includes("Edited by a person"), "the row holding the key");
  assert.ok(!t.rows[0].cells.includes("Lead 7"), "not the row the revert would have written");
  assert.equal(t.rows[0].cells.at(-1), "Another row now has this key.");
});

test("every conflict kind shows the row now, or its key when it is gone, whatever the op", async () => {
  globalThis.document = { createElement: fakeElement };
  const req = await parseRevertRequest("#" + fixtures.request.fragment);
  const skip = req.lines[3];
  const reasons = {
    CHANGED_AFTER: "Changed after the agent. Kept as it is now.",
    ROW_GONE: "No longer there, or not visible to the revert.",
    KEY_TAKEN: "Another row now has this key.",
    ALREADY_REVERTED: "Already reverted.",
    VALUES_PRUNED: "Older than 30 days: the old values are gone.",
    SCHEMA_CHANGED: "The table changed since the agent wrote it.",
    CASCADE: "Restoring it would change rows that are not part of this revert.",
    CONSTRAINT: "Restoring it would break a database constraint.",
  };
  for (const [conflict, reason] of Object.entries(reasons)) {
    for (const op of ["INSERT", "UPDATE", "DELETE"]) {
      const line = { ...skip, op, conflict };
      const t = tableRows(line);
      assert.equal(t.rows.length, 1, `${conflict} ${op}`);
      const now = Object.keys(skip.now).map((c) => t.rows[0].cells[t.header.indexOf(c)]);
      assert.ok(now.includes("Edited by a person"), `${conflict} ${op} shows the row now`);
      assert.ok(!t.rows[0].cells.includes("Lead 7"), `${conflict} ${op} hides what it would have written`);
      assert.equal(t.rows[0].cells.at(-1), reason);
      const gone = tableRows({ ...line, now: null });
      assert.deepEqual(gone.rows[0].cells, ["=", rowKeyText(line), reason], `${conflict} ${op} gone`);
    }
  }
});

test("a changed column shows the value now struck through and the value it goes back to", async () => {
  globalThis.document = { createElement: fakeElement };
  const req = await parseRevertRequest("#" + fixtures.request.fragment);
  const t = tableRows(req.lines[2]);
  const status = t.header.indexOf("status");
  assert.equal(t.rows[0].classes[status], "was");
  assert.equal(t.rows[1].classes[status], "set");
  const same = t.header.findIndex((col, i) => i > 0 && t.rows[0].cells[i] === t.rows[1].cells[i]);
  assert.ok(same > 0, "some column does not change");
  assert.deepEqual([t.rows[0].classes[same], t.rows[1].classes[same]], ["", ""]);
});

test("a row from another agent than the requester is tagged amber", () => {
  globalThis.document = { createElement: fakeElement };
  const own = agentTag({ role: "basalt_agent_bot", other: false });
  assert.equal(own.className, "ag");
  assert.equal(own.textContent, "bot");
  assert.equal(own.title, "basalt_agent_bot");
  const other = agentTag({ role: "basalt_agent_sync", other: true });
  assert.equal(other.className, "ag other");
  assert.equal(other.textContent, "sync");
  // A role name is shown as text with its hidden characters escaped.
  assert.equal(agentTag({ role: "basalt_agent_a‮b", other: true }).textContent, "a<U+202E>b");
});

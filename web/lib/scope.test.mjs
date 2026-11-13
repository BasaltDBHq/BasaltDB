// Runs with `node --test web/lib/*.test.mjs` (make web-check). The revert
// page's decision panel: who changed the rows, the headline, what the person
// signs, and the Reject note sent to the engine.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import { parseRevertBinding, parseRevertRequest } from "./codec.js";
import { revertPaths, rejectRevert } from "./local.js";
import {
  MAX_NOTE,
  agentName,
  expiresIn,
  headline,
  noteLength,
  noteProblem,
  rejectBody,
  rejectDone,
  rowAgent,
  signingSummary,
} from "./scope.js";

const fixtures = JSON.parse(
  readFileSync(new URL("../../internal/revert/testdata/fixtures.json", import.meta.url), "utf8"),
);
const BINDING = fixtures.request.binding;
const ID = fixtures.request.revertId;

// widen turns the fixture's own proposal into a widened select, as the
// engine returns it after the person's widen proof.
function widen(agentRows, agents = "null") {
  return parseRevertBinding(BINDING.replace('["basalt_agent_bot"]', agents)
    .replace('"widened": false', `"widened": true, "agentRows": ${JSON.stringify(agentRows)}`));
}

test("agent roles show by their short name", () => {
  assert.equal(agentName("basalt_agent_bot"), "bot");
  assert.equal(agentName("acme_agent_sync_2"), "sync_2");
  assert.equal(agentName("reporter"), "reporter");
  assert.equal(agentName("basalt_agent_"), "basalt_agent_");
});

test("a row is tagged with its agent only when the signed select names one", () => {
  const own = parseRevertBinding(BINDING);
  assert.deepEqual(rowAgent(own), { role: "basalt_agent_bot", other: false });
  // The person kept only another agent's changes: every row is that
  // agent's, and it is not the requester.
  const onlySync = widen({ basalt_agent_sync: 4 }, '["basalt_agent_sync"]');
  assert.deepEqual(rowAgent(onlySync), { role: "basalt_agent_sync", other: true });
  // Several agents: the lines do not say whose each one is, so no row is
  // tagged rather than tagged wrong.
  assert.equal(rowAgent(widen({ basalt_agent_bot: 3, basalt_agent_sync: 1 })), null);
  // agents null with a single agent in the scope.
  assert.deepEqual(rowAgent(widen({ basalt_agent_sync: 4 })), { role: "basalt_agent_sync", other: true });
});

test("the headline says whose rows and when the person widened", () => {
  const own = headline(parseRevertBinding(BINDING));
  assert.equal(own.title, "Undo 3 rows that bot changed");
  assert.equal(own.widened, false);
  assert.equal(own.lede, "Nothing changes until you sign with your passkey.");

  const wide = headline(widen({ basalt_agent_bot: 3, basalt_agent_sync: 1 }));
  assert.equal(wide.title, "Undo 3 rows in this run");
  assert.equal(wide.widened, true);
  assert.equal(wide.lede, "bot proposed its own 3. You added sync's 1. bot can't see the rows you added.");

  const one = headline(parseRevertBinding(BINDING.replace('"rows": 3', '"rows": 1').replace('"skipped": 1', '"skipped": 0')));
  assert.equal(one.title, "Undo 1 row that bot changed");
});

test("what the person signs counts rows and the tables they are in", async () => {
  const req = await parseRevertRequest("#" + fixtures.request.fragment);
  const tables = new Set(req.lines.filter((l) => l.action === "RESTORE").map((l) => l.table)).size;
  assert.equal(signingSummary(req), `You're signing 3 rows in ${tables} ${tables === 1 ? "table" : "tables"}.`);
  // A large plan shows only a sample: the table count is not signed data.
  const big = await parseRevertRequest("#" + fixtures.batched.fragment);
  assert.equal(signingSummary(big), `You're signing ${big.binding.rows} rows.`);
});

test("the link's time left reads in minutes", () => {
  const now = new Date("2026-11-11T06:10:00Z");
  assert.equal(expiresIn(new Date("2026-11-11T07:02:11Z"), now), "Link expires in 53 min");
  assert.equal(expiresIn(new Date("2026-11-11T06:10:30Z"), now), "Link expires in 1 min");
  assert.equal(expiresIn(new Date("2026-11-11T06:09:00Z"), now), "Link expired");
});

test("the note follows the engine's rules: 500 characters, no control characters", () => {
  assert.equal(MAX_NOTE, 500);
  assert.equal(noteProblem(""), null);
  assert.equal(noteProblem("Merge the duplicates instead.\n\tThanks"), null);
  assert.equal(noteLength("日本 🚀"), 4, "code points, as the engine counts them");
  assert.equal(noteProblem("🚀".repeat(500)), null);
  assert.match(noteProblem("a".repeat(501)), /500/);
  for (const bad of ["a\u0000b", "a\rb", "a\u001bb", "a\u007fb", "a\u0085b", "a‮b", "a⁦b", "a‏b", "a؜b"]) {
    assert.match(noteProblem(bad), /control/, JSON.stringify(bad));
  }
});

test("the reject body carries the note only when there is one", () => {
  assert.equal(rejectBody(""), "{}");
  assert.equal(rejectBody("  \n "), "{}");
  assert.equal(rejectBody("Merge them instead"), '{"note":"Merge them instead"}');
  assert.throws(() => rejectBody("a".repeat(501)), /500/);
});

test("the reject result says nothing was reverted and who reads the note", () => {
  assert.equal(rejectDone(false, "basalt_agent_bot"), "Rejected. Nothing was reverted, and bot was told.");
  assert.equal(rejectDone(true, "basalt_agent_bot"), "Rejected. Nothing was reverted, and bot was told. It will read your note.");
});

test("Reject posts the note to the engine under the link's secret, and nothing else", async () => {
  const paths = revertPaths(ID);
  assert.deepEqual(paths, {
    request: `/api/v1/reverts/${ID}`,
    relay: `/api/v1/reverts/${ID}/apply`,
    reject: `/api/v1/reverts/${ID}/reject`,
    scope: `/api/v1/reverts/${ID}/scope`,
  });
  const calls = [];
  const fetchFn = async (path, init) => {
    calls.push({ path, init });
    return new Response(JSON.stringify({ revertId: ID, status: "REJECTED", rejectedAt: "2026-11-11T06:10:00Z" }));
  };
  const out = await rejectRevert(fetchFn, ID, "s3cr3t", "Merge them instead");
  assert.equal(out.status, "REJECTED");
  assert.equal(calls.length, 1);
  assert.equal(calls[0].path, paths.reject);
  assert.equal(calls[0].init.method, "POST");
  assert.equal(calls[0].init.headers["basalt-link-secret"], "s3cr3t");
  assert.equal(calls[0].init.headers["Content-Type"], "application/json");
  assert.equal(calls[0].init.body, '{"note":"Merge them instead"}');
  assert.equal(calls[0].init.credentials, "omit");

  await rejectRevert(fetchFn, ID, "s3cr3t", "");
  assert.equal(calls[1].init.body, "{}");
});

test("a refused reject reaches the page as the engine's error", async () => {
  const fetchFn = async () =>
    new Response(JSON.stringify({ code: "REVERT_INVALID", message: "signed meanwhile", personMessage: "This revert can no longer be rejected." }), { status: 409 });
  await assert.rejects(rejectRevert(fetchFn, ID, "s3cr3t", ""), (err) => {
    assert.equal(err.name, "RelayError");
    assert.equal(err.code, "REVERT_INVALID");
    assert.equal(err.personMessage, "This revert can no longer be rejected.");
    return true;
  });
});

// Runs with `node --test web/lib/*.test.mjs` (make web-check). The revert
// page's decision panel: who changed the rows, the headline, what the person
// signs, and the Reject note sent to the engine.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import { parseRevertBinding, parseRevertRequest } from "./codec.js";
import { revertPaths, rejectRevert } from "./local.js";
import { sameOriginSession } from "./transport.js";
import {
  MAX_NOTE,
  RESET_MESSAGE,
  agentName,
  knownTables,
  nothingToSign,
  scopeChoices,
  scopeFailure,
  scopeLine,
  toggled,
  expiresIn,
  headline,
  noteLength,
  noteProblem,
  rejectBody,
  rejectDone,
  lineAgents,
  rowAgent,
  signingSummary,
} from "./scope.js";

const fixtures = JSON.parse(
  readFileSync(new URL("../../internal/core/revert/testdata/fixtures.json", import.meta.url), "utf8"),
);
const BINDING = fixtures.request.binding;
const ID = fixtures.request.revertId;

// widen turns the fixture's own proposal into a widened select, as the
// engine returns it after the person's widen proof.
function widen(agentRows, agents = "null") {
  return parseRevertBinding(BINDING.replace('["agent:bot"]', agents)
    .replace('"widened": false', `"widened": true, "agentRows": ${JSON.stringify(agentRows)}`));
}

test("agent roles show by their short name", () => {
  assert.equal(agentName("agent:bot"), "bot");
  assert.equal(agentName("agent:sync_2"), "sync_2");
  // Only agent:<name> loses its prefix; a store login is never stripped.
  assert.equal(agentName("acme_agent_sync_2"), "acme_agent_sync_2");
  assert.equal(agentName("reporter"), "reporter");
});

test("a row is tagged with its agent only when the signed select names one", () => {
  const own = parseRevertBinding(BINDING);
  assert.deepEqual(rowAgent(own), { role: "agent:bot", other: false });
  // The person kept only another agent's changes: every row is that
  // agent's, and it is not the requester.
  const onlySync = widen({ "agent:sync": 4 }, '["agent:sync"]');
  assert.deepEqual(rowAgent(onlySync), { role: "agent:sync", other: true });
  // Several agents: the lines do not say whose each one is, so no row is
  // tagged rather than tagged wrong.
  assert.equal(rowAgent(widen({ "agent:bot": 3, "agent:sync": 1 })), null);
  // agents null with a single agent in the scope.
  assert.deepEqual(rowAgent(widen({ "agent:sync": 4 })), { role: "agent:sync", other: true });
});

test("with the catalog's change map every row of a multi-agent select is tagged with its agents", () => {
  const BOT = "0193a000-0000-7000-8000-000000000001";
  const SYNC = "0193a000-0000-7000-8000-000000000002";
  const OTHER = "0193a000-0000-7000-8000-000000000003";
  const wide = widen({ "agent:bot": 3, "agent:sync": 1 });
  const catalog = { changeAgents: new Map([[BOT, "agent:bot"], [SYNC, "agent:sync"]]) };
  const of = lineAgents(wide, catalog);
  assert.deepEqual(of({ changeIds: [BOT] }), [{ role: "agent:bot", other: false }]);
  assert.deepEqual(of({ changeIds: [SYNC] }), [{ role: "agent:sync", other: true }]);
  // A row two agents changed names both, each once, in a stable order.
  assert.deepEqual(of({ changeIds: [SYNC, BOT, SYNC] }), [
    { role: "agent:bot", other: false },
    { role: "agent:sync", other: true },
  ]);
  // A change the map does not name, or no change at all: no tag rather
  // than a guessed one.
  assert.equal(of({ changeIds: [BOT, OTHER] }), null);
  assert.equal(of({ changeIds: [] }), null);
  // No catalog (before a widen) or a catalog without the map (a guard
  // older than version 32): no per-row tags; rowAgent covers one agent.
  assert.equal(lineAgents(wide, null), null);
  assert.equal(lineAgents(wide, { agents: [], runs: [], resources: [] }), null);
  // One agent in the select: the one tag for every row stays.
  assert.equal(lineAgents(parseRevertBinding(BINDING), catalog), null);
});

test("the headline says whose rows and when the person widened", () => {
  const own = headline(parseRevertBinding(BINDING));
  assert.equal(own.title, "Undo 3 rows that bot changed");
  assert.equal(own.widened, false);
  assert.equal(own.lede, "Nothing changes until you sign with your passkey.");

  const wide = headline(widen({ "agent:bot": 3, "agent:sync": 1 }));
  assert.equal(wide.title, "Undo 3 rows in this run");
  assert.equal(wide.widened, true);
  assert.equal(wide.lede, "bot proposed its own 3. You added sync's 1. bot can't see the rows you added.");

  const one = headline(parseRevertBinding(BINDING.replace('"rows": 3', '"rows": 1').replace('"skipped": 1', '"skipped": 0')));
  assert.equal(one.title, "Undo 1 row that bot changed");
});

test("what the person signs counts rows and the tables they are in", async () => {
  const req = await parseRevertRequest("#" + fixtures.request.fragment);
  const tables = new Set(req.lines.filter((l) => l.action === "RESTORE").map((l) => l.resource)).size;
  assert.equal(signingSummary(req), `You're signing 3 rows in ${tables} ${tables === 1 ? "table" : "tables"}.`);
  // A large plan shows only a sample: the table count is not signed data.
  const big = await parseRevertRequest("#" + fixtures.batched.fragment);
  assert.equal(signingSummary(big), `You're signing ${big.binding.rows} rows.`);
});

// The dates are built in local time, so the same-day test holds in every
// time zone.
test("the link's time left reads in minutes, and shows its date on another day", () => {
  const now = new Date(2026, 10, 11, 6, 10, 0);
  assert.equal(expiresIn(new Date(2026, 10, 11, 7, 2, 11), now), "Link expires in 53 min");
  assert.equal(expiresIn(new Date(2026, 10, 11, 6, 10, 30), now), "Link expires in 1 min");
  assert.equal(expiresIn(new Date(2026, 10, 11, 6, 9, 0), now), "Link expired");
  assert.equal(expiresIn(new Date(2026, 10, 12, 17, 37), now), "Link expires 12 Nov 17:37");
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
  assert.equal(rejectDone(false, "agent:bot"), "Rejected. Nothing was reverted, and bot was told.");
  assert.equal(rejectDone(true, "agent:bot"), "Rejected. Nothing was reverted, and bot was told. It will read your note.");
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
  const out = await rejectRevert(sameOriginSession(fetchFn), ID, "s3cr3t", "Merge them instead");
  assert.equal(out.status, "REJECTED");
  assert.equal(calls.length, 1);
  assert.equal(calls[0].path, paths.reject);
  assert.equal(calls[0].init.method, "POST");
  assert.equal(calls[0].init.headers["basalt-link-secret"], "s3cr3t");
  assert.equal(calls[0].init.headers["content-type"], "application/json");
  assert.equal(calls[0].init.body, '{"note":"Merge them instead"}');
  assert.equal(calls[0].init.credentials, "omit");

  await rejectRevert(sameOriginSession(fetchFn), ID, "s3cr3t", "");
  assert.equal(calls[1].init.body, "{}");
});

test("a refused reject reaches the page as the engine's error", async () => {
  const fetchFn = async () =>
    new Response(JSON.stringify({ code: "REVERT_INVALID", message: "signed meanwhile", personMessage: "This revert can no longer be rejected." }), { status: 409 });
  await assert.rejects(rejectRevert(sameOriginSession(fetchFn), ID, "s3cr3t", ""), (err) => {
    assert.equal(err.name, "RelayError");
    assert.equal(err.code, "REVERT_INVALID");
    assert.equal(err.personMessage, "This revert can no longer be rejected.");
    return true;
  });
});

const CATALOG = {
  agents: [{ agent: "agent:bot", changes: 2 }, { agent: "agent:sync", changes: 1 }],
  runs: [
    { runId: "0193a4c2-7d1e-7c3a-9f00-0000000000b3", agent: "agent:sync", startedAt: new Date("2026-11-11T10:05:00Z"), changes: 1 },
    { runId: "0193a4c2-7d1e-7c3a-9f00-0000000000b2", agent: "agent:bot", startedAt: new Date("2026-11-11T09:12:00Z"), changes: 2 },
  ],
  resources: [{ resource: "public.notes", rows: 1 }, { resource: "public.leads", rows: 3 }],
};

// hm is a run's start as the page shows it: local hours and minutes.
const hm = (d) => `${String(d.getHours()).padStart(2, "0")}:${String(d.getMinutes()).padStart(2, "0")}`;

async function taskReq(edit = (b) => b) {
  const req = await parseRevertRequest("#" + fixtures.request.fragment);
  return { ...req, binding: parseRevertBinding(edit(BINDING.replace('"scope": "RUN"', '"scope": "TASK"'))) };
}

test("before a widen the chips are the agent's own: itself, fixed, and the tables its lines touch", async () => {
  const req = await taskReq();
  const known = knownTables(req, []);
  assert.deepEqual(known, ["public.lead_notes", "public.leads", "public.note_tags"]);
  const c = scopeChoices(req, null, known);
  assert.deepEqual(c.agents, [{ key: "agent:bot", label: "bot", count: 4, on: true, other: false, fixed: true }]);
  assert.deepEqual(c.resources.map((t) => [t.key, t.count, t.on, t.fixed]), [
    ["public.lead_notes", 1, true, false],
    ["public.leads", 2, true, false],
    ["public.note_tags", 1, true, false],
  ]);
  assert.equal(c.runs, null);
  // A table the person left out keeps its chip, unticked.
  const narrowed = await taskReq((b) => b.replace('"resources": null', '"resources": ["public.leads"]'));
  const n = scopeChoices({ ...narrowed, lines: narrowed.lines.filter((l) => l.resource === "public.leads") }, null, knownTables(narrowed, known));
  assert.deepEqual(n.resources.map((t) => [t.key, t.on]), [["public.lead_notes", false], ["public.leads", true], ["public.note_tags", false]]);
});

test("after a widen the chips and runs come from the catalog", async () => {
  const req = await taskReq((b) => b.replace('["agent:bot"]', "null")
    .replace('"widened": false', '"widened": true, "agentRows": {"agent:bot": 3, "agent:sync": 1}'));
  const c = scopeChoices(req, CATALOG, []);
  assert.deepEqual(c.agents.map((a) => [a.label, a.count, a.on, a.other, a.fixed]), [["bot", 3, true, false, false], ["sync", 1, true, true, false]]);
  assert.deepEqual(c.resources.map((t) => [t.key, t.count, t.on]), [["public.leads", 2, true], ["public.notes", 0, true]]);
  assert.deepEqual(c.runs.map((r) => [r.key, r.label, r.on]), [
    ["0193a4c2-7d1e-7c3a-9f00-0000000000b2", `bot, 2 changes, ${hm(CATALOG.runs[1].startedAt)}`, true],
    ["0193a4c2-7d1e-7c3a-9f00-0000000000b3", `sync, 1 change, ${hm(CATALOG.runs[0].startedAt)}`, true],
  ]);
});

test("ticking a chip builds the next select: null for all, never an empty list", async () => {
  const req = await taskReq((b) => b.replace('["agent:bot"]', "null")
    .replace('"widened": false', '"widened": true, "agentRows": {"agent:bot": 3, "agent:sync": 1}'));
  const c = scopeChoices(req, CATALOG, []);
  const s1 = toggled(req.binding.select, c, "agents", "agent:sync");
  assert.deepEqual(s1.agents, ["agent:bot"]);
  assert.equal(s1.resources, null);
  const back = toggled(s1, scopeChoices({ ...req, binding: { ...req.binding, select: s1 } }, CATALOG, []), "agents", "agent:sync");
  assert.equal(back.agents, null, "every agent again is null");
  const s2 = toggled(req.binding.select, c, "runs", "0193a4c2-7d1e-7c3a-9f00-0000000000b3");
  assert.deepEqual(s2.runs, ["0193a4c2-7d1e-7c3a-9f00-0000000000b2"]);
  // With sync left out, its run is out of the scope: unticked, fixed, and
  // never listed when the person unticks bot's run.
  const botOnly = { ...req.binding.select, agents: ["agent:bot"] };
  const cb = scopeChoices({ ...req, binding: { ...req.binding, select: botOnly } }, CATALOG, []);
  assert.deepEqual(cb.runs.map((r) => [r.on, r.fixed]), [[true, false], [false, true]]);
  assert.equal(toggled(botOnly, cb, "runs", "0193a4c2-7d1e-7c3a-9f00-0000000000b3"), null);
  assert.equal(toggled(botOnly, cb, "runs", "0193a4c2-7d1e-7c3a-9f00-0000000000b2"), null, "bot's only run is the last one ticked");
  // Unticking an agent drops its runs from the list: Postgres takes only
  // runs of selected agents.
  const r1 = "0193a4c2-7d1e-7c3a-9f00-0000000000b2";
  const r3 = "0193a4c2-7d1e-7c3a-9f00-0000000000b3";
  const runs2 = { ...CATALOG, runs: [...CATALOG.runs, { runId: "0193a4c2-7d1e-7c3a-9f00-0000000000b4", agent: "agent:bot", startedAt: new Date("2026-11-11T09:40:00Z"), changes: 1 }] };
  const noR4 = { ...req.binding.select, runs: [r1, r3] };
  const cr = scopeChoices({ ...req, binding: { ...req.binding, select: noR4 } }, runs2, []);
  assert.deepEqual(toggled(noR4, cr, "agents", "agent:sync"), { ...noR4, agents: ["agent:bot"], runs: [r1] });
  // Only sync's run listed, sync left out: every run of bot again.
  const onlyR3 = { ...req.binding.select, runs: [r3] };
  const c3 = scopeChoices({ ...req, binding: { ...req.binding, select: onlyR3 } }, runs2, []);
  assert.equal(toggled(onlyR3, c3, "agents", "agent:sync").runs, null);
  const one = toggled(req.binding.select, c, "resources", "public.leads");
  assert.equal(toggled(one, scopeChoices({ ...req, binding: { ...req.binding, select: one } }, CATALOG, []), "resources", "public.notes"), null,
    "the last ticked chip cannot be left out");
});

test("the phone's scope line sums up the choice", async () => {
  const own = await taskReq();
  assert.deepEqual(scopeLine(own, null, knownTables(own, [])), { text: "bot, 3 tables", sub: "As bot proposed" });
  const wide = await taskReq((b) => b.replace('["agent:bot"]', "null")
    .replace('"widened": false', '"widened": true, "agentRows": {"agent:bot": 3, "agent:sync": 1}'));
  assert.deepEqual(scopeLine(wide, CATALOG, []), { text: "bot + sync, 2 tables, 2 runs", sub: "bot can't see the rows you added" });
  const changed = await taskReq((b) => b.replace('"resources": null', '"resources": ["public.leads"]')
    .replace('"widened": false', '"widened": false, "proposed": {"runs": null, "scope": "TASK", "agents": ["agent:bot"], "scopeId": "0193a4c2-7d1e-7c3a-9f00-0000000000b2", "resources": null}'));
  assert.equal(scopeLine(changed, null, ["public.leads", "public.notes"]).sub, "You changed bot's proposal");
});

test("a scope with nothing to restore cannot be signed", async () => {
  assert.equal(nothingToSign(parseRevertBinding(BINDING)), null);
  const empty = parseRevertBinding(BINDING.replace('"scope": "RUN"', '"scope": "TASK"').replace('"rows": 3', '"rows": 0').replace('"skipped": 1', '"skipped": 0'));
  assert.equal(nothingToSign(empty), "There is nothing to revert in this scope.");
});

test("a reset link says the agent reset it; other failures say what the engine said", () => {
  const reset = Object.assign(new Error("reset"), { name: "RelayError", code: "NOT_FOUND", reason: "LINK_RESET", personMessage: "x" });
  assert.equal(scopeFailure(reset), RESET_MESSAGE);
  assert.equal(RESET_MESSAGE, "The agent reset this revert to its own work. Ask it for the new link, and widen again if you still want to include other agents.");
  const slow = Object.assign(new Error("slow"), { name: "RelayError", code: "QUERY_TIMEOUT", personMessage: "Changing the scope took longer than 100 seconds and was stopped." });
  assert.equal(scopeFailure(slow), "Changing the scope took longer than 100 seconds and was stopped.");
  assert.equal(scopeFailure(new Error("boom")), "The scope could not be changed: boom");
});

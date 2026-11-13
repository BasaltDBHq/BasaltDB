// The revert page's decision panel (CONTRACT.md, Revert, Rescope, widen and
// reject): who changed the rows, the headline, what the person signs, and
// the Reject note. Pure functions over the checked request, so they run
// under `node --test`; revert.js puts their text on the page.

import { personText } from "./page.js";

const SCOPE_WORDS = { CHANGE: "change", RUN: "run", TASK: "task" };

// agentName is an agent role as the person knows the agent: the part after
// "<prefix>_agent_" (basalt_agent_bot is "bot"), or the whole role when it
// has no such part.
export function agentName(role) {
  const m = /^.+?_agent_(.+)$/.exec(role);
  return m ? m[1] : role;
}

function plural(n, word) {
  return `${n} ${word}${n === 1 ? "" : "s"}`;
}

// agentsOf is every agent role the signed select covers: its agents list,
// or for a widen to every agent (null) the roles agentRows names.
function agentsOf(binding) {
  return binding.select.agents ?? Object.keys(binding.agentRows ?? {});
}

// rowAgent is the agent every row of the revert belongs to, and whether it
// is another agent than the one that requested the revert; null when the
// select covers several agents. A line names its changes, not their agent,
// so with several agents no row is tagged rather than tagged wrong.
export function rowAgent(binding) {
  const agents = agentsOf(binding);
  if (agents.length !== 1) return null;
  return { role: agents[0], other: agents[0] !== binding.requestedBy };
}

// headline is the page's title and the sentence under it. A widened revert
// says what the agent proposed, what the person added, and that the agent
// cannot see it (RS-5).
export function headline(binding) {
  const requester = agentName(binding.requestedBy);
  if (!binding.widened) {
    return {
      title: `Undo ${plural(binding.rows, "row")} that ${requester} changed`,
      lede: "Nothing changes until you sign with your passkey.",
      widened: false,
    };
  }
  const rows = binding.agentRows;
  const added = Object.keys(rows)
    .filter((role) => role !== binding.requestedBy)
    .map((role) => `${agentName(role)}'s ${rows[role]}`);
  const parts = [];
  if (binding.requestedBy in rows) parts.push(`${requester} proposed its own ${rows[binding.requestedBy]}.`);
  if (added.length > 0) parts.push(`You added ${added.join(", ")}.`);
  parts.push(`${requester} can't see the rows you added.`);
  return {
    title: `Undo ${plural(binding.rows, "row")} in this ${SCOPE_WORDS[binding.select.scope]}`,
    lede: parts.join(" "),
    widened: true,
  };
}

// signingSummary is the line above Sign. The tables are counted from the
// lines only when the request carries every line: a large plan's sample
// does not name every table the signature covers.
export function signingSummary(req) {
  const rows = plural(req.binding.rows, "row");
  if (req.binding.batched) return `You're signing ${rows}.`;
  const tables = new Set(req.lines.filter((l) => l.action === "RESTORE").map((l) => l.table)).size;
  return `You're signing ${rows} in ${plural(tables, "table")}.`;
}

const MINUTE_MS = 60000;

// expiresIn is the top bar's "Link expires in N min", rounded up.
export function expiresIn(expiresAt, now) {
  const left = expiresAt.getTime() - now.getTime();
  if (left <= 0) return "Link expired";
  return `Link expires in ${Math.ceil(left / MINUTE_MS)} min`;
}

// MAX_NOTE is the longest Reject note, in characters (code points), as the
// engine counts them (revert-reject-request.schema.json).
export const MAX_NOTE = 500;

export function noteLength(text) {
  return Array.from(text).length;
}

// refusedInNote matches what the engine refuses in a note (agent.rejectNote):
// a control character other than a newline or a tab, and the bidirectional
// marks, embeddings, overrides and isolates that could make it read
// otherwise to the agent or the person it shows the note to.
const REFUSED_IN_NOTE = /[\u0000-\u0008\u000b-\u001f\u007f-\u009f؜‎‏‪-‮⁦-⁩]/u;

// noteProblem is why the engine would refuse the note, or null.
export function noteProblem(text) {
  if (noteLength(text) > MAX_NOTE) return `The note is longer than ${MAX_NOTE} characters.`;
  if (REFUSED_IN_NOTE.test(text)) return "The note has a control character; only text, new lines and tabs.";
  return null;
}

// rejectBody is the body of POST …/reject: the note only when the person
// wrote one (revert-reject-request.schema.json).
export function rejectBody(text) {
  const problem = noteProblem(text);
  if (problem !== null) throw new Error(problem);
  if (text.trim() === "") return "{}";
  return JSON.stringify({ note: text });
}

// rejectDone is what the page says once the engine took the reject.
export function rejectDone(withNote, requestedBy) {
  const told = `Rejected. Nothing was reverted, and ${agentName(requestedBy)} was told.`;
  return withNote ? `${told} It will read your note.` : told;
}

// RESET_MESSAGE is what the page says when the agent reset the revert to
// its proposal and the person's link stopped working (NOT_FOUND reason
// LINK_RESET; CONTRACT.md, Rescope, widen and reject).
export const RESET_MESSAGE =
  "The agent reset this revert to its own work. Ask it for the new link, and widen again if you still want to include other agents.";

// scopeFailure is the sentence for a scope change the engine refused.
export function scopeFailure(err) {
  if (err?.reason === "LINK_RESET") return RESET_MESSAGE;
  return personText(err) || `The scope could not be changed: ${err?.message ?? err}`;
}

// nothingToSign is why Sign is off, or null: a scope with no row to
// restore (an empty task proposal, or a narrowing that left nothing), which
// apply_revert would answer NOTHING_TO_REVERT.
export function nothingToSign(binding) {
  return binding.rows === 0 ? "There is nothing to revert in this scope." : null;
}

const byText = (a, b) => (a < b ? -1 : a > b ? 1 : 0);

// knownTables are the tables the page can offer before a widen: the ones
// it has seen so far (the proposal's lines, and each answer since) and the
// ones the select or the proposal names. The agent's own work has no
// catalog, so a table left out stays known from earlier answers.
export function knownTables(req, known) {
  const b = req.binding;
  const all = new Set([...known, ...req.lines.map((l) => l.table), ...(b.select.tables ?? []), ...(b.proposed?.tables ?? [])]);
  return [...all].sort(byText);
}

function linesPerTable(req) {
  const n = new Map();
  for (const l of req.lines) n.set(l.table, (n.get(l.table) ?? 0) + 1);
  return n;
}

const pad2 = (n) => String(n).padStart(2, "0");

// scopeChoices are the chips and runs the decision panel shows. Before a
// widen: the requesting agent (fixed, its proposal is its own work) and
// the tables it touched. After one: the catalog's agents, tables and runs.
// count is the lines a chip has in the current select; on, whether the
// select includes it.
export function scopeChoices(req, catalog, known) {
  const b = req.binding;
  const sel = b.select;
  const isOn = (list, key) => list === null || list.includes(key);
  const perTable = linesPerTable(req);
  if (catalog === null) {
    return {
      agents: [{ key: b.requestedBy, label: agentName(b.requestedBy), count: b.rows + b.skipped, on: true, other: false, fixed: true }],
      tables: known.map((t) => ({ key: t, label: t, count: perTable.get(t) ?? 0, on: isOn(sel.tables, t), fixed: false })),
      runs: null,
    };
  }
  const agentRows = b.agentRows ?? { [b.requestedBy]: b.rows + b.skipped };
  return {
    agents: [...catalog.agents].sort((x, y) => byText(x.agent, y.agent)).map((a) => ({
      key: a.agent, label: agentName(a.agent), count: agentRows[a.agent] ?? 0, on: isOn(sel.agents, a.agent),
      other: a.agent !== b.requestedBy, fixed: false,
    })),
    tables: [...catalog.tables].sort((x, y) => byText(x.table, y.table)).map((t) => ({
      key: t.table, label: t.table, count: perTable.get(t.table) ?? 0, on: isOn(sel.tables, t.table), fixed: false,
    })),
    // A run of an agent left out is not in the scope: shown unticked and
    // fixed, and never listed (Postgres takes only runs of selected agents).
    runs: sel.scope !== "TASK" ? null : [...catalog.runs].sort((x, y) => x.startedAt - y.startedAt).map((r) => {
      const agentOn = isOn(sel.agents, r.agent);
      return {
        key: r.runId,
        label: `${agentName(r.agent)}, ${plural(r.changes, "change")}, ${pad2(r.startedAt.getHours())}:${pad2(r.startedAt.getMinutes())}`,
        on: agentOn && isOn(sel.runs, r.runId),
        other: r.agent !== b.requestedBy,
        fixed: !agentOn,
      };
    }),
  };
}

// toggled is the select after the person ticks or unticks key in kind
// (agents, runs or tables): null when every choice is ticked, else the
// ticked keys. null (no change) when it would untick the last one: a
// descriptor lists at least one of each, or null for all.
export function toggled(select, choices, kind, key) {
  const items = choices[kind].filter((c) => !c.fixed);
  if (!items.some((c) => c.key === key)) return null;
  const on = new Set(items.filter((c) => c.on).map((c) => c.key));
  if (on.has(key)) on.delete(key);
  else on.add(key);
  if (on.size === 0) return null;
  const list = items.map((c) => c.key).filter((k) => on.has(k));
  return { ...select, [kind]: list.length === items.length ? null : list };
}

// scopeLine is the phone's one line above the restore list ("bot, 1 table,
// 2 runs") and what it is: the proposal, a change of it, or a widen.
export function scopeLine(req, catalog, known) {
  const b = req.binding;
  const c = scopeChoices(req, catalog, known);
  const agents = c.agents.filter((a) => a.on).map((a) => a.label).join(" + ");
  const parts = [agents, plural(c.tables.filter((t) => t.on).length, "table")];
  if (c.runs !== null) parts.push(plural(c.runs.filter((r) => r.on).length, "run"));
  const requester = agentName(b.requestedBy);
  let sub = `As ${requester} proposed`;
  if (b.proposed) sub = `You changed ${requester}'s proposal`;
  if (b.widened) sub = `${requester} can't see the rows you added`;
  return { text: parts.join(", "), sub };
}

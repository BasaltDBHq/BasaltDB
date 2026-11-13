// The revert page's decision panel (CONTRACT.md, Revert, Rescope, widen and
// reject): who changed the rows, the headline, what the person signs, and
// the Reject note. Pure functions over the checked request, so they run
// under `node --test`; revert.js puts their text on the page.

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

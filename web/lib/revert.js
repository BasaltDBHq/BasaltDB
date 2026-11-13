// The revert page: read the revert (from the long link's fragment, or from
// the engine for a short link /reverts/<id>), check the lines against the
// binding, show what will be restored and what is left alone, and sign the
// binding with the person's passkey. From a long link the page sends
// nothing anywhere and shows a code to paste into `basalt revert`; from a
// short link it posts the signature to the engine that served it, which
// relays it to Postgres.
//
// From a short link the person may also change the scope (CONTRACT.md,
// Rescope, widen and reject): untick agents, runs or tables, which posts a
// narrower select, or include other agents' changes, which first asks the
// passkey for a widen proof (rescope.js). Each answer is a new request the
// page checks and shows in full, as on load.
import {
  KIND_REVERT,
  MAX_REVERT_BATCH,
  REVERT_APPLY_HOURS,
  checkRevertRequest,
  displayValue,
  encodeRevertResponse,
  parseRevertRequest,
  relyingParty,
  revertResponseJSON,
  revertShown,
  visibleText,
} from "./codec.js";
import { fetchRequest, isLongLink, linkSecret, pageId, postResponse, rejectRevert, revertDone, revertPaths } from "./local.js";
import { $, REVERT_REOPEN, el, fail, linkFailure, loadOrPaste, personText, showCode, showDone, showRelayFailed, webauthnError } from "./page.js";
import { canWiden, narrow, widen } from "./rescope.js";
import { applyReveal, canReveal, clearReveal, hiddenLines, NOT_CHECKED, OPEN_FROM_ENGINE, reveal, revealedLine, revealFailure, revealPath, SHOWN_TO_YOU } from "./reveal.js";
import {
  MAX_NOTE,
  RESET_MESSAGE,
  agentName,
  expiresIn,
  headline,
  knownTables,
  noteLength,
  noteProblem,
  nothingToSign,
  rejectDone,
  rowAgent,
  scopeChoices,
  scopeFailure,
  scopeLine,
  signingSummary,
  toggled,
} from "./scope.js";

const PROMPT_TIMEOUT_MS = 120000;

const SCOPES = { CHANGE: "One change", RUN: "One run", TASK: "One task" };

// Why a row is left alone, in words (CONTRACT.md, Revert, Conflicts).
const CONFLICTS = {
  CHANGED_AFTER: "Changed after the agent. Kept as it is now.",
  ROW_GONE: "No longer there, or not visible to the revert.",
  KEY_TAKEN: "Another row now has this key.",
  ALREADY_REVERTED: "Already reverted.",
  VALUES_PRUNED: "Older than 30 days: the old values are gone.",
  SCHEMA_CHANGED: "The table changed since the agent wrote it.",
  CASCADE: "Restoring it would change rows that are not part of this revert.",
  CONSTRAINT: "Restoring it would break a database constraint.",
};

// display shows a column's value as the line carries it (displayValue), with
// the characters that hide or reorder text shown as escapes (visibleText).
function display(line, member, col) {
  const row = line[member] ?? {};
  return visibleText(displayValue(row[col], line.texts?.[member]?.get(col)));
}

function plural(n, word) {
  return `${n} ${word}${n === 1 ? "" : "s"}`;
}

// renderHeader fills the top bar, the headline and the agent's reason. A
// widened revert carries the "You widened this" pill.
function renderHeader(req) {
  const b = req.binding;
  const requester = visibleText(agentName(b.requestedBy));
  const head = headline(b);
  $("crumb").textContent = `Revert request from ${requester}`;
  $("headline").textContent = visibleText(head.title);
  $("lede").textContent = visibleText(head.lede);
  $("widened-pill").hidden = !head.widened;
  $("why-label").textContent = `${requester}'s reason:`;
  $("signing").textContent = signingSummary(req);
  $("expires-in").textContent = expiresIn(b.expiresAt, new Date());
}

const RESTORE_NOTE =
  "Struck-through values are the row now; highlighted values are what it goes back to, as before the agent. " +
  "Postgres checks these exact rows again before the revert runs; if any changed, nothing is written.";

// EXPIRY_TICK_MS is how often the top bar's time left is redrawn.
const EXPIRY_TICK_MS = 30000;

function renderSummary(req) {
  const b = req.binding;
  $("scope").textContent = `${SCOPES[b.select.scope]} (${b.select.scopeId})`;
  $("agents").textContent = visibleText((b.select.agents ?? Object.keys(b.agentRows)).join(", "));
  $("database").textContent = visibleText(b.database);
  $("intent").textContent = visibleText(b.intent);
  $("rows").textContent = plural(b.rows, "row");
  $("skipped").textContent = plural(b.skipped, "row");
  $("expires").textContent = b.expiresAt.toLocaleString();
  if (!b.batched) {
    $("plan").textContent = `${plural(b.rows + b.skipped, "row")}, all shown below, restored in one step when you sign.`;
    $("restore-title").textContent = "What goes back";
    $("skip-title").textContent = "Rows left as they are";
    $("restore-note").textContent = RESTORE_NOTE;
    return;
  }
  // A large plan (decisions N12-1 to N12-4, RSS-1): the link carries a
  // sample. The counts come from the binding and the checked lines only.
  const shown = revertShown(req);
  $("plan").textContent =
    `${plural(b.rows + b.skipped, "row")}. Your signature covers every one; this page shows ${req.lines.length}: ` +
    `${shown.restoreShown} to restore and ${shown.skipShown} left as they are. ` +
    `Not shown: ${plural(shown.restoreHidden, "row")} to restore and ${plural(shown.skipHidden, "row")} left as they are. ` +
    `After you sign, the agent restores them in batches of up to ${MAX_REVERT_BATCH} rows ` +
    `within ${REVERT_APPLY_HOURS} hours. Follow it with basalt revert --status ${b.revertId}.`;
  $("restore-title").textContent = `What goes back (${shown.restoreShown} of ${b.rows} shown)`;
  $("skip-title").textContent = `Rows left as they are (${shown.skipShown} of ${b.skipped} shown)`;
  $("restore-note").textContent =
    "Struck-through values are the row now; highlighted values are what it goes back to. Each row is checked again with its row locked when its batch runs; a row someone changed by then is left as it is.";
}

// rowTable shows a row now and after the revert: only "Now" for a row the
// revert deletes, only "After revert" for a row it re-inserts, both for an
// update with the columns that change highlighted. A row the revert leaves
// alone (SKIP) shows only "Now": the revert keeps it as it is, so values it
// would have written must not look like they will be applied.
//
// A skipped row that is gone (ROW_GONE) has neither: rowTable returns null,
// and the page names the row by its key instead (rowKeyText).
export function rowTable(line) {
  const now = line.now ?? {};
  const skipped = line.action === "SKIP";
  const after = skipped ? {} : (line.set ?? {});
  const showNow = line.now !== null;
  const showAfter = !skipped && line.set !== null;
  if (!showNow && !showAfter) return null;
  const table = el("table", "values");
  const head = el("tr");
  head.append(el("th", "", "Column"));
  if (showNow) head.append(el("th", "", "Now"));
  if (showAfter) head.append(el("th", "", "After revert"));
  table.append(head);
  const columns = [...new Set([...Object.keys(now), ...Object.keys(after)])];
  for (const col of columns) {
    const changes = showNow && showAfter && col in after && display(line, "now", col) !== display(line, "set", col);
    const tr = el("tr", changes ? "changed" : "");
    tr.append(el("td", "col", visibleText(col)));
    if (showNow) tr.append(el("td", changes ? "now" : "", display(line, "now", col)));
    if (showAfter) tr.append(el("td", changes ? "back" : "", display(line, "set", col)));
    table.append(tr);
  }
  return table;
}

// rowKeyText names a row by its primary key, for a row with no values to
// show: "Row id = 42", or each key column for a composite key.
export function rowKeyText(line) {
  const key = line.key ?? {};
  const parts = Object.keys(key).map((col) => `${visibleText(col)} = ${display(line, "key", col)}`);
  return parts.length ? `Row ${parts.join(", ")}` : "Row key not recorded.";
}

function opLabel(line) {
  if (line.op === "DELETE") return "DELETE";
  if (line.op === "INSERT") return "RE-INSERT";
  return "RESTORE";
}

// agentTag is a row's "changed by" tag: amber for an agent other than the
// one that requested the revert.
export function agentTag(who) {
  const tag = el("span", who.other ? "ag other" : "ag", visibleText(agentName(who.role)));
  tag.title = visibleText(who.role);
  return tag;
}

// renderLine shows one row. A hidden row shows its values once the person
// revealed them (shown), labelled as shown to them only, and as not checked
// when Postgres left out secret columns; until then it says the values are
// hidden, and on a long link where to see them.
export function renderLine(line, who, shown = null, longLink = false) {
  const card = el("li", "row");
  const title = el("div", "row-title");
  title.append(el("span", `op op-${line.op.toLowerCase()}`, opLabel(line)));
  title.append(el("span", "table-name", visibleText(line.table)));
  if (line.cascaded) title.append(el("span", "badge", "cascaded"));
  if (who !== null) title.append(agentTag(who));
  card.append(title);
  if (line.action === "SKIP") {
    const reason = CONFLICTS[line.conflict];
    card.append(el("p", "conflict", line.sqlState ? `${reason} (SQLSTATE ${visibleText(line.sqlState)})` : reason));
  }
  if (line.redacted && shown) {
    card.append(el("p", "muted", SHOWN_TO_YOU));
    if (!shown.checked) card.append(el("p", "conflict", NOT_CHECKED));
    const shownLine = revealedLine(line, shown, "now");
    card.append(rowTable(shownLine) ?? el("p", "muted", rowKeyText(shownLine)));
    return card;
  }
  if (line.redacted) {
    const hidden = "Values hidden: the role that prepared this revert cannot read this table.";
    card.append(el("p", "muted", longLink ? `${hidden} ${OPEN_FROM_ENGINE}` : hidden));
    return card;
  }
  if (line.op === "DELETE" && line.action === "RESTORE") card.append(el("p", "muted", "The agent inserted this row; the revert deletes it."));
  const table = rowTable(line);
  card.append(table ?? el("p", "muted", rowKeyText(line)));
  return card;
}

// engineFetch is fetch bound to the window, for the local relay.
const engineFetch = (path, init) => window.fetch(path, init);

// loadRequest reads the request: from the fragment of a long link, or from
// the engine for a short link. relay is the path to post the signature to,
// null for a long link.
async function loadRequest(hash) {
  // Every link names its revert in the path; a long link's request must
  // name the same one.
  const id = pageId(window.location.pathname, "reverts");
  if (isLongLink(hash)) {
    const req = await parseRevertRequest(hash);
    if (req.revertId !== id) throw new Error(`the link is for revert ${req.revertId}, its path for ${id}`);
    return { req, relay: null };
  }
  const paths = revertPaths(id);
  // A short link: #s=<secret>. Without it the engine answers as for an
  // unknown id.
  const secret = linkSecret(hash);
  const req = await checkRevertRequest(await fetchRequest(engineFetch, paths.request, secret));
  if (req.revertId !== id) throw new Error(`the engine sent revert ${req.revertId}, not ${id}`);
  return { req, relay: { path: paths.relay, secret, id } };
}

// finish relays the signed response when the page came from a short link,
// and otherwise (or when the relay fails) shows the code to paste.
async function finish(response, relay) {
  if (relay !== null) {
    try {
      showDone(revertDone(await postResponse(engineFetch, relay.path, relay.secret, revertResponseJSON(response))));
      return;
    } catch (err) {
      showRelayFailed(`The engine did not take the revert: ${personText(err) || err.message}. To finish by hand, paste the code below into basalt revert --apply.`);
    }
  }
  showCode(encodeRevertResponse(response));
}

async function sign(rp, state) {
  const { req, relay } = state;
  $("sign").disabled = true;
  try {
    const cred = await navigator.credentials.get({
      publicKey: {
        challenge: req.challenge,
        rpId: rp.rpId,
        allowCredentials: req.credentialIds.map((id) => ({ type: "public-key", id })),
        userVerification: "required",
        timeout: PROMPT_TIMEOUT_MS,
      },
    });
    const r = cred.response;
    await finish(
      {
        revertId: req.revertId,
        credentialId: new Uint8Array(cred.rawId),
        authenticatorData: new Uint8Array(r.authenticatorData),
        clientDataJson: new Uint8Array(r.clientDataJSON),
        signature: new Uint8Array(r.signature),
      },
      relay,
    );
  } catch (err) {
    $("sign").disabled = nothingToSign(state.req.binding) !== null || state.expired;
    $("status").textContent = webauthnError(err);
  }
}

// openNote shows the Reject note: inline in the decision panel on a wide
// screen, as a sheet over the page on a phone (style.css).
function openNote(open) {
  $("action").hidden = open;
  $("reject-note").hidden = !open;
  $("sheet-dim").hidden = !open;
  if (open) $("note").focus();
}

function noteChanged() {
  const text = $("note").value;
  $("note-count").textContent = `${noteLength(text)} / ${MAX_NOTE}`;
  const problem = noteProblem(text);
  $("reject-status").textContent = problem ?? "";
  $("reject-send").disabled = problem !== null;
}

// reject posts the person's Reject with their note. No passkey: rejecting
// can only stop a revert (CONTRACT.md, Rescope, widen and reject).
async function reject(state) {
  const { req, relay } = state;
  const note = $("note").value;
  $("reject-send").disabled = true;
  $("reject-cancel").disabled = true;
  $("reject-status").textContent = "";
  try {
    await rejectRevert(engineFetch, relay.id, relay.secret, note);
  } catch (err) {
    $("reject-send").disabled = false;
    $("reject-cancel").disabled = false;
    $("reject-status").textContent = err?.reason === "LINK_RESET" ? RESET_MESSAGE : personText(err) || `The engine did not take the reject: ${err.message}`;
    return;
  }
  $("reject-note").hidden = true;
  $("sheet-dim").hidden = true;
  showDone(rejectDone(note.trim() !== "", req.binding.requestedBy));
}

// wireReject offers Reject when the page talks to the engine. A long link
// has no engine to tell: closing the page declines.
function wireReject(state) {
  const { req, relay } = state;
  if (relay === null) {
    $("decline").textContent = "Close this page to decline; nothing happens unless you sign.";
    return;
  }
  $("decline").hidden = true;
  $("reject").hidden = false;
  $("note-reader").textContent = `${visibleText(agentName(req.binding.requestedBy))} will read this note.`;
  $("reject").addEventListener("click", () => openNote(true));
  $("reject-cancel").addEventListener("click", () => openNote(false));
  $("sheet-dim").addEventListener("click", () => openNote(false));
  $("note").addEventListener("input", noteChanged);
  $("reject-send").addEventListener("click", () => reject(state));
}

// render shows the current request: header, summary, lines, scope and
// whether it can be signed. It runs on load and after every scope change.
function render(state) {
  const { req } = state;
  renderHeader(req);
  renderSummary(req);
  const who = rowAgent(req.binding);
  $("restore").replaceChildren();
  $("skip").replaceChildren();
  const longLink = state.relay === null;
  req.lines.forEach((line, i) => {
    $(line.action === "SKIP" ? "skip" : "restore").append(renderLine(line, who, state.shown.get(i) ?? null, longLink));
  });
  renderReveal(state);
  $("skip-section").hidden = req.binding.skipped === 0;
  renderScope(state);
  // Sign and Reject wait while a scope change is in flight, and stay off
  // on a revert that had expired when the page loaded.
  const nothing = nothingToSign(req.binding);
  $("sign").disabled = nothing !== null || state.busy || state.expired;
  $("reject").disabled = state.busy || state.expired;
  $("status").textContent = state.expired ? EXPIRED : (nothing ?? "");
}

const EXPIRED = "This revert link expired. Nothing was reverted; run basalt revert again.";

// RUN_ID_SHOWN is how much of a run id its chip shows.
const RUN_ID_SHOWN = 8;

// chip is one choice of the scope (an agent, a table or a run). A fixed
// chip, or any chip on a long link, cannot be pressed.
function chip(choice, kind, state) {
  const editable = state.relay !== null && !choice.fixed;
  const b = el("button", `chip${choice.on ? " on" : ""}${choice.other ? " other" : ""}${kind === "runs" ? " run" : ""}`);
  b.type = "button";
  b.setAttribute("aria-pressed", String(choice.on));
  b.disabled = !editable || state.busy;
  b.append(el("span", "tk", choice.on ? "\u2713" : ""));
  if (kind === "runs") {
    // A run by the end of its id (the start of a UUIDv7 is its time, alike
    // for runs of one morning); the whole id on hover.
    b.append(el("span", "mono", choice.key.slice(-RUN_ID_SHOWN)));
    b.append(el("span", "w", visibleText(choice.label)));
    b.title = choice.key;
  } else {
    b.append(el("span", kind === "agents" ? "" : "mono", visibleText(choice.label)));
    if (choice.count > 0) b.append(el("b", "", String(choice.count)));
  }
  if (editable) b.addEventListener("click", () => rescope(state, kind, choice.key));
  return b;
}

function renderScope(state) {
  const { req, catalog } = state;
  state.known = catalog === null ? knownTables(req, state.known) : state.known;
  const choices = scopeChoices(req, catalog, state.known);
  state.choices = choices;
  const editable = state.relay !== null;
  $("included-hint").textContent = editable ? "tap to leave out" : "";
  $("agent-chips").replaceChildren(...choices.agents.map((c) => chip(c, "agents", state)));
  $("table-chips").replaceChildren(...choices.tables.map((c) => chip(c, "tables", state)));
  $("runs-section").hidden = choices.runs === null;
  if (choices.runs !== null) {
    $("runs-count").textContent = String(choices.runs.length);
    $("runs").replaceChildren(...choices.runs.map((c) => chip(c, "runs", state)));
  }
  $("widen").hidden = !canWiden(req, state.relay, catalog);
  $("widen").disabled = state.busy;
  $("widen-text").textContent = `Asks for your passkey. ${visibleText(agentName(req.binding.requestedBy))} won't see what you add.`;
  $("scope-readonly").hidden = editable;
  const line = scopeLine(req, catalog, state.known);
  $("scope-line-text").textContent = visibleText(line.text);
  $("scope-line-sub").textContent = visibleText(line.sub);
}

// applyScope shows an answer of the scope route: the new request and, after
// a widen, the catalog and the link's new secret.
function applyScope(state, out) {
  state.req = out.req;
  // New lines: what was shown belonged to the old ones.
  clearReveal(state);
  if (out.catalog !== null) state.catalog = out.catalog;
  if (out.secret) state.relay.secret = out.secret;
}

async function changeScope(state, run) {
  state.busy = true;
  $("scope-status").textContent = "Updating the rows…";
  render(state);
  try {
    applyScope(state, await run());
    $("scope-status").textContent = "";
  } catch (err) {
    $("scope-status").textContent = err?.name === "NotAllowedError" || err?.name === "SecurityError" ? webauthnError(err) : scopeFailure(err);
  }
  state.busy = false;
  render(state);
}

// rescope posts the select with kind's key ticked or unticked. The engine
// adds the scope token after a widen; no passkey.
function rescope(state, kind, key) {
  const select = toggled(state.req.binding.select, state.choices, kind, key);
  if (select === null) {
    $("scope-status").textContent = "Keep at least one ticked; to stop the whole revert, use Reject.";
    return;
  }
  return changeScope(state, () => narrow({ req: state.req, secret: state.relay.secret, fetchFn: engineFetch, select }));
}

// includeOthers widens to every agent's changes in the task: the passkey
// signs the widen proof first, and nothing is sent without it.
function includeOthers(state) {
  return changeScope(state, () =>
    widen({
      req: state.req,
      rpId: state.rp.rpId,
      secret: state.relay.secret,
      fetchFn: engineFetch,
      getAssertion: (options) => navigator.credentials.get(options),
    }),
  );
}

// renderReveal offers Show values on a page the engine served with hidden
// rows, until the person revealed them. It never prompts on its own (HR-4).
function renderReveal(state) {
  const { req } = state;
  const offer = canReveal(req, state.relay) && !state.revealDone;
  $("reveal-box").hidden = !offer;
  if (!offer) return;
  $("reveal-text").textContent = `${hiddenLines(req)} of these rows are in tables the agent cannot read. You can see their values with your passkey; the agent still cannot.`;
  $("reveal").disabled = state.busy || state.revealFinal === req;
}

// showValues asks the passkey once and shows every hidden row. Signing
// still asks for the passkey again; nothing shown goes into the signature.
async function showValues(state) {
  const { req, relay } = state;
  // Busy: the scope chips, Sign and Reject wait for the reveal.
  state.busy = true;
  $("reveal-status").textContent = "";
  render(state);
  let shown = null;
  let status = "";
  try {
    shown = await reveal({
      kind: KIND_REVERT,
      id: req.revertId,
      req,
      rpId: state.rp.rpId,
      path: revealPath("reverts", req.revertId),
      secret: relay.secret,
      fetchFn: engineFetch,
      getAssertion: (options) => navigator.credentials.get(options),
    });
  } catch (err) {
    const failure = revealFailure(err, KIND_REVERT);
    status = failure?.text ?? (err?.name === "NotAllowedError" ? webauthnError(err) : personText(err) || err.message);
    if (failure?.final) state.revealFinal = req;
  }
  state.busy = false;
  // Rows of an older request never land on the lines shown now.
  if (shown !== null) applyReveal(state, req, shown);
  if (state.req === req) $("reveal-status").textContent = status;
  render(state);
}

// openScope shows the scope sheet on a phone; on a wide screen the scope is
// always in the decision panel (style.css).
function openScope(open) {
  $("scope-panel").classList.toggle("open", open);
  $("sheet-dim").hidden = !open;
}

const describe = (err) => (err?.reason === "LINK_RESET" ? RESET_MESSAGE : linkFailure(err, "revert", REVERT_REOPEN));

async function main() {
  let rp;
  let req;
  let relay;
  try {
    rp = relyingParty(window.location);
    ({ req, relay } = await loadOrPaste(loadRequest, describe));
  } catch (err) {
    fail(describe(err));
    return;
  }
  const expired = req.binding.expiresAt.getTime() <= Date.now();
  const state = { rp, req, relay, catalog: null, known: [], choices: null, busy: false, expired, shown: new Map(), revealDone: false };
  render(state);
  $("main").hidden = false;
  setInterval(() => {
    $("expires-in").textContent = expiresIn(state.req.binding.expiresAt, new Date());
  }, EXPIRY_TICK_MS);
  wireReject(state);
  $("widen").addEventListener("click", () => includeOthers(state));
  $("reveal").addEventListener("click", () => showValues(state));
  $("scope-line").addEventListener("click", () => openScope(true));
  $("scope-done").addEventListener("click", () => openScope(false));
  $("sheet-dim").addEventListener("click", () => openScope(false));
  if (expired) return;
  $("sign").addEventListener("click", () => sign(rp, state));
}

// Pages run it; the tests import rowTable without a page.
if (typeof document !== "undefined") main();

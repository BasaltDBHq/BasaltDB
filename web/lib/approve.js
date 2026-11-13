// The approval page: read the held action (from the long link's fragment,
// or from the engine for a short link /approvals/<id>), check the rows against
// the binding, show them, and sign the binding with the person's passkey.
// From a long link the page sends nothing anywhere and shows a code to
// paste; from a short link it posts the signature to the engine that served
// it (same origin), which relays it to Postgres.
import {
  KIND_APPROVE,
  approvalResponseJSON,
  checkApprovalRequest,
  displayValue,
  encodeApprovalResponse,
  paramsText,
  parseApprovalRequest,
  relyingParty,
  visibleText,
} from "./codec.js";
import { fetchRequest, isLongLink, linkSecret, pageId, postResponse, relayPaths } from "./local.js";
import { $, APPROVE_REOPEN, el, fail, linkFailure, loadOrPaste, personText, showCode, showDone, showRelayFailed, webauthnError } from "./page.js";
import { canReveal, hiddenLines, NOT_CHECKED, OPEN_FROM_ENGINE, reveal, revealedLine, revealFailure, revealPath, SHOWN_TO_YOU } from "./reveal.js";
import { canStartPasskey, cascadeConfirmation, headline, summarize } from "./summary.js";

const PROMPT_TIMEOUT_MS = 120000;

// display shows a column's value as the line carries it (displayValue), with
// the characters that hide or reorder text shown as escapes (visibleText).
function display(line, member, col) {
  const row = line[member] ?? {};
  return visibleText(displayValue(row[col], line.texts?.[member]?.get(col)));
}

function renderSummary(req, summary) {
  const b = req.binding;
  $("headline").textContent = visibleText(headline(summary));
  $("headline").classList.toggle("cascades", summary.cascadedRows > 0);
  $("agent").textContent = visibleText(b.agent);
  $("database").textContent = visibleText(b.database);
  $("intent").textContent = visibleText(b.intent);
  $("statement").textContent = visibleText(b.statement, { lines: true });
  // The signed text, not JSON.parse's rounding of it (paramsText).
  $("params").textContent = visibleText(paramsText(req.bindingText));
  $("rows").textContent = String(b.rows);
  $("expires").textContent = b.expiresAt.toLocaleString();
}

// rowTable shows a row's values: before only for a DELETE, after only for an
// INSERT, both for an UPDATE with the assigned columns highlighted.
export function rowTable(line) {
  const showBefore = line.op !== "INSERT";
  const showAfter = line.op !== "DELETE";
  const table = el("table", "values");
  const head = el("tr");
  head.append(el("th", "", "Column"));
  if (showBefore) head.append(el("th", "", "Before"));
  if (showAfter) head.append(el("th", "", "After"));
  table.append(head);
  const before = line.old ?? {};
  const after = line.set ?? {};
  const columns = [...new Set([...Object.keys(before), ...Object.keys(after)])];
  for (const col of columns) {
    const assigned = col in after;
    const tr = el("tr", assigned && line.op === "UPDATE" ? "changed" : "");
    tr.append(el("td", "col", visibleText(col)));
    if (showBefore) tr.append(el("td", "", display(line, "old", col)));
    if (showAfter) tr.append(el("td", "", assigned ? display(line, "set", col) : ""));
    table.append(tr);
  }
  return table;
}

// renderLine shows one row. A hidden row shows its values once the person
// revealed them (shown), labelled as shown to them only, and as not checked
// when Postgres left out secret columns; until then it says the values are
// hidden, and on a long link where to see them.
export function renderLine(line, shown = null, longLink = false) {
  const card = el("li", "row");
  const title = el("div", "row-title");
  title.append(el("span", `op op-${line.op.toLowerCase()}`, line.op));
  title.append(el("span", "table-name", visibleText(line.table)));
  if (line.cascaded) title.append(el("span", "badge", "cascaded"));
  card.append(title);
  if (line.redacted && shown) {
    card.append(el("p", "muted", SHOWN_TO_YOU));
    if (!shown.checked) card.append(el("p", "conflict", NOT_CHECKED));
    card.append(rowTable(revealedLine(line, shown, "old")));
    return card;
  }
  if (line.redacted) {
    const hidden = "Values hidden: the agent cannot read this table.";
    card.append(el("p", "muted", longLink ? `${hidden} ${OPEN_FROM_ENGINE}` : hidden));
    return card;
  }
  if (line.op === "INSERT") card.append(el("p", "muted", "New row. Columns not listed are filled in by the database."));
  card.append(rowTable(line));
  return card;
}

// gate enables the passkey button once the person may start the prompt: a
// write with cascaded rows needs the cascade box ticked first, and an
// expired approval never.
function gate(req, summary) {
  const expired = req.binding.expiresAt.getTime() <= Date.now();
  const allowed = canStartPasskey({ summary, confirmed: $("cascade-ok").checked, expired });
  $("approve").disabled = !allowed;
  return allowed;
}

function showCascadeConfirmation(summary) {
  const text = cascadeConfirmation(summary);
  if (text === null) return;
  $("cascade-text").textContent = visibleText(text);
  $("cascade-confirm").hidden = false;
}

// engineFetch is fetch bound to the window, for the local relay.
const engineFetch = (path, init) => window.fetch(path, init);

// loadRequest reads the request: from the fragment of a long link, or from
// the engine for a short link. relay is the path to post the signature to,
// null for a long link.
async function loadRequest(hash) {
  // Every link names its approval in the path; a long link's request must
  // name the same one.
  const id = pageId(window.location.pathname, "approvals");
  if (isLongLink(hash)) {
    const req = await parseApprovalRequest(hash);
    if (req.approvalId !== id) throw new Error(`the link is for approval ${req.approvalId}, its path for ${id}`);
    return { req, relay: null };
  }
  const paths = relayPaths("approvals", id);
  // A short link: #s=<secret>. Without it the engine answers as for an
  // unknown id.
  const secret = linkSecret(hash);
  const req = await checkApprovalRequest(await fetchRequest(engineFetch, paths.request, secret));
  if (req.approvalId !== id) throw new Error(`the engine sent approval ${req.approvalId}, not ${id}`);
  return { req, relay: { path: paths.relay, secret } };
}

// finish relays the signed response when the page came from a short link,
// and otherwise (or when the relay fails) shows the code to paste.
async function finish(response, relay) {
  if (relay !== null) {
    try {
      await postResponse(engineFetch, relay.path, relay.secret, approvalResponseJSON(response));
      showDone("Approved. The agent will continue.");
      return;
    } catch (err) {
      showRelayFailed(`The engine did not take the approval: ${personText(err) || err.message}. To finish by hand, paste the code below into basalt approve.`);
    }
  }
  showCode(encodeApprovalResponse(response));
}

async function approve(rp, req, summary, relay) {
  if (!gate(req, summary)) return;
  $("approve").disabled = true;
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
        approvalId: req.approvalId,
        credentialId: new Uint8Array(cred.rawId),
        authenticatorData: new Uint8Array(r.authenticatorData),
        clientDataJson: new Uint8Array(r.clientDataJSON),
        signature: new Uint8Array(r.signature),
      },
      relay,
    );
  } catch (err) {
    gate(req, summary);
    $("status").textContent = webauthnError(err);
  }
}

const describe = (err) => linkFailure(err, "approval", APPROVE_REOPEN);

function renderLines(state) {
  const longLink = state.relay === null;
  $("lines").replaceChildren(...state.req.lines.map((line, i) => renderLine(line, state.shown.get(i) ?? null, longLink)));
}

// wireReveal offers Show values on a page the engine served with hidden
// rows: one passkey prompt shows every hidden row. It never prompts on its
// own (HR-4), and signing still asks for the passkey again.
function wireReveal(rp, state) {
  const { req, relay } = state;
  if (!canReveal(req, relay)) return;
  $("reveal-text").textContent = `${hiddenLines(req)} of these rows are in tables the agent cannot read. You can see their values with your passkey; the agent still cannot.`;
  $("reveal-box").hidden = false;
  $("reveal").addEventListener("click", async () => {
    $("reveal").disabled = true;
    $("reveal-status").textContent = "";
    try {
      state.shown = await reveal({
        kind: KIND_APPROVE,
        id: req.approvalId,
        req,
        rpId: rp.rpId,
        path: revealPath("approvals", req.approvalId),
        secret: relay.secret,
        fetchFn: engineFetch,
        getAssertion: (options) => navigator.credentials.get(options),
      });
      renderLines(state);
      $("reveal-box").hidden = true;
    } catch (err) {
      const failure = revealFailure(err, KIND_APPROVE);
      $("reveal-status").textContent = failure?.text ?? (err?.name === "NotAllowedError" ? webauthnError(err) : personText(err) || err.message);
      $("reveal").disabled = failure?.final === true;
    }
  });
}

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
  const summary = summarize(req.lines);
  renderSummary(req, summary);
  const state = { req, relay, shown: new Map() };
  renderLines(state);
  wireReveal(rp, state);
  $("main").hidden = false;
  if (req.binding.expiresAt.getTime() <= Date.now()) {
    $("approve").disabled = true;
    $("status").textContent = "This approval expired. The write stays blocked; the agent has to ask again.";
    return;
  }
  showCascadeConfirmation(summary);
  gate(req, summary);
  $("cascade-ok").addEventListener("change", () => gate(req, summary));
  $("approve").addEventListener("click", () => approve(rp, req, summary, relay));
}

// Tests import the module without a document; only a page runs main.
if (typeof document !== "undefined") main();

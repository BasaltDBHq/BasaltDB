// The approval page: read the held action (from the long link's fragment,
// or from the engine for a short link /approvals/<id>), check the rows against
// the binding, show them, and sign the binding with the person's passkey.
// From a long link the page sends nothing anywhere and shows a code to
// paste; from a short link it posts the signature to the engine that served
// it (same origin), which relays it to Postgres.
import { approvalResponseJSON, checkApprovalRequest, displayValue, encodeApprovalResponse, parseApprovalRequest, relyingParty } from "./codec.js";
import { fetchRequest, isLongLink, linkSecret, pageId, postResponse, relayPaths } from "./local.js";
import { $, APPROVE_REOPEN, el, fail, linkFailure, personText, showCode, showDone, showRelayFailed, webauthnError } from "./page.js";
import { canStartPasskey, cascadeConfirmation, headline, summarize } from "./summary.js";

const PROMPT_TIMEOUT_MS = 120000;

// display shows a column's value as the line carries it (displayValue).
function display(line, member, col) {
  const row = line[member] ?? {};
  return displayValue(row[col], line.texts?.[member]?.get(col));
}

function renderSummary(req, summary) {
  const b = req.binding;
  $("headline").textContent = headline(summary);
  $("headline").classList.toggle("cascades", summary.cascadedRows > 0);
  $("agent").textContent = b.agent;
  $("database").textContent = b.database;
  $("intent").textContent = b.intent;
  $("statement").textContent = b.statement;
  $("params").textContent = JSON.stringify(b.params);
  $("rows").textContent = String(b.rows);
  $("expires").textContent = b.expiresAt.toLocaleString();
}

// rowTable shows a row's values: before only for a DELETE, after only for an
// INSERT, both for an UPDATE with the assigned columns highlighted.
function rowTable(line) {
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
    tr.append(el("td", "col", col));
    if (showBefore) tr.append(el("td", "", display(line, "old", col)));
    if (showAfter) tr.append(el("td", "", assigned ? display(line, "set", col) : ""));
    table.append(tr);
  }
  return table;
}

function renderLine(line) {
  const card = el("li", "row");
  const title = el("div", "row-title");
  title.append(el("span", `op op-${line.op.toLowerCase()}`, line.op));
  title.append(el("span", "table-name", line.table));
  if (line.cascaded) title.append(el("span", "badge", "cascaded"));
  card.append(title);
  if (line.redacted) {
    card.append(el("p", "muted", "Values hidden: the agent cannot read this table."));
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
  $("cascade-text").textContent = text;
  $("cascade-confirm").hidden = false;
}

// engineFetch is fetch bound to the window, for the local relay.
const engineFetch = (path, init) => window.fetch(path, init);

// loadRequest reads the request: from the fragment of a long link, or from
// the engine for a short link. relay is the path to post the signature to,
// null for a long link.
async function loadRequest() {
  // Every link names its approval in the path; a long link's request must
  // name the same one.
  const id = pageId(window.location.pathname, "approvals");
  if (isLongLink(window.location.hash)) {
    const req = await parseApprovalRequest(window.location.hash);
    if (req.approvalId !== id) throw new Error(`the link is for approval ${req.approvalId}, its path for ${id}`);
    return { req, relay: null };
  }
  const paths = relayPaths("approvals", id);
  // A short link: #s=<secret>. Without it the engine answers as for an
  // unknown id.
  const secret = linkSecret(window.location.hash);
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

async function main() {
  let rp;
  let req;
  let relay;
  try {
    rp = relyingParty(window.location);
    ({ req, relay } = await loadRequest());
  } catch (err) {
    fail(linkFailure(err, "approval", APPROVE_REOPEN));
    return;
  }
  const summary = summarize(req.lines);
  renderSummary(req, summary);
  const list = $("lines");
  for (const line of req.lines) list.append(renderLine(line));
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

main();

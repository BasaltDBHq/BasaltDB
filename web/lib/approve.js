// The approval page: decode the held action from the link, check the rows
// against the binding, show them, and sign the binding with the person's
// passkey. The page sends nothing anywhere; it shows a code to paste.
import { encodeApprovalResponse, parseApprovalRequest, relyingParty } from "./codec.js";
import { $, APPROVE_REOPEN, el, fail, linkFailure, showCode, webauthnError } from "./page.js";
import { canStartPasskey, cascadeConfirmation, headline, summarize } from "./summary.js";

const PROMPT_TIMEOUT_MS = 120000;

function display(value) {
  if (value === undefined) return "";
  if (typeof value === "string") return value;
  return JSON.stringify(value);
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
    if (showBefore) tr.append(el("td", "", display(before[col])));
    if (showAfter) tr.append(el("td", "", assigned ? display(after[col]) : ""));
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

async function approve(rp, req, summary) {
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
    showCode(
      encodeApprovalResponse({
        approvalId: req.approvalId,
        credentialId: new Uint8Array(cred.rawId),
        authenticatorData: new Uint8Array(r.authenticatorData),
        clientDataJson: new Uint8Array(r.clientDataJSON),
        signature: new Uint8Array(r.signature),
      }),
    );
  } catch (err) {
    gate(req, summary);
    $("status").textContent = webauthnError(err);
  }
}

async function main() {
  let rp;
  let req;
  try {
    rp = relyingParty(window.location);
    req = await parseApprovalRequest(window.location.hash);
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
  $("approve").addEventListener("click", () => approve(rp, req, summary));
}

main();

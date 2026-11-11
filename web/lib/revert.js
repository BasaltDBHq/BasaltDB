// The revert page: decode the revert from the link, check the lines against
// the binding, show what will be restored and what is left alone, and sign
// the binding with the person's passkey. The page sends nothing anywhere; it
// shows a code to paste into `basalt revert`.
import {
  MAX_REVERT_BATCH,
  REVERT_APPLY_HOURS,
  encodeRevertResponse,
  parseRevertRequest,
  relyingParty,
} from "./codec.js";
import { $, el, fail, showCode, webauthnError } from "./page.js";

const PROMPT_TIMEOUT_MS = 120000;

const SCOPES = { CHANGE: "One change", RUN: "One run", TASK: "One task, every agent" };

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

function display(value) {
  if (value === undefined) return "";
  if (typeof value === "string") return value;
  return JSON.stringify(value);
}

function plural(n, word) {
  return `${n} ${word}${n === 1 ? "" : "s"}`;
}

function renderSummary(req) {
  const b = req.binding;
  $("scope").textContent = `${SCOPES[b.scope]} (${b.scopeId})`;
  $("agents").textContent = b.agents.join(", ");
  $("database").textContent = b.database;
  $("intent").textContent = b.intent;
  $("rows").textContent = plural(b.rows, "row");
  $("skipped").textContent = plural(b.skipped, "row");
  $("expires").textContent = b.expiresAt.toLocaleString();
  if (!b.batched) {
    $("plan").textContent = `${plural(b.rows + b.skipped, "row")}, all shown below, restored in one step when you sign.`;
    return;
  }
  // A large plan (decisions N12-1 to N12-4): the link carries a sample.
  const restoreShown = req.lines.filter((l) => l.action === "RESTORE").length;
  const skipShown = req.lines.length - restoreShown;
  $("plan").textContent =
    `${plural(b.rows + b.skipped, "row")}. Your signature covers every one; this page shows the first ${req.lines.length}, ` +
    `rows left alone first. After you sign, the agent restores them in batches of up to ${MAX_REVERT_BATCH} rows ` +
    `within ${REVERT_APPLY_HOURS} hours. Follow it with basalt revert --status ${b.revertId}.`;
  $("restore-title").textContent = `Rows that will be restored (${restoreShown} of ${b.rows} shown)`;
  $("skip-title").textContent = `Rows left as they are (${skipShown} of ${b.skipped} shown)`;
  $("restore-note").textContent =
    "Highlighted values change back to what they were before the agent. Each row is checked again with its row locked when its batch runs; a row someone changed by then is left as it is.";
}

// rowTable shows a row now and after the revert: only "Now" for a row the
// revert deletes, only "After revert" for a row it re-inserts, both for an
// update with the columns that change highlighted.
function rowTable(line) {
  const now = line.now ?? {};
  const after = line.set ?? {};
  const showNow = line.now !== null;
  const showAfter = line.set !== null;
  const table = el("table", "values");
  const head = el("tr");
  head.append(el("th", "", "Column"));
  if (showNow) head.append(el("th", "", "Now"));
  if (showAfter) head.append(el("th", "", "After revert"));
  table.append(head);
  const columns = [...new Set([...Object.keys(now), ...Object.keys(after)])];
  for (const col of columns) {
    const changes = showNow && showAfter && col in after && display(now[col]) !== display(after[col]);
    const tr = el("tr", changes ? "changed" : "");
    tr.append(el("td", "col", col));
    if (showNow) tr.append(el("td", "", display(now[col])));
    if (showAfter) tr.append(el("td", "", display(after[col])));
    table.append(tr);
  }
  return table;
}

function opLabel(line) {
  if (line.op === "DELETE") return "DELETE";
  if (line.op === "INSERT") return "RE-INSERT";
  return "RESTORE";
}

function renderLine(line) {
  const card = el("li", "row");
  const title = el("div", "row-title");
  title.append(el("span", `op op-${line.op.toLowerCase()}`, opLabel(line)));
  title.append(el("span", "table-name", line.table));
  if (line.cascaded) title.append(el("span", "badge", "cascaded"));
  card.append(title);
  if (line.action === "SKIP") {
    const reason = CONFLICTS[line.conflict];
    card.append(el("p", "conflict", line.sqlState ? `${reason} (SQLSTATE ${line.sqlState})` : reason));
  }
  if (line.redacted) {
    card.append(el("p", "muted", "Values hidden: the role that prepared this revert cannot read this table."));
    return card;
  }
  if (line.op === "DELETE" && line.action === "RESTORE") card.append(el("p", "muted", "The agent inserted this row; the revert deletes it."));
  card.append(rowTable(line));
  return card;
}

async function sign(rp, req) {
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
    showCode(
      encodeRevertResponse({
        revertId: req.revertId,
        credentialId: new Uint8Array(cred.rawId),
        authenticatorData: new Uint8Array(r.authenticatorData),
        clientDataJson: new Uint8Array(r.clientDataJSON),
        signature: new Uint8Array(r.signature),
      }),
    );
  } catch (err) {
    $("sign").disabled = false;
    $("status").textContent = webauthnError(err);
  }
}

async function main() {
  let rp;
  let req;
  try {
    rp = relyingParty(window.location);
    req = await parseRevertRequest(window.location.hash);
  } catch (err) {
    fail(`This revert link cannot be used: ${err.message}`);
    return;
  }
  renderSummary(req);
  for (const line of req.lines) {
    $(line.action === "SKIP" ? "skip" : "restore").append(renderLine(line));
  }
  $("skip-section").hidden = req.binding.skipped === 0;
  $("main").hidden = false;
  if (req.binding.expiresAt.getTime() <= Date.now()) {
    $("sign").disabled = true;
    $("status").textContent = "This revert link expired. Nothing was reverted; run basalt revert again.";
    return;
  }
  $("sign").addEventListener("click", () => sign(rp, req));
}

main();

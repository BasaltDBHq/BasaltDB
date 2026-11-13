// The approval page: read the held action (from the long link's fragment,
// or from the engine for a short link /approvals/<id>), check the rows against
// the binding, show them, and sign the binding with the person's passkey.
// From a long link the page sends nothing anywhere and shows a code to
// paste; from a short link it posts the signature to the engine that served
// it (same origin), which relays it to Postgres.
import { changeGroups, countText } from "./changes.js";
import {
  KIND_APPROVE,
  approvalResponseJSON,
  checkApprovalRequest,
  encodeApprovalResponse,
  paramsText,
  parseApprovalRequest,
  relyingParty,
  visibleText,
} from "./codec.js";
import { fetchRequest, isLongLink, linkSecret, pageId, postResponse, relayPaths } from "./local.js";
import { $, APPROVE_REOPEN, el, fail, linkFailure, loadOrPaste, personText, setPill, showCode, showDone, showRelayFailed, webauthnError, whenText } from "./page.js";
import { applyReveal, canReveal, hiddenLines, reveal, revealFailure, revealPath, SHOWN_TO_YOU } from "./reveal.js";
import { canStartPasskey, cascadeConfirmation, headline, summarize } from "./summary.js";

const PROMPT_TIMEOUT_MS = 120000;

const VERBS = { DELETE: "delete", UPDATE: "update", INSERT: "insert" };

// mainOp is the write's own op: of its first direct row, else of its first
// cascaded one.
export function mainOp(summary) {
  return summary.direct[0]?.op ?? summary.cascaded[0]?.op ?? null;
}

// approveLabel is the passkey button's text: the write's own rows of its
// op, then the cascade, "Approve: delete 1 row + 2 cascaded". The cascaded
// rows are never counted as the write's own. A delete's button is red.
export function approveLabel(summary) {
  const rows = (n) => (n === 1 ? "1 row" : `${n} rows`);
  const op = mainOp(summary);
  const own = summary.direct.filter((g) => g.op === op).reduce((n, g) => n + g.rows, 0);
  const cascade = summary.cascadedRows > 0 ? ` + ${summary.cascadedRows} cascaded` : "";
  if (own === 0) return `Approve: ${rows(summary.cascadedRows)} cascaded`;
  return `Approve: ${VERBS[op] ?? op.toLowerCase()} ${rows(own)}${cascade}`;
}

function hex(bytes) {
  return Array.from(new Uint8Array(bytes), (b) => b.toString(16).padStart(2, "0")).join("");
}

// signedText is the footer: the hash the passkey signs, shortened.
export function signedText(challenge, rows) {
  const h = hex(challenge);
  return `You sign sha256:${h.slice(0, 4)}\u2026${h.slice(-4)} over the statement, its parameters and these ${rows === 1 ? "1 row" : `${rows} rows`}.`;
}

// ID_SHOWN is how much of the approval id the top bar shows; all of it on hover.
const ID_SHOWN = 8;

function renderSummary(req, summary) {
  const b = req.binding;
  const op = mainOp(summary);
  $("op").textContent = op ?? "";
  $("op").className = `op-badge op-${(op ?? "").toLowerCase()}`;
  $("op").hidden = op === null;
  $("item-id").textContent = req.approvalId.slice(-ID_SHOWN);
  $("item-id").title = req.approvalId;
  $("headline").textContent = visibleText(headline(summary));
  $("headline").classList.toggle("cascades", summary.cascadedRows > 0);
  // The agent by its name in the engine's config when the engine says it
  // (display only); the signed role on hover, and alone on a long link.
  $("agent").textContent = visibleText(req.agentName ?? b.agent);
  $("agent").title = visibleText(b.agent);
  $("database").textContent = visibleText(b.database);
  $("intent").textContent = visibleText(b.intent);
  $("statement").textContent = visibleText(b.statement, { lines: true });
  // The signed text, not JSON.parse's rounding of it (paramsText).
  $("params").textContent = visibleText(paramsText(req.bindingText));
  $("rows").textContent = String(b.rows);
  $("expires").textContent = b.expiresAt.toLocaleString();
  const now = new Date();
  if (b.expiresAt.getTime() <= now.getTime()) setPill("state", "Expired", "bad");
  else setPill("state", `Held \u00b7 expires ${whenText(b.expiresAt, now)}`, "hold");
  $("approve").textContent = approveLabel(summary);
  $("approve").classList.toggle("danger", op === "DELETE");
  $("change-count").replaceChildren(...countText(req.lines).map((c) => el("span", `count-${c.op.toLowerCase()}`, c.text)));
  $("signed-hash").textContent = signedText(req.challenge, b.rows);
}

const INSERT_NOTE = "New row. Columns not listed are filled in by the database.";

// lineGroups renders the rows as one table per table. A hidden row shows
// its values once the person revealed them (shown), labelled as shown to
// them only, and as not checked when Postgres left out secret columns;
// until then its values show as dots, and on a long link it says where to
// see them.
export function lineGroups(lines, shown = new Map(), longLink = false, columns = new Map()) {
  return changeGroups(
    lines.map((line, index) => ({ line, index })),
    {
      mid: "old",
      shown,
      columns,
      longLink,
      who: null,
      skipped: () => false,
      why: () => null,
      // Highlighted values are what the statement sets.
      highlights: () => true,
      notes: (ls) => (ls.some((l) => l.op === "INSERT") ? [INSERT_NOTE] : []),
    },
  );
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
      setPill("state", "Approved", "ok");
      return;
    } catch (err) {
      showRelayFailed(`The engine did not take the approval: ${personText(err) || err.message}. To finish by hand, paste the code below into basalt approve.`);
    }
  }
  showCode(encodeApprovalResponse(response));
  setPill("state", "Signed", "ok");
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
  const shown = state.valuesHidden ? new Map() : state.shown;
  $("lines").replaceChildren(...lineGroups(state.req.lines, shown, longLink, state.req.columns));
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
      const shown = await reveal({
        kind: KIND_APPROVE,
        id: req.approvalId,
        req,
        rpId: rp.rpId,
        path: revealPath("approvals", req.approvalId),
        secret: relay.secret,
        fetchFn: engineFetch,
        getAssertion: (options) => navigator.credentials.get(options),
      });
      applyReveal(state, req, shown);
      renderLines(state);
      $("reveal").hidden = true;
      $("reveal-text").textContent = SHOWN_TO_YOU;
      $("hide-values").hidden = false;
    } catch (err) {
      const failure = revealFailure(err, KIND_APPROVE);
      $("reveal-status").textContent = failure?.text ?? (err?.name === "NotAllowedError" ? webauthnError(err) : personText(err) || err.message);
      $("reveal").disabled = failure?.final === true;
    }
  });
  // Hide values only hides them on this page; showing them again needs no
  // passkey: the page still has them.
  $("hide-values").addEventListener("click", () => {
    state.valuesHidden = !state.valuesHidden;
    $("hide-values-text").textContent = state.valuesHidden ? "Show values" : "Hide values";
    $("hide-values").setAttribute("aria-pressed", String(state.valuesHidden));
    renderLines(state);
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

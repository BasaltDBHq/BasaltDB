// DOM helpers shared by the approval and registration pages. Text only goes
// into the page through textContent, never innerHTML: every value on these
// pages came from a link someone else built.
import { checkReceipt, RELAY, fingerprint as engineFingerprint } from "./channel.js";
import { visibleText } from "./codec.js";
import { readPaste, repairHash } from "./repair.js";
import { BlockAssembler, HASH_PREFIX, MAX_REQUEST_FILE_BYTES, readRequestFile } from "./requestfile.js";

export const $ = (id) => document.getElementById(id);

// controlsOf lists the buttons and boxes under the elements the ids name, to
// lock while one of them works. A page with no such elements gives none.
export const controlsOf = (...ids) => [...(globalThis.document?.querySelectorAll?.(ids.flatMap((id) => [`${id} button`, `${id} input`]).join(", ")) ?? [])];

// busy marks a pressed button as working, at once and before any await: it
// disables the button, sets aria-busy="true" (the stylesheet draws the
// spinner from it) and swaps the label for the working one. It returns done,
// which gives the button back as it was; done.label(text) changes the
// working label while the button stays busy ("Waiting for your passkey…",
// then "Setting up…"). It returns null while the button is already busy, so a
// second press sends nothing: `const done = busy(b, "Checking…"); if (!done) return;`.
// Every way out of the handler calls done(), also when the view moves on, so
// a screen shown again does not come back stuck. done() puts the label and
// the disabled state back, so paint the same button's disabled state after
// it; a label the page painted meanwhile is left alone.
// lock lists the other controls that would start or change the same action
// (the Check button, the boxes): they are disabled while the button is busy,
// and done() gives back the ones that were enabled.
export function busy(button, label, lock = []) {
  if (!button || button.getAttribute("aria-busy") === "true") return null;
  // A button with an icon keeps it: its child nodes come back, not its text.
  const kept = button.childNodes && button.replaceChildren ? [...button.childNodes] : null;
  const label0 = button.textContent;
  const disabled0 = button.disabled === true;
  button.setAttribute("aria-busy", "true");
  button.disabled = true;
  button.textContent = label;
  const locked = lock.filter((n) => n && n !== button && n.disabled !== true);
  for (const n of locked) n.disabled = true;
  let shown = label;
  let over = false;
  const done = () => {
    if (over) return;
    over = true;
    button.setAttribute("aria-busy", "false");
    // A page that painted the button's label meanwhile keeps its own.
    if (button.textContent === shown) {
      if (kept) button.replaceChildren(...kept);
      else button.textContent = label0;
    }
    button.disabled = disabled0;
    for (const n of locked) n.disabled = false;
  };
  done.label = (text) => {
    if (over) return;
    shown = text;
    button.textContent = text;
  };
  return done;
}

const MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

// whenText is a moment in local time for a pill: "17:37" today, else with
// its date, "14 Nov 17:37".
export function whenText(at, now) {
  const time = `${String(at.getHours()).padStart(2, "0")}:${String(at.getMinutes()).padStart(2, "0")}`;
  const today = at.getFullYear() === now.getFullYear() && at.getMonth() === now.getMonth() && at.getDate() === now.getDate();
  return today ? time : `${at.getDate()} ${MONTHS[at.getMonth()]} ${time}`;
}

// setPill sets the top bar's state pill: hold (amber), ok (green) or bad
// (red).
export function setPill(id, text, tone) {
  $(id).textContent = text;
  $(id).className = `pill ${tone}`;
  $(id).hidden = false;
}

export function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

// personText is what the engine tells the person about a failure: its
// personMessage and, for each of the person's steps, the command to run or
// the link to open. "" when the engine told nothing more than its message.
export function personText(err) {
  if (!err?.personMessage) return "";
  const lines = [err.personMessage];
  for (const step of err.nextSteps ?? []) {
    if (step.action === "RUN_COMMAND" && step.command) lines.push(step.text + " Run: " + step.command);
    if (step.action === "OPEN_LINK" && step.url) lines.push(step.text + " Open: " + step.url);
  }
  return lines.join("\n");
}

// WITHDRAWN_TEXT is a withdrawn request's line when the engine gave no
// message of its own.
export const WITHDRAWN_TEXT = "The agent withdrew this request. Nothing changed.";

// withdrawnText is what a page shows for err when the engine refused the
// request because the agent withdrew it (reason WITHDRAWN, CONTRACT.md,
// Withdrawn requests): the engine's line, "The agent withdrew this request:
// <reason>. Nothing changed."; null for any other failure.
export function withdrawnText(err) {
  if (err?.name !== "RelayError" || err.reason !== "WITHDRAWN") return null;
  return visibleText(err.personMessage || WITHDRAWN_TEXT);
}

// showWithdrawn shows a withdrawn request as an expired one is shown: the
// pill (pill, its id) says Withdrawn, the line takes the page's place, and
// nothing is left to sign.
export function showWithdrawn(pill, text) {
  setPill(pill, "Withdrawn", "bad");
  fail(text);
}

// linkFailure is the sentence a page shows when its link cannot be used.
// kind names the page ("approval", "revert"); reopen says how to get a
// working link. A link that does not decode was most likely cut short when
// copied, so the person is told to get it again, not that it is bad.
export function linkFailure(err, kind, reopen) {
  const told = err?.name === "RelayError" ? personText(err) : "";
  if (told && err.code === "NOT_FOUND") return told + "\nOr " + reopen + ".";
  if (told) return told;
  if (err?.name === "RelayError" && err.code === "NOT_FOUND") {
    return `This ${kind} link is incomplete, was replaced by a newer one, or the ${kind} is gone. ` +
      `${sentenceStart(reopen)}.`;
  }
  if (err?.name === "RelayError") {
    return `This ${kind} cannot be shown: ${err.message}`;
  }
  if (err?.name === "TruncatedLinkError") {
    return `This ${kind} link looks cut short (${err.message}). Long links often break when copied from a terminal or a chat. ` +
      `${sentenceStart(reopen)}.`;
  }
  return `This ${kind} link cannot be used: ${err?.message ?? err}`;
}

// sentenceStart starts s with a capital letter.
function sentenceStart(s) {
  return s.charAt(0).toUpperCase() + s.slice(1);
}

// What a cut, replaced or lost link tells the person: the agent gets a new
// link (list_pending, or request_revert, with reissueLink).
export const APPROVE_REOPEN = "ask the agent for a new link to this approval";
export const REVERT_REOPEN = "ask the agent for a new link to this revert";

// NO_CARRIER is what a page says on a long link: it shows the change, but
// only a short link (from the engine's own pages, or from BasaltVault)
// can send a signature to the engine, so the page offers no passkey prompt.
export const NO_CARRIER =
  "This link shows the change but cannot send your signature to the engine, so it cannot be signed here. " +
  "Only a short link from the engine's own pages or from BasaltVault can. Nothing was signed.";

const NO_LINK_IN_PASTE =
  "No link found in that text. Paste the whole message from your agent, from the line before the link to the line after it.";

// loadOrPaste loads with the page's own fragment, repaired (CONTRACT.md,
// Showing links). When that fails it shows the paste box and loads with the
// fragment read from the pasted message. load(hash) gets only a fragment: the
// page keeps its own origin and path, and never opens or fetches a pasted
// URL. describe(err) is the message to show for a failure.
export async function loadOrPaste(load, describe) {
  const hash = repairHash(window.location.hash);
  // Only the approval and revert pages have the request box; elsewhere a
  // hash link fails to load like any other fragment it cannot read.
  if (hash.startsWith(HASH_PREFIX) && $("request-box")) return askForRequest(hash.slice(HASH_PREFIX.length), load, describe);
  try {
    return await load(hash);
  } catch (err) {
    if (!pasteHelps(err)) throw err;
    return askForPaste(err, load, describe);
  }
}

// pasteHelps: a pasted link can only fix a link that is wrong. An answer of
// the engine other than NOT_FOUND (unavailable, expired, used) is not about
// the link, so the box is not shown for it.
function pasteHelps(err) {
  return err?.name !== "RelayError" || err.code === "NOT_FOUND";
}

// MAX_PASTE_CHARS caps the pasted text: far above the largest link the
// link budget (default 1800) allows, plus the message around it.
export const MAX_PASTE_CHARS = 20000;
const PASTE_TOO_LONG = "That text is too long to be one message from your agent. Paste only the message with the link.";

function askForPaste(err, load, describe) {
  fail(describe(err));
  $("paste-box").hidden = false;
  return new Promise((resolve) => {
    $("paste-read").addEventListener("click", async () => {
      const pasted = $("paste").value;
      if (pasted.length > MAX_PASTE_CHARS) {
        $("paste-status").textContent = PASTE_TOO_LONG;
        return;
      }
      const fragment = readPaste(pasted);
      if (fragment === null) {
        $("paste-status").textContent = NO_LINK_IN_PASTE;
        return;
      }
      const done = busy($("paste-read"), "Checking…");
      if (!done) return;
      try {
        resolve(await load(`#${fragment}`));
        $("paste-box").hidden = true;
        $("error").hidden = true;
      } catch (e) {
        $("paste-status").textContent = describe(e);
      } finally {
        done();
      }
    });
  });
}

// The request box of a hash link (CONTRACT.md, The request file and pasted
// blocks): the person gives the page the file or the text blocks their agent
// sent; once h matches, the text is loaded as a long link's fragment.
const REQUEST_MISMATCH = "This does not match the link: it is another request's, or it was cut or changed on the way. Ask the agent to send it again.";
const REQUEST_TOO_BIG = "That file is too big to be a request from your agent.";
const BLOCK_REASONS = {
  NO_BLOCK: "No block found in that text. Paste the blocks your agent sent, each starting with its basalt-request line.",
  CUT_SHORT: "A block was cut short. Copy that whole block again.",
  OTHER_REQUEST: "A block belongs to another request. Paste only the blocks sent with this link.",
};

export function requestProgress(assembler) {
  const missing = assembler.missing();
  if (assembler.n === 0) return "";
  const have = assembler.n - missing.length;
  if (missing.length === 0) return `All ${assembler.n} blocks are in.`;
  return `${have} of ${assembler.n} blocks; still missing: ${missing.join(", ")}.`;
}

function askForRequest(h, load, describe) {
  $("request-box").hidden = false;
  const assembler = new BlockAssembler(h);
  const say = (text) => {
    $("request-status").textContent = text;
  };
  return new Promise((resolve) => {
    const tryText = async (text) => {
      try {
        const loaded = await load(`#${text}`);
        $("request-box").hidden = true;
        resolve(loaded);
      } catch (e) {
        say(describe(e));
      }
    };
    $("request-file").addEventListener("change", async () => {
      const file = $("request-file").files?.[0];
      if (!file) return;
      if (file.size > MAX_REQUEST_FILE_BYTES) {
        say(REQUEST_TOO_BIG);
        return;
      }
      const got = await readRequestFile(await file.text(), h);
      if (got.error) {
        say(REQUEST_MISMATCH);
        return;
      }
      await tryText(got.text);
    });
    $("request-read").addEventListener("click", async () => {
      const done = busy($("request-read"), "Checking…");
      if (!done) return;
      try {
        await readBlocks();
      } finally {
        done();
      }
    });
    const readBlocks = async () => {
      const refused = assembler.add($("request-paste").value);
      $("request-paste").value = "";
      const progress = requestProgress(assembler);
      const reasons = [...new Set(refused)].map((r) => BLOCK_REASONS[r]);
      say([...reasons, progress].filter(Boolean).join(" "));
      const got = await assembler.text();
      if (got.error === "MISMATCH") {
        say(REQUEST_MISMATCH);
        return;
      }
      if (got.text) await tryText(got.text);
    };
  });
}

export function fail(message) {
  $("error-text").textContent = message;
  $("error").hidden = false;
  $("main").hidden = true;
}

// showEngine names the engine a portal session reached, with the
// fingerprint of the key the session verified, for the person to compare
// with the agent's status (CONTRACT.md, Engine keys: shown on every portal page
// with a session). Nothing for the engine's own local pages.
export function showEngine(session) {
  const engine = session?.engine;
  if (!engine) return;
  const fp = engineFingerprint(engine.engineId);
  $("engine").textContent = `Through the BasaltVault relay to the engine with fingerprint ${fp}. Before you sign, check that your agent's status shows the same fingerprint (vault.fingerprint).`;
  $("engine").hidden = false;
}

// endSession closes a finished page's session to the engine and disables
// the buttons that would still send it a request.
export function endSession(session, buttons) {
  session.close();
  for (const id of buttons) {
    const b = $(id);
    if (b) b.disabled = true;
  }
}

// openSession opens transport's session for link, saying so on the page
// while a RELAY session connects through the Vault.
export async function openSession(transport, link) {
  const note = transport.kind === RELAY ? $("connecting") : null;
  if (note) note.hidden = false;
  try {
    return await transport.open(link);
  } finally {
    if (note) note.hidden = true;
  }
}

// noReceiptText is why an answer carries no receipt (CONTRACT.md,
// Receipts, No receipt), as the engine's receipt line says it.
function noReceiptText(result) {
  switch (result.noReceipt) {
    case "KEY_ERROR":
      return "No receipt: the engine's key file is refused (the agent's status tool shows KEY_ERROR), so nothing confirms what was signed.";
    case "WIDENED": {
      const rows = result.batched ? `${result.pending ?? 0} rows to restore in batches` : `${result.rows ?? 0} rows restored`;
      return `No receipt: the revert's scope was changed on the signing page (${rows}). If you did not change it, tell the agent at once.`;
    }
    default:
      return visibleText(`No receipt: ${result.noReceipt}.`);
  }
}

export const RECEIPT_REFUSED =
  "The engine's receipt does not check against the key of this session or does not name what this page signed, " +
  "so this page shows nothing from it. Tell the agent.";

// receiptText is what the page says of a receipt it checked against the
// session's own key: what the engine says was signed, and the fingerprint
// to compare with the one in the chat. It never calls the receipt verified:
// on the relay the session's key is not pinned (CONTRACT.md, Receipts, In
// the page), so only the person's comparison checks which engine signed.
// The headline is the engine's text: it goes through visibleText.
export function receiptText(payload, fp) {
  const kind = payload.kind === "REVERT" ? "revert" : "approval";
  return `Receipt from the engine with fingerprint ${fp}: ${visibleText(payload.headline)} (${kind} ${payload.itemId}, ${payload.status}). ` +
    "Compare this fingerprint with the one the agent showed you in the chat; this page cannot tell on its own which engine signed it.";
}

// receiptLine is the line for an approve or apply answer on a session:
// the receipt checked against the session's key and against what the page
// signed (expect: kind APPROVAL or REVERT, itemId and the binding's
// rowsHash), why there is none, or nothing (a same-origin page, an answer
// without either). A receipt for another item, kind or set of rows is
// refused like one that does not verify.
export async function receiptLine(result, session, expect) {
  const engine = session?.engine;
  if (!engine?.engineKey) return "";
  if (typeof result?.noReceipt === "string") return noReceiptText(result);
  if (typeof result?.receipt !== "string") return "";
  const payload = await checkReceipt(result.receipt, engine.engineKey);
  if (payload === null) return RECEIPT_REFUSED;
  if (payload.kind !== expect?.kind || payload.itemId !== expect?.itemId || payload.rowsHash !== expect?.rowsHash) return RECEIPT_REFUSED;
  return receiptText(payload, engineFingerprint(engine.engineId));
}

// showReceipt shows receiptLine's text, when there is one.
export async function showReceipt(result, session, expect) {
  const text = await receiptLine(result, session, expect);
  if (text === "") return;
  $("receipt").textContent = text;
  $("receipt").hidden = false;
}

// What a page says after a relayed signature failed. The engine
// answered with a refusal (an HTTP status): nothing was signed. No answer
// came (the session dropped after the request may have gone out): the page
// cannot tell, and the link shows whether it went through.
export const RELAY_REFUSED = "Nothing was signed through this page. Open the link again to sign again, or ask the agent for a new link.";
export const RELAY_NO_ANSWER =
  "This page did not hear back from the engine, so it cannot tell whether the signature went through. " +
  "Open the link again: it shows whether it was signed.";

// relayRefused says whether err, a relayed signature that failed, is the
// engine's own refusal (an answer with an HTTP status).
function relayRefused(err) {
  return err?.name === "RelayError" && err.status > 0;
}

// relayRetry is the sentence for err, a relayed signature that failed.
export function relayRetry(err) {
  return relayRefused(err) ? RELAY_REFUSED : RELAY_NO_ANSWER;
}

// relayFailure is what a page shows when the relayed signature of
// item ("approval", "revert") failed: the engine's refusal and its reason,
// or, with no answer, only that the page cannot tell.
export function relayFailure(err, item) {
  if (!relayRefused(err)) return RELAY_NO_ANSWER;
  return `The engine did not take the ${item}: ${personText(err) || err.message}. ${RELAY_REFUSED}`;
}

// showDone says the engine took the signature: nothing to paste.
export function showDone(message) {
  $("done-text").textContent = message;
  $("done").hidden = false;
  $("action").hidden = true;
}

// showRelayFailed says the engine did not take the signature.
export function showRelayFailed(message) {
  $("done-text").textContent = message;
  $("done").hidden = false;
}

// showCode shows the result code with Copy and, where the browser can,
// Share, so the person can paste it into `basalt` or the agent's chat.
export function showCode(code) {
  $("code").value = code;
  $("result").hidden = false;
  $("action").hidden = true;
  $("copy").addEventListener("click", async () => {
    try {
      await navigator.clipboard.writeText(code);
      $("copy").textContent = "Copied";
    } catch {
      $("code").select();
    }
  });
  if (typeof navigator.share !== "function") return;
  $("share").hidden = false;
  $("share").addEventListener("click", () => navigator.share({ text: code }).catch(() => {}));
}

// webauthnError turns a WebAuthn failure into a sentence for the person.
// offered is how many of the database's passkeys the prompt allowed: with
// some, a prompt that ends with none may mean this device has none of them.
export function webauthnError(err, offered = 0) {
  if (err && err.name === "NotAllowedError" && offered > 0) {
    return "Nothing was signed. The prompt was cancelled or timed out, or this device has none of this database's passkeys: " +
      "use the device or password manager that holds the passkey you registered with basalt init.";
  }
  if (err && err.name === "NotAllowedError") return "The passkey prompt was cancelled or timed out. Nothing was signed.";
  if (err && err.name === "SecurityError") return "This browser refused the passkey for this site.";
  return `The passkey could not sign: ${err && err.message ? err.message : err}`;
}

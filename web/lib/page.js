// DOM helpers shared by the approval and registration pages. Text only goes
// into the page through textContent, never innerHTML: every value on these
// pages came from a link someone else built.
import { readPaste, repairHash } from "./repair.js";

export const $ = (id) => document.getElementById(id);

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

// linkFailure is the sentence a page shows when its link cannot be used.
// kind names the page ("approval", "revert"); reopen says how to open the
// full link from the terminal. A link that does not decode was most likely
// cut short when copied, so the person is told to reopen it, not that it
// is bad.
export function linkFailure(err, kind, reopen) {
  const told = err?.name === "RelayError" ? personText(err) : "";
  if (told && err.code === "NOT_FOUND") return told + "\nOr " + reopen + ".";
  if (told) return told;
  if (err?.name === "RelayError" && err.code === "NOT_FOUND") {
    return `This ${kind} link is incomplete, was replaced by a newer one, or the ${kind} is gone. ` +
      `Ask the agent for the link again (it gets a new one from list_pending), or ${reopen}.`;
  }
  if (err?.name === "RelayError") {
    return `This ${kind} cannot be shown: ${err.message}`;
  }
  if (err?.name === "TruncatedLinkError") {
    return `This ${kind} link looks cut short (${err.message}). Long links often break when copied from a terminal or a chat. ` +
      `Open it from your terminal instead: ${reopen}.`;
  }
  return `This ${kind} link cannot be used: ${err?.message ?? err}`;
}

export const APPROVE_REOPEN =
  "run basalt approve --agent <name> --open <approvalId> with the approvalId your agent gave you; it opens the full link in your browser";
export const REVERT_REOPEN =
  "run your basalt revert command again with --open; it prepares the revert and opens the full link in your browser";

const NO_LINK_IN_PASTE =
  "No link found in that text. Paste the whole message from your agent, from the line before the link to the line after it.";

// loadOrPaste loads with the page's own fragment, repaired (CONTRACT.md,
// Showing links). When that fails it shows the paste box and loads with the
// fragment read from the pasted message. load(hash) gets only a fragment: the
// page keeps its own origin and path, and never opens or fetches a pasted
// URL. describe(err) is the message to show for a failure.
export async function loadOrPaste(load, describe) {
  try {
    return await load(repairHash(window.location.hash));
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
      $("paste-read").disabled = true;
      try {
        resolve(await load(`#${fragment}`));
        $("paste-box").hidden = true;
        $("error").hidden = true;
      } catch (e) {
        $("paste-status").textContent = describe(e);
      }
      $("paste-read").disabled = false;
    });
  });
}

export function fail(message) {
  $("error-text").textContent = message;
  $("error").hidden = false;
  $("main").hidden = true;
}

// showDone says the engine took the signature: nothing to paste.
export function showDone(message) {
  $("done-text").textContent = message;
  $("done").hidden = false;
  $("action").hidden = true;
}

// showRelayFailed says the engine did not take the signature; the code
// shown next is the way to finish by hand.
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

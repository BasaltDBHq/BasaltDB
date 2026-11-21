// DOM helpers shared by the approval and registration pages. Text only goes
// into the page through textContent, never innerHTML: every value on these
// pages came from a link someone else built.
import { RELAY, fingerprint as engineFingerprint } from "./channel.js";
import { readPaste, repairHash } from "./repair.js";
import { BlockAssembler, HASH_PREFIX, MAX_REQUEST_FILE_BYTES, readRequestFile } from "./requestfile.js";

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
    });
  });
}

export function fail(message) {
  $("error-text").textContent = message;
  $("error").hidden = false;
  $("main").hidden = true;
}

// showEngine names the engine a portal session reached, with the
// fingerprint of the key the session verified, for the person to compare
// with basalt status (CONTRACT.md, Engine keys: shown on every portal page
// with a session). Nothing for the engine's own local pages.
export function showEngine(session) {
  const engine = session?.engine;
  if (!engine) return;
  const fp = engineFingerprint(engine.engineId);
  $("engine").textContent = engine.address
    ? `Through your engine at ${engine.address}, fingerprint ${fp}, pinned on this device.`
    : `Through the BasaltDB Vault to the engine with fingerprint ${fp}. Before you sign, check that basalt status shows the same fingerprint.`;
  $("engine").hidden = false;
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

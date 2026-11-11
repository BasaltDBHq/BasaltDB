// DOM helpers shared by the approval and registration pages. Text only goes
// into the page through textContent, never innerHTML: every value on these
// pages came from a link someone else built.

export const $ = (id) => document.getElementById(id);

export function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

// linkFailure is the sentence a page shows when its link cannot be used.
// kind names the page ("approval", "revert"); reopen says how to open the
// full link from the terminal. A link that does not decode was most likely
// cut short when copied, so the person is told to reopen it, not that it
// is bad.
export function linkFailure(err, kind, reopen) {
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
export function webauthnError(err) {
  if (err && err.name === "NotAllowedError") return "The passkey prompt was cancelled or timed out. Nothing was signed.";
  if (err && err.name === "SecurityError") return "This browser refused the passkey for this site.";
  return `The passkey could not sign: ${err && err.message ? err.message : err}`;
}

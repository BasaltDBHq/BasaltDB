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

export function fail(message) {
  $("error-text").textContent = message;
  $("error").hidden = false;
  $("main").hidden = true;
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

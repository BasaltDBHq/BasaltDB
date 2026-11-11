// The passkey page `basalt passkey check` and `basalt passkey remove` open
// (CONTRACT.md, Passkey management). CHECK: sign a harmless challenge with
// each passkey, one at a time, and show a code listing which this device
// has. FORGET: ask the password manager to drop a revoked passkey through
// the WebAuthn Signal API, where the browser has it. Sends nothing anywhere.
import { relyingParty } from "./codec.js";
import { MODE_CHECK, checkChallenge, encodeCheckResponse, parseManageRequest, sendForgetSignals } from "./manage.js";
import { $, el, fail, showCode } from "./page.js";

const PROMPT_TIMEOUT_MS = 120000;
const FOUND = "found on this device";
const MISSING = "not found on this device";

async function checkOne(rp, req, cred, results, state, button) {
  button.disabled = true;
  state.textContent = "Waiting for the passkey...";
  try {
    const got = await navigator.credentials.get({
      publicKey: {
        challenge: await checkChallenge(req.challenge),
        rpId: rp.rpId,
        allowCredentials: [{ type: "public-key", id: cred.id }],
        userVerification: "required",
        timeout: PROMPT_TIMEOUT_MS,
      },
    });
    const r = got.response;
    results.set(cred.credentialId, {
      credentialId: new Uint8Array(got.rawId),
      authenticatorData: new Uint8Array(r.authenticatorData),
      clientDataJson: new Uint8Array(r.clientDataJSON),
      signature: new Uint8Array(r.signature),
    });
    state.textContent = FOUND;
  } catch {
    // WebAuthn does not tell "not on this device" from "cancelled".
    results.delete(cred.credentialId);
    state.textContent = `${MISSING} (or the prompt was cancelled)`;
    button.textContent = "Try again";
  }
  button.disabled = false;
}

function showCheck(rp, req) {
  const results = new Map();
  for (const cred of req.credentials) {
    const card = el("li", "row");
    const title = el("div", "row-title");
    title.append(el("span", "table-name", cred.label));
    title.append(el("span", "muted", ` ${cred.credentialId.slice(0, 12)}...`));
    card.append(title);
    const state = el("p", "muted", "not checked yet");
    const button = el("button", "", "Check");
    button.type = "button";
    button.addEventListener("click", () => checkOne(rp, req, cred, results, state, button));
    card.append(state, button);
    $("credentials").append(card);
  }
  $("done").addEventListener("click", () => {
    const found = [...results.values()];
    const missing = req.credentials.filter((c) => !results.has(c.credentialId)).map((c) => c.credentialId);
    showCode(encodeCheckResponse({ challenge: req.challenge, found, missing }));
  });
  $("check").hidden = false;
}

function showForget(rp, req) {
  $("removed-labels").textContent = req.removed.map((r) => r.label).join(", ");
  $("rp-id").textContent = rp.rpId;
  $("signal").addEventListener("click", async () => {
    $("signal").disabled = true;
    const { supported, outcomes } = await sendForgetSignals(window.PublicKeyCredential, rp.rpId, req);
    if (!supported) {
      $("signal-status").textContent =
        "This browser cannot signal removed passkeys. Delete it by hand: in your password manager (macOS Passwords, Google Password Manager, iCloud Keychain, 1Password) search for " +
        rp.rpId + ".";
      return;
    }
    const failed = outcomes.filter((o) => !o.ok);
    $("signal-status").textContent = failed.length === 0
      ? "Sent. Your password manager may now hide or delete it; if it still shows, delete it by hand."
      : `Some signals failed (${failed.map((o) => `${o.call}: ${o.error}`).join("; ")}). Delete it by hand in your password manager.`;
  });
  $("forget").hidden = false;
}

function main() {
  let rp;
  let req;
  try {
    rp = relyingParty(window.location);
    req = parseManageRequest(window.location.hash);
  } catch (err) {
    fail(`This passkey link cannot be used: ${err.message}`);
    return;
  }
  $("main").hidden = false;
  if (req.mode === MODE_CHECK) {
    showCheck(rp, req);
    return;
  }
  showForget(rp, req);
}

main();

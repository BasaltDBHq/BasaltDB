// The passkey registration page: create an ES256 passkey for this relying
// party and show the code to paste back.
import { ALG_ES256, encodeRegistrationResponse, parseRegistrationRequest, relyingParty } from "./codec.js";
import { $, busy, fail, loadOrPaste, showCode, webauthnError } from "./page.js";

const PROMPT_TIMEOUT_MS = 120000;

// prfEnabled reports whether the authenticator enabled prf for the new
// credential. Browsers without the extension return nothing; that is false,
// never an error.
function prfEnabled(cred) {
  try {
    return cred.getClientExtensionResults?.()?.prf?.enabled === true;
  } catch {
    return false;
  }
}

export async function register(rp, req) {
  const done = busy($("register"), "Waiting for your passkey…");
  if (!done) return;
  try {
    const cred = await navigator.credentials.create({
      publicKey: {
        challenge: req.challenge,
        rp: { id: rp.rpId, name: "BasaltDB" },
        user: { id: req.userId, name: req.userName, displayName: req.displayName },
        pubKeyCredParams: [{ type: "public-key", alg: ALG_ES256 }],
        authenticatorSelection: { residentKey: "required", requireResidentKey: true, userVerification: "required" },
        attestation: "none",
        // Ask for prf so a later vault channel phase needs no re-registration.
        // Only whether it is enabled is read; no prf output is used or sent.
        extensions: { prf: {} },
        timeout: PROMPT_TIMEOUT_MS,
      },
    });
    const r = cred.response;
    if (typeof r.getPublicKey !== "function" || typeof r.getAuthenticatorData !== "function") {
      throw new Error("this browser is too old to export the passkey's public key");
    }
    const fields = {
      credentialId: new Uint8Array(cred.rawId),
      clientDataJson: new Uint8Array(r.clientDataJSON),
      authenticatorData: new Uint8Array(r.getAuthenticatorData()),
      publicKey: new Uint8Array(r.getPublicKey()),
      publicKeyAlgorithm: r.getPublicKeyAlgorithm(),
      prfSupported: prfEnabled(cred),
    };
    showCode(encodeRegistrationResponse(fields));
    done();
  } catch (err) {
    done();
    $("status").textContent = webauthnError(err);
  }
}

const describe = (err) => `This registration link cannot be used: ${err.message}`;

async function main() {
  let rp;
  let req;
  try {
    rp = relyingParty(window.location);
    req = await loadOrPaste(parseRegistrationRequest, describe);
  } catch (err) {
    fail(describe(err));
    return;
  }
  $("user-name").textContent = req.userName;
  $("rp-id").textContent = rp.rpId;
  $("main").hidden = false;
  $("register").addEventListener("click", () => register(rp, req));
}

// Only in a browser: the tests load this module without a document.
if (typeof document !== "undefined") main();

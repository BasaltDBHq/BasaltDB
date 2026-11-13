// The passkey registration page `basalt init` opens: create an ES256 passkey
// for this relying party and show the code `basalt init` reads, or, when
// init serves the page itself, post the passkey back to init and show the
// short pairing code the person types into init.
import { ALG_ES256, encodeRegistrationResponse, parseRegistrationRequest, registrationResponseJson, relyingParty } from "./codec.js";
import { postResponse } from "./local.js";
import { $, fail, loadOrPaste, showCode, showDone, showRelayFailed, webauthnError } from "./page.js";
import { pairingCode, pairingCoordinates } from "./pairing.js";

// HAND_BACK_PATH is basalt init's hand-back route, on the pages init serves
// itself: a request with a handBack secret came from there.
export const HAND_BACK_PATH = "/api/v1/passkeys/register";

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

async function register(rp, req) {
  $("register").disabled = true;
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
    if (req.handBack !== "" && (await sendToInit((path, init) => window.fetch(path, init), req, fields))) return;
    showCode(encodeRegistrationResponse(fields));
  } catch (err) {
    $("register").disabled = false;
    $("status").textContent = webauthnError(err);
  }
}

// initEnded is a hand-back that found no basalt init waiting for this
// link: nothing listens on the port any more (init finished or gave up), or
// a newer init run there does not know this link's secret.
function initEnded(err) {
  return err?.status === 0 || err?.status === 404;
}

// sendToInit posts the passkey to basalt init, which keeps it until the
// person types the pairing code this page then shows (CONTRACT.md, CLI).
// The code appears only after init answered that it took the passkey. It
// returns false when the person should paste the long code instead.
export async function sendToInit(fetchFn, req, fields) {
  try {
    await postResponse(fetchFn, HAND_BACK_PATH, req.handBack, registrationResponseJson(fields));
  } catch (err) {
    if (initEnded(err)) {
      showDone("basalt init is no longer waiting; run it again, and register with the link it opens.");
      return true;
    }
    showRelayFailed(`basalt init did not take the passkey (${err.message}). Paste the code below into its prompt instead.`);
    return false;
  }
  const { x, y } = pairingCoordinates(fields.publicKey);
  $("pairing-code").textContent = await pairingCode(req.challenge, fields.credentialId, x, y);
  $("pairing").hidden = false;
  showDone("Passkey created and sent to basalt init. Type or paste this code into basalt init, so it keeps this passkey and no other:");
  return true;
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

// Only in a browser: the tests import this module without a document.
if (typeof document !== "undefined") main();

// The passkey registration page `basalt init` opens: create an ES256 passkey
// for this relying party and show the code `basalt init` reads.
import { ALG_ES256, encodeRegistrationResponse, parseRegistrationRequest, relyingParty } from "./codec.js";
import { $, fail, showCode, webauthnError } from "./page.js";

const PROMPT_TIMEOUT_MS = 120000;

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
        timeout: PROMPT_TIMEOUT_MS,
      },
    });
    const r = cred.response;
    if (typeof r.getPublicKey !== "function" || typeof r.getAuthenticatorData !== "function") {
      throw new Error("this browser is too old to export the passkey's public key");
    }
    showCode(
      encodeRegistrationResponse({
        credentialId: new Uint8Array(cred.rawId),
        clientDataJson: new Uint8Array(r.clientDataJSON),
        authenticatorData: new Uint8Array(r.getAuthenticatorData()),
        publicKey: new Uint8Array(r.getPublicKey()),
        publicKeyAlgorithm: r.getPublicKeyAlgorithm(),
      }),
    );
  } catch (err) {
    $("register").disabled = false;
    $("status").textContent = webauthnError(err);
  }
}

function main() {
  let rp;
  let req;
  try {
    rp = relyingParty(window.location);
    req = parseRegistrationRequest(window.location.hash);
  } catch (err) {
    fail(`This registration link cannot be used: ${err.message}`);
    return;
  }
  $("user-name").textContent = req.userName;
  $("rp-id").textContent = rp.rpId;
  $("main").hidden = false;
  $("register").addEventListener("click", () => register(rp, req));
}

main();

// Codecs and WebAuthn Signal API helpers for the passkey page
// (CONTRACT.md, Passkey management). Pure functions with no DOM access, so
// they run in the browser and under `node --test`. The Go side is
// internal/passkey/manage.go.
//
// A check signs sha256("basalt-passkey-check.1." + challenge): approval and
// revert challenges hash a JSON binding text, never this prefix, so a check
// signature cannot authorize anything.
import { CodeError, b64urlDecode, b64urlEncode, sha256, utf8 } from "./codec.js";

export const MANAGE_REQUEST_PREFIX = "1.";
export const CHECK_RESPONSE_PREFIX = "basalt-passkey-check.1.";
export const CHECK_CHALLENGE_PREFIX = "basalt-passkey-check.1.";
export const MODE_CHECK = "CHECK";
export const MODE_FORGET = "FORGET";

const MAX_FRAGMENT_LENGTH = 64 << 10;
const MAX_PASSKEYS = 100; // the bound of basalt passkey list
const CHALLENGE_BYTES = 32;
const MAX_LABEL_LENGTH = 200; // register_passkey's label limit
const MAX_USER_HANDLE_BYTES = 64; // WebAuthn user.id limit

const decoder = new TextDecoder("utf-8", { fatal: true });

function fail(message) {
  throw new CodeError(message);
}

function requireKeys(obj, what, required, optional = []) {
  if (obj === null || typeof obj !== "object" || Array.isArray(obj)) fail(`${what} must be an object`);
  const allowed = new Set([...required, ...optional]);
  for (const k of Object.keys(obj)) if (!allowed.has(k)) fail(`${what} has an unknown field ${k}`);
  for (const k of required) if (!(k in obj)) fail(`${what} is missing ${k}`);
}

function requireId(text, what) {
  if (typeof text !== "string" || text === "") fail(`${what} must be a base64url string`);
  const bytes = b64urlDecode(text);
  if (bytes.length === 0) fail(`${what} is empty`);
  return bytes;
}

function requireLabel(text, what) {
  if (typeof text !== "string" || text === "" || text.length > MAX_LABEL_LENGTH) fail(`${what} must be 1 to ${MAX_LABEL_LENGTH} characters`);
  return text;
}

function requireList(list, what, min) {
  if (!Array.isArray(list) || list.length < min || list.length > MAX_PASSKEYS) {
    fail(`${what} must list ${min} to ${MAX_PASSKEYS} passkeys`);
  }
  return list;
}

function parseCheck(obj) {
  requireKeys(obj, "check request", ["mode", "challenge", "credentials"]);
  const challenge = b64urlDecode(obj.challenge);
  if (challenge.length !== CHALLENGE_BYTES) fail(`the challenge must be ${CHALLENGE_BYTES} bytes`);
  const credentials = requireList(obj.credentials, "credentials", 1).map((c, i) => {
    requireKeys(c, `credential ${i + 1}`, ["credentialId", "label"]);
    return { credentialId: c.credentialId, id: requireId(c.credentialId, "credentialId"), label: requireLabel(c.label, "label") };
  });
  return { mode: MODE_CHECK, challenge: obj.challenge, credentials };
}

function parseForget(obj) {
  requireKeys(obj, "forget request", ["mode", "removed", "accepted"]);
  const removed = requireList(obj.removed, "removed", 1).map((r, i) => {
    requireKeys(r, `removed passkey ${i + 1}`, ["credentialId", "label"], ["userHandle"]);
    requireId(r.credentialId, "credentialId");
    if (r.userHandle !== undefined) {
      const h = requireId(r.userHandle, "userHandle");
      if (h.length > MAX_USER_HANDLE_BYTES) fail(`userHandle must be at most ${MAX_USER_HANDLE_BYTES} bytes`);
    }
    return { credentialId: r.credentialId, label: requireLabel(r.label, "label"), userHandle: r.userHandle };
  });
  const accepted = requireList(obj.accepted, "accepted", 0);
  accepted.forEach((id) => requireId(id, "accepted credentialId"));
  return { mode: MODE_FORGET, removed, accepted };
}

// parseManageRequest decodes the page's fragment (with or without '#').
export function parseManageRequest(fragment) {
  const text = String(fragment).replace(/^#/, "");
  if (text.length > MAX_FRAGMENT_LENGTH) fail("the link is too long");
  if (!text.startsWith(MANAGE_REQUEST_PREFIX)) fail(`the link must start with #${MANAGE_REQUEST_PREFIX}`);
  let obj;
  try {
    obj = JSON.parse(decoder.decode(b64urlDecode(text.slice(MANAGE_REQUEST_PREFIX.length))));
  } catch (err) {
    if (err instanceof CodeError) throw err;
    fail("the link does not hold a request");
  }
  if (obj && obj.mode === MODE_CHECK) return parseCheck(obj);
  if (obj && obj.mode === MODE_FORGET) return parseForget(obj);
  return fail("unknown mode");
}

// modeForPath is the mode the page's path serves: /passkeys/check or
// /passkeys/forget (CONTRACT.md, Page links). Anything else is refused.
export function modeForPath(pathname) {
  if (pathname === "/passkeys/check") return MODE_CHECK;
  if (pathname === "/passkeys/forget") return MODE_FORGET;
  return fail(`this page only runs at /passkeys/check or /passkeys/forget, not ${pathname}`);
}

// checkChallenge is the WebAuthn challenge a check signs.
export async function checkChallenge(challenge) {
  return sha256(utf8(CHECK_CHALLENGE_PREFIX + challenge));
}

// encodeCheckResponse is the code the person pastes into basalt passkey check.
export function encodeCheckResponse({ challenge, found, missing }) {
  const body = {
    challenge,
    found: found.map((a) => ({
      credentialId: b64urlEncode(a.credentialId),
      authenticatorData: b64urlEncode(a.authenticatorData),
      clientDataJson: b64urlEncode(a.clientDataJson),
      signature: b64urlEncode(a.signature),
    })),
    missing,
  };
  return CHECK_RESPONSE_PREFIX + b64urlEncode(utf8(JSON.stringify(body)));
}

// signalSupport reports which WebAuthn Signal API calls the browser has.
// pkc is window.PublicKeyCredential (undefined in old browsers).
export function signalSupport(pkc) {
  return {
    unknownCredential: typeof pkc?.signalUnknownCredential === "function",
    allAcceptedCredentials: typeof pkc?.signalAllAcceptedCredentials === "function",
  };
}

// sendForgetSignals asks the password manager to forget each removed
// passkey: signalUnknownCredential where supported, and
// signalAllAcceptedCredentials where supported and the user handle is
// known. It never throws; it returns one outcome per call, or none at all
// when the browser has neither (the person deletes the passkey by hand).
export async function sendForgetSignals(pkc, rpId, req) {
  const support = signalSupport(pkc);
  const outcomes = [];
  async function attempt(label, call, args) {
    try {
      await pkc[call](args);
      outcomes.push({ label, call, ok: true });
    } catch (err) {
      outcomes.push({ label, call, ok: false, error: String(err?.message ?? err) });
    }
  }
  for (const r of req.removed) {
    if (support.unknownCredential) {
      await attempt(r.label, "signalUnknownCredential", { rpId, credentialId: r.credentialId });
    }
    if (support.allAcceptedCredentials && r.userHandle) {
      await attempt(r.label, "signalAllAcceptedCredentials", {
        rpId,
        userId: r.userHandle,
        allAcceptedCredentialIds: req.accepted,
      });
    }
  }
  return { supported: support.unknownCredential || support.allAcceptedCredentials, outcomes };
}

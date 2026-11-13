// Rows hidden from the agent (CONTRACT.md, Approvals, Rows hidden from the
// agent; owner decisions HR-1 to HR-4): on a page the engine served, the
// person presses Show values, their passkey signs the reveal challenge, and
// the engine answers with the values of the redacted lines. The page shows
// a row only after it hashes to its line's rowHash; a row with SECRET
// columns cannot be checked and says so. Nothing revealed goes anywhere but
// this page: not into the signature, not into any other request.
import {
  b64urlEncode,
  checkRevealAnswer,
  KIND_APPROVE,
  newRevealSecret,
  revealChallenge,
  revealKey,
} from "./codec.js";
import { postResponse } from "./local.js";

const PROMPT_TIMEOUT_MS = 120000;

// The texts the pages show (CONTRACT.md and the plan's task 6).
export const SHOWN_TO_YOU = "Shown to you only. The agent cannot read this table.";
// notChecked is the callout under a revealed row with SECRET columns: the
// page cannot check it against what the person signs. row names it by key.
export function notChecked(row) {
  return `${row} has a secret column, so this page can't check it against what you sign.`;
}
export const SECRET_VALUE = "secret \u00b7 not shown";
export const OPEN_FROM_ENGINE = "Values are hidden on this link. Open the short link to see them.";
export const REVEAL_REFUSED_TEXT = "Your passkey didn't confirm. Nothing was shown; try again.";
const BAD_ANSWER = "The engine sent values that do not match the rows you sign, so none are shown. Nothing changed; you can still decide without them.";

// hiddenLines counts the request's redacted lines.
export function hiddenLines(req) {
  return req.lines.filter((l) => l.redacted).length;
}

// canReveal: the page offers Show values only when the engine served it
// (relay), gave the nonce the proof signs, and some line is hidden. A long
// link has neither: its page says to open the link from the engine.
export function canReveal(req, relay) {
  return relay !== null && typeof req.revealNonce === "string" && hiddenLines(req) > 0;
}

// revealPath is the item's reveal route on the engine (CONTRACT.md, Local
// pages).
export function revealPath(page, id) {
  return `/api/v1/${page}/${id}/reveal`;
}

// revealBody is the body of POST …/reveal (reveal-request.schema.json).
export function revealBody(assertion, secret) {
  return JSON.stringify({
    proof: {
      credentialId: b64urlEncode(assertion.credentialId),
      authenticatorData: b64urlEncode(assertion.authenticatorData),
      clientDataJson: b64urlEncode(assertion.clientDataJson),
      signature: b64urlEncode(assertion.signature),
    },
    revealSecret: b64urlEncode(secret),
  });
}

// reveal asks the passkey for the reveal proof, posts it with a fresh
// reveal secret, and checks every row of the answer against its line. It
// returns a Map from line index to { checked, values, texts, secretColumns }.
// A row that fails the check fails the whole answer: nothing is shown.
export async function reveal({ kind, id, req, rpId, path, secret, session, getAssertion }) {
  const revealSecret = newRevealSecret();
  const key = await revealKey(revealSecret);
  const id_ = kind === KIND_APPROVE ? req.approvalId : req.revertId;
  if (id_ !== id) throw new Error(`the request is for ${id_}, not ${id}`);
  const challenge = await revealChallenge(kind, id, req.revealNonce, key, req.binding.rowsHash);
  key.fill(0);
  const cred = await getAssertion({
    publicKey: {
      challenge,
      rpId,
      allowCredentials: req.credentialIds.map((c) => ({ type: "public-key", id: c })),
      userVerification: "required",
      timeout: PROMPT_TIMEOUT_MS,
    },
  });
  const r = cred.response;
  const body = revealBody(
    {
      credentialId: new Uint8Array(cred.rawId),
      authenticatorData: new Uint8Array(r.authenticatorData),
      clientDataJson: new Uint8Array(r.clientDataJSON),
      signature: new Uint8Array(r.signature),
    },
    revealSecret,
  );
  revealSecret.fill(0);
  const answer = await postResponse(session, path, secret, body);
  let rows;
  try {
    rows = await checkRevealAnswer(req.lines, answer);
  } catch {
    throw new RevealError(BAD_ANSWER, true);
  }
  return new Map(rows.map((row) => [row.line, row]));
}

// RevealError is a reveal the page cannot show; final when trying again
// cannot help.
export class RevealError extends Error {
  constructor(message, final = false) {
    super(message);
    this.name = "RevealError";
    this.final = final;
  }
}

// revealFailure is what the page says when a reveal fails, and whether the
// button stays off: rows that changed since the agent asked mean the item
// can no longer apply as it is.
export function revealFailure(err, kind) {
  if (err instanceof RevealError) return { text: err.message, final: err.final };
  if (err?.reason === "ROWS_CHANGED") {
    const then = kind === KIND_APPROVE
      ? "This approval can no longer apply; ask the agent to try the write again."
      : "This revert can no longer apply; ask the agent to prepare it again.";
    return { text: `These rows changed since the agent asked. ${then}`, final: true };
  }
  if (err?.reason === "REVEAL_REFUSED") {
    return { text: err.personMessage || REVEAL_REFUSED_TEXT, final: false };
  }
  return null;
}

// revealedLine is line with the revealed values in place of its redaction,
// for the page's row table: key, then old (approval) or now (revert), then
// set; a SECRET column reads "secret · not shown".
export function revealedLine(line, shown, mid) {
  const [key, middle, set] = shown.values;
  const texts = { key: new Map(shown.texts[0]), [mid]: new Map(shown.texts[1]), set: new Map(shown.texts[2]) };
  for (const col of shown.secretColumns) {
    for (const member of ["key", mid, "set"]) {
      if (texts[member].has(col)) texts[member].set(col, SECRET_VALUE);
    }
  }
  return { ...line, redacted: false, key, [mid]: middle, set, texts };
}

// applyReveal keeps the rows a reveal of req returned, unless the page
// moved on to another request meanwhile (a rescope): rows of the old lines
// never land on the new ones. It reports whether it kept them.
export function applyReveal(state, req, shown) {
  if (state.req !== req) return false;
  state.shown = shown;
  state.revealDone = true;
  state.valuesHidden = false;
  return true;
}

// clearReveal forgets what was shown, for a new request.
export function clearReveal(state) {
  state.shown = new Map();
  state.revealDone = false;
  state.valuesHidden = false;
}

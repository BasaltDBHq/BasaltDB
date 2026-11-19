// The connect page (CONTRACT.md, Connect): run a bot's setup code through
// the connect service. The person opens the link their bot sent, checks the
// summary and fingerprint, takes the passkey step, and only then pastes the
// database's admin connection string; the service runs the setup once.
//
// The page calls the service's three ConnectRPC methods with fetch and a
// JSON POST, no generated client. The admin connection string lives only in
// one variable of this module: never in storage, the address, a log or a
// message on the page. The input box is emptied as soon as it is read, and
// the variable after RunSetup, whatever its answer.
import { ALG_ES256, PORTAL, PROD_RP_ID, b64urlDecode, b64urlEncode, hex, sha256, utf8 } from "./codec.js";
import { pairingCoordinates } from "./pairing.js";
import { browserFetch } from "./transport.js";

// CONNECT_SERVICE is the only origin this page connects to; the page's
// policy (its meta CSP and the edge function's header) allows it alone.
export const CONNECT_SERVICE = "https://connect.basaltvault.app";
export const SERVICE_PATH = "/basalt.connect.v1.SetupService/";
// PAGE_HOST is the one host this page runs at and tells the person to see
// in the address bar.
export const PAGE_HOST = "portal.basaltvault.app";

export const LAPTOP_COMMAND = "basalt init --setup-code <the code your bot sent>";
const LAPTOP_LINE = `Or run the setup on your own computer instead, with no hosted service: ${LAPTOP_COMMAND}`;

// A setup code is at most 1500 characters (CONTRACT.md, The setup code).
export const MAX_CODE_CHARS = 1500;
const MAX_PASTE_CHARS = 20000;
// The payload holds no dot, and the check is 6 characters (CONTRACT.md, The
// setup code), so the code ends there even when words follow it once white
// space is dropped.
const CODE_IN_TEXT = /basalt-setup\.1\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]{6}/;
const CALL_TIMEOUT_MS = 75000;
const PROMPT_TIMEOUT_MS = 120000;
// A connection string longer than this is not one; the service caps the
// whole body at 16 KiB.
const MAX_URL_CHARS = 4096;

// Refusal is a refusal of the connect service: reason and message come from
// its basalt.connect.v1.Refusal detail, or are fixed words of this page.
export class Refusal extends Error {
  constructor(reason, message, retryAfterSeconds = 0) {
    super(message);
    this.name = "Refusal";
    this.reason = reason;
    this.retryAfterSeconds = retryAfterSeconds;
  }
}

const UNREACHABLE = "The connect service could not be reached. Check your connection and try again.";

// readCode finds the setup code in a fragment or a pasted message: white
// space is dropped first (a wrapped copy still works), as the laptop command
// does. null when there is none.
export function readCode(text) {
  const s = String(text ?? "");
  if (s.length > MAX_PASTE_CHARS) return null;
  const m = s.replace(/\s+/g, "").match(CODE_IN_TEXT);
  if (!m || m[0].length > MAX_CODE_CHARS) return null;
  return m[0];
}

// refusalFrom reads a ConnectRPC error body: the Refusal detail's proto3
// JSON form (its debug field), else the error's own code and message.
export function refusalFrom(status, body) {
  let parsed = null;
  try {
    parsed = JSON.parse(body);
  } catch {
    parsed = null;
  }
  const detail = Array.isArray(parsed?.details)
    ? parsed.details.find((d) => d?.type === "basalt.connect.v1.Refusal" && d.debug && typeof d.debug === "object")
    : undefined;
  if (detail) {
    const d = detail.debug;
    const reason = typeof d.reason === "string" && /^[A-Z_]{1,64}$/.test(d.reason) ? d.reason : "UNKNOWN";
    const message = typeof d.message === "string" && d.message !== "" ? d.message : `The connect service refused this (${reason}).`;
    const retry = Number.isInteger(d.retryAfterSeconds) && d.retryAfterSeconds > 0 ? d.retryAfterSeconds : 0;
    return new Refusal(reason, message, retry);
  }
  const code = typeof parsed?.code === "string" && /^[a-z_]{1,32}$/.test(parsed.code) ? parsed.code : `HTTP ${status}`;
  return new Refusal("UNKNOWN", `The connect service answered with an error (${code}).`);
}

// call POSTs one ConnectRPC method as JSON. It sends no cookie and no
// referrer, follows no redirect and keeps nothing in the HTTP cache. Its
// errors never carry the request or the browser's own message.
export async function call(fetchFn, method, request) {
  let res;
  try {
    res = await fetchFn(CONNECT_SERVICE + SERVICE_PATH + method, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(request),
      mode: "cors",
      credentials: "omit",
      cache: "no-store",
      redirect: "error",
      referrerPolicy: "no-referrer",
      signal: typeof AbortSignal !== "undefined" && AbortSignal.timeout ? AbortSignal.timeout(CALL_TIMEOUT_MS) : undefined,
    });
  } catch {
    throw new Refusal("UNREACHABLE", UNREACHABLE);
  }
  let text;
  try {
    text = await res.text();
  } catch {
    throw new Refusal("UNREACHABLE", UNREACHABLE);
  }
  if (!res.ok) throw refusalFrom(res.status, text);
  try {
    const out = JSON.parse(text);
    if (out && typeof out === "object" && !Array.isArray(out)) return out;
  } catch {
    // Fall through to the fixed message.
  }
  throw new Refusal("UNKNOWN", "The connect service sent an answer this page cannot read.");
}

// refusalText is what the page shows for a refusal: its message, when to
// try again, and the laptop command as the other way (every reason but a
// limit, which passes).
export function refusalText(err) {
  if (!(err instanceof Refusal)) return "Something went wrong on this page. Nothing was sent.";
  const lines = [err.message];
  if (err.retryAfterSeconds > 0) lines.push(`Try again in ${err.retryAfterSeconds} seconds.`);
  if (err.reason !== "RATE_LIMITED" && err.reason !== "BUSY") lines.push(LAPTOP_LINE);
  return lines.join("\n");
}

const CHECK_DOMAIN = "basalt-passkey-check.1\n";

// passkeyCheckCode is the passkey check code (CONTRACT.md, Connect): the
// first 10 bytes of sha256("basalt-passkey-check.1\n" || x || y), in
// lowercase hex as five groups of four. spki is the public key the browser
// returned, never one the service sent.
export async function passkeyCheckCode(spki) {
  const { x, y } = pairingCoordinates(spki);
  const domain = utf8(CHECK_DOMAIN);
  const all = new Uint8Array(domain.length + 64);
  all.set(domain, 0);
  all.set(x, domain.length);
  all.set(y, domain.length + 32);
  const h = hex((await sha256(all)).slice(0, 10));
  return h.match(/.{4}/g).join(" ");
}

// compareCheckCodes says whether the passkeys the service reports
// registered are the one this page created, with the same code. mine is
// { credentialId, checkCode } or null when this page created none.
export function compareCheckCodes(mine, registered) {
  const list = Array.isArray(registered) ? registered : [];
  if (!mine) return list.length === 0 ? "" : "The service reports a passkey registered that this page did not create. Something is wrong: do not use this database's passkeys until you have checked them with basalt passkey list on your own computer, and remove any you did not create.";
  const others = list.filter((p) => p?.credentialId !== mine.credentialId);
  const same = list.find((p) => p?.credentialId === mine.credentialId);
  if (others.length > 0) return "The service reports a passkey registered that this page did not create. Something is wrong: remove every passkey you did not create (basalt passkey list on your own computer).";
  if (!same) return "The service does not report the passkey this page created. Something is wrong: check the database's passkeys with basalt passkey list on your own computer.";
  if (same.checkCode !== mine.checkCode) return "The service reports a different check code for your passkey than this page computed. Something is wrong: stop, and remove that passkey (basalt passkey list on your own computer).";
  return "";
}

function prfEnabled(cred) {
  try {
    return cred.getClientExtensionResults?.()?.prf?.enabled === true;
  } catch {
    return false;
  }
}

// createPasskey makes the approval passkey with the service's challenge
// (CONTRACT.md, The passkey challenge) and returns the registration to send
// with RunSetup and its check code.
export async function createPasskey(credentials, challenge) {
  const cred = await credentials.create({
    publicKey: {
      challenge: b64urlDecode(challenge.challenge),
      rp: { id: PROD_RP_ID, name: "BasaltDB" },
      user: { id: b64urlDecode(challenge.userId), name: challenge.userName, displayName: challenge.displayName },
      pubKeyCredParams: [{ type: "public-key", alg: ALG_ES256 }],
      authenticatorSelection: { residentKey: "required", requireResidentKey: true, userVerification: "required" },
      attestation: "none",
      extensions: { prf: {} },
      timeout: PROMPT_TIMEOUT_MS,
    },
  });
  const r = cred.response;
  if (typeof r.getPublicKey !== "function" || typeof r.getAuthenticatorData !== "function") {
    throw new Error("this browser is too old to export the passkey's public key");
  }
  const publicKey = new Uint8Array(r.getPublicKey());
  const registration = {
    credentialId: b64urlEncode(new Uint8Array(cred.rawId)),
    clientDataJson: b64urlEncode(new Uint8Array(r.clientDataJSON)),
    authenticatorData: b64urlEncode(new Uint8Array(r.getAuthenticatorData())),
    publicKey: b64urlEncode(publicKey),
    publicKeyAlgorithm: r.getPublicKeyAlgorithm(),
    prfSupported: prfEnabled(cred),
  };
  return { registration, checkCode: await passkeyCheckCode(publicKey) };
}

// signOnce asks for the person's existing passkey of this site with a
// challenge of the page's own. Nothing of the answer is kept or sent: it is
// the habit that lets a returning person notice a site that cannot offer
// their passkey (CONTRACT.md, The connect page, step 3).
export async function signOnce(credentials) {
  const challenge = new Uint8Array(32);
  crypto.getRandomValues(challenge);
  await credentials.get({ publicKey: { challenge, rpId: PROD_RP_ID, userVerification: "required", timeout: PROMPT_TIMEOUT_MS } });
}

function passkeyError(err) {
  if (err?.name === "NotAllowedError") return "The passkey prompt was cancelled or timed out, or this device has no passkey for this site.";
  if (err?.name === "SecurityError") return "This browser refused the passkey for this site.";
  if (err?.name === "InvalidStateError") return "This device already has a passkey for this setup.";
  return "The passkey step did not finish on this browser.";
}

const KIND_WORDS = { INSTALL: "Set up a new agent", AGENT: "Change an existing agent", UPGRADE: "Upgrade Basalt's guard" };
const CHOICE_WORDS = { ALL_ROWS: "Yes, all rows", NONE: "No" };

// Flow is the page's state, in its fixed order. Every step checks the one
// before it ran; the admin connection string is the private #databaseUrl.
export class Flow {
  #databaseUrl = "";

  constructor({ fetch: fetchFn, credentials }) {
    this.fetch = fetchFn;
    this.credentials = credentials;
    this.step = "code";
    this.code = "";
    this.summary = null;
    this.challenge = null;
    this.passkey = null; // { registration, checkCode } once created
    this.check = null;
  }

  async describe(code) {
    if (this.step !== "code") throw new Error("the code is already read");
    const out = await call(this.fetch, "DescribeSetup", { code });
    const summary = out.summary;
    const challenge = out.challenge;
    if (!summary || typeof summary !== "object" || !challenge || typeof challenge !== "object" || !KIND_WORDS[summary.kind]) {
      throw new Refusal("UNKNOWN", "The connect service sent an answer this page cannot read.");
    }
    this.code = code;
    this.summary = summary;
    this.challenge = challenge;
    this.step = "passkey";
    return summary;
  }

  // needsNewPasskey: an INSTALL creates the approval passkey at step 3; a
  // later code signs with the existing one.
  get needsNewPasskey() {
    return this.summary?.kind === "INSTALL";
  }

  async createPasskey() {
    if (this.step !== "passkey" && this.step !== "questions") throw new Error("not at the passkey step");
    this.passkey = await createPasskey(this.credentials, this.challenge);
    if (this.step === "passkey") this.step = "paste";
  }

  async signExisting() {
    if (this.step !== "passkey") throw new Error("not at the passkey step");
    await signOnce(this.credentials);
    this.step = "paste";
  }

  // skipSign lets a person whose passkey is on no device at hand go on; the
  // page has warned them first.
  skipSign() {
    if (this.step !== "passkey" || this.needsNewPasskey) throw new Error("not at the passkey step");
    this.step = "paste";
  }

  // checkSetup takes the connection string the person pasted. On a refusal
  // the string is dropped: the person pastes it again.
  async checkSetup(databaseUrl) {
    if (this.step !== "paste") throw new Error("not at the paste step");
    const url = String(databaseUrl ?? "").trim();
    if (url === "") throw new Refusal("CONNECTION_STRING_REFUSED", "Paste the database's admin connection string first.");
    if (url.length > MAX_URL_CHARS) throw new Refusal("CONNECTION_STRING_REFUSED", "That is too long to be a connection string.");
    this.#databaseUrl = url;
    try {
      const out = await call(this.fetch, "CheckSetup", { code: this.code, databaseUrl: this.#databaseUrl });
      this.check = {
        questions: Array.isArray(out.questions) ? out.questions : [],
        passkeyNeeded: out.passkeyNeeded === true,
        notes: Array.isArray(out.notes) ? out.notes : [],
        nothingToDo: out.nothingToDo === true,
      };
    } catch (err) {
      this.#databaseUrl = "";
      throw err;
    }
    this.step = "questions";
    return this.check;
  }

  get passkeyMissing() {
    return this.check?.passkeyNeeded === true && !this.passkey;
  }

  // runSetup sends the answers. The connection string is cleared whatever
  // the answer; after a refusal the person pastes it again.
  async runSetup(answers) {
    if (this.step !== "questions") throw new Error("not at the approve step");
    if (this.passkeyMissing) throw new Refusal("PASSKEY_REQUIRED", "Create the passkey first.");
    const req = { code: this.code, databaseUrl: this.#databaseUrl, answers };
    if (this.passkey) {
      req.challenge = this.challenge;
      req.passkey = { ...this.passkey.registration };
    }
    try {
      const out = await call(this.fetch, "RunSetup", req);
      this.step = "done";
      return {
        warnings: Array.isArray(out.warnings) ? out.warnings : [],
        passkeys: Array.isArray(out.passkeys) ? out.passkeys : [],
        nothingToDo: out.nothingToDo === true,
      };
    } catch (err) {
      this.step = "paste";
      this.check = null;
      throw err;
    } finally {
      this.#databaseUrl = "";
    }
  }

  // holdsConnectionString is for the tests: whether the variable is set.
  get holdsConnectionString() {
    return this.#databaseUrl !== "";
  }
}

// ---- The page ----

const $ = (id) => document.getElementById(id);

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

function clear(node) {
  while (node.firstChild) node.removeChild(node.firstChild);
}

function setText(id, text) {
  $(id).textContent = text;
}

function show(id, on = true) {
  $(id).hidden = !on;
}

function fail(message) {
  setText("error-text", message);
  show("error");
}

function targetText(t) {
  if (!t || typeof t !== "object") return "";
  const where = t.supabaseRef ? `Supabase project ${t.supabaseRef}` : `${t.host}:${t.port}`;
  return `database ${t.database} of ${where}`;
}

function showSummary(s) {
  setText("kind", KIND_WORDS[s.kind]);
  setText("fingerprint", String(s.fingerprint ?? ""));
  const facts = $("facts");
  clear(facts);
  const fact = (label, value) => {
    if (!value) return;
    const row = el("li");
    row.appendChild(el("strong", "", label + ": "));
    row.appendChild(el("span", "", value));
    facts.appendChild(row);
  };
  fact("Agent", s.agent ? `${s.agent} (role ${s.role})` : "");
  fact("Database", targetText(s.target));
  fact("Changes rows in", Array.isArray(s.write) ? s.write.join(", ") : "");
  fact("Reads", Array.isArray(s.read) ? s.read.join(", ") : "");
  fact("Engine fingerprint", s.engineFingerprint ?? "");
  fact("Code expires", s.expiresAt ?? "");
  const lines = $("summary-lines");
  clear(lines);
  for (const line of Array.isArray(s.lines) ? s.lines : []) lines.appendChild(el("li", "", String(line)));
  show("summary");
}

function showPasskeyStep(flow) {
  if (flow.needsNewPasskey) {
    setText("passkey-lead", "Create the passkey that approves this agent's larger changes and reverts. It is made for basaltvault.app and stays on your device or password manager.");
    setText("passkey-go", "Create passkey");
  } else {
    setText("passkey-lead", "Sign once with the passkey you already use for this database. Only the real site can ask for it: if your device offers none, check the address bar before you go on. Nothing of this signature is sent.");
    setText("passkey-go", "Sign with your passkey");
  }
  show("passkey");
}

function questionNode(q, i) {
  const box = el("fieldset", "question");
  box.appendChild(el("legend", "", String(q.text ?? q.table ?? "")));
  for (const choice of Array.isArray(q.choices) ? q.choices : []) {
    const label = el("label", "choice");
    const input = el("input");
    input.type = "radio";
    input.name = `q${i}`;
    input.value = String(choice);
    input.dataset.question = String(i);
    label.appendChild(input);
    label.appendChild(el("span", "", CHOICE_WORDS[choice] ?? String(choice)));
    box.appendChild(label);
  }
  return box;
}

// answersFrom reads the chosen answer to each question; null when one is
// left without an answer.
export function answersFrom(questions, root) {
  const out = [];
  for (let i = 0; i < questions.length; i++) {
    const picked = root.querySelector(`input[name="q${i}"]:checked`);
    if (!picked) return null;
    out.push({ kind: questions[i].kind, table: questions[i].table, choice: picked.value });
  }
  return out;
}

function showQuestions(flow) {
  const c = flow.check;
  const notes = $("notes");
  clear(notes);
  for (const n of c.notes) notes.appendChild(el("li", "", String(n)));
  const qs = $("questions");
  clear(qs);
  c.questions.forEach((q, i) => qs.appendChild(questionNode(q, i)));
  show("passkey-now", flow.passkeyMissing);
  $("approve").disabled = flow.passkeyMissing;
  setText("approve-status", "");
  show("review");
}

async function showResult(flow, result) {
  show("review", false);
  setText("result-text", result.nothingToDo ? "Nothing to do: the guard is already at that version. Nothing changed." : "Done. The setup ran on your database.");
  const warnings = $("warnings");
  clear(warnings);
  for (const w of result.warnings) warnings.appendChild(el("li", "", String(w)));
  show("warnings", result.warnings.length > 0);
  const mine = flow.passkey ? { credentialId: flow.passkey.registration.credentialId, checkCode: flow.passkey.checkCode } : null;
  if (mine) {
    setText("check-code", mine.checkCode);
    show("check-code-box");
  }
  const problem = compareCheckCodes(mine, result.passkeys);
  setText("check-problem", problem);
  show("check-problem", problem !== "");
  show("result");
  show("done");
}

// start runs the page. env carries the browser's location, fetch and
// credentials, so the tests can run it against a fake service.
export function start(env) {
  const { location } = env;
  if (location.origin !== PORTAL) {
    fail(`This page only runs at ${PORTAL}. Close it: the address bar shows another site.`);
    return null;
  }
  const flow = new Flow(env);
  setText("host", PAGE_HOST);
  show("main");

  const describe = async (code) => {
    setText("code-status", "Reading the setup code…");
    try {
      showSummary(await flow.describe(code));
      show("code-box", false);
      setText("code-status", "");
      showPasskeyStep(flow);
    } catch (err) {
      show("code-box");
      setText("code-status", refusalText(err));
    }
  };

  $("code-read").addEventListener("click", () => {
    const code = readCode($("code-paste").value);
    if (!code) {
      setText("code-status", "No setup code found in that text. Paste the code your bot sent; it starts with basalt-setup.1.");
      return;
    }
    $("code-paste").value = "";
    return describe(code);
  });

  $("passkey-go").addEventListener("click", async () => {
    $("passkey-go").disabled = true;
    setText("passkey-status", "");
    try {
      if (flow.needsNewPasskey) await flow.createPasskey();
      else await flow.signExisting();
      show("passkey-skip", false);
      setText("passkey-status", flow.passkey ? "Passkey created." : "Signed.");
      show("paste");
    } catch (err) {
      $("passkey-go").disabled = false;
      setText("passkey-status", passkeyError(err));
      // Only a later code can go on without signing; an INSTALL needs the
      // new passkey.
      if (!flow.needsNewPasskey) show("passkey-skip");
    }
  });

  $("passkey-skip").addEventListener("click", () => {
    flow.skipSign();
    $("passkey-go").disabled = true;
    show("passkey-skip", false);
    setText("passkey-status", "Went on without signing. If you have a passkey for this database and this page never offered it, stop: this may not be the real site.");
    show("paste");
  });

  $("check").addEventListener("click", async () => {
    const input = $("database-url");
    const typed = input.value;
    input.value = "";
    $("check").disabled = true;
    setText("check-status", "Checking your database…");
    try {
      await flow.checkSetup(typed);
      setText("check-status", "");
      show("paste", false);
      showQuestions(flow);
    } catch (err) {
      setText("check-status", refusalText(err));
    } finally {
      $("check").disabled = false;
    }
  });

  $("passkey-now").addEventListener("click", async () => {
    $("passkey-now").disabled = true;
    try {
      await flow.createPasskey();
      show("passkey-now", false);
      $("approve").disabled = false;
      setText("approve-status", "Passkey created.");
    } catch (err) {
      setText("approve-status", passkeyError(err));
    } finally {
      $("passkey-now").disabled = false;
    }
  });

  $("approve").addEventListener("click", async () => {
    const answers = answersFrom(flow.check.questions, $("questions"));
    if (!answers) {
      setText("approve-status", "Answer every question first.");
      return;
    }
    $("approve").disabled = true;
    setText("approve-status", "Running the setup…");
    let result;
    try {
      result = await flow.runSetup(answers);
    } catch (err) {
      show("review", false);
      // A challenge past its 15 minutes, one for another code, or a passkey
      // the service refused needs a fresh start (a new challenge and a new
      // passkey); sending the same registration again would be refused
      // again.
      if (err instanceof Refusal && (err.reason.startsWith("CHALLENGE_") || err.reason === "PASSKEY_INVALID")) {
        fail(refusalText(err) + "\nOpen the link from your bot again to start over.");
        return;
      }
      // No answer arrived: the setup may have run. Pasting again would be
      // refused USED, so show the page's own check code and send the
      // person to the bot.
      if (err instanceof Refusal && (err.reason === "UNREACHABLE" || err.reason === "UNKNOWN")) {
        fail(`${err.message}\nThis page cannot tell whether the setup ran. Tell your bot "done" so it checks; if it says the setup is still pending, open the link from your bot again.`);
        if (flow.passkey) {
          setText("check-code", flow.passkey.checkCode);
          show("check-code-box");
          setText("result-text", "If the setup ran, this is your passkey's check code.");
          show("result");
        }
        return;
      }
      setText("check-status", refusalText(err) + "\nPaste the connection string again to retry.");
      show("paste");
      return;
    } finally {
      $("approve").disabled = false;
    }
    // The setup ran: show it, outside the try, so a display error is never
    // reported as a refusal.
    await showResult(flow, result);
  });

  const code = readCode(location.hash.replace(/^#/, ""));
  if (code) return { flow, ready: describe(code) };
  show("code-box");
  return { flow, ready: Promise.resolve() };
}

// Only in a browser: the tests load this module without a document.
if (typeof document !== "undefined" && typeof window !== "undefined" && window.location) {
  start({ location: window.location, fetch: browserFetch, credentials: navigator.credentials });
}

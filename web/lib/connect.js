// The connect page (CONTRACT.md, Connect): run a bot's setup code through
// the connect service, one step per screen. The person opens the link their
// bot sent, checks that the code is the one in their chat, takes the passkey
// step, and only then pastes the database's admin connection string. For a
// code that names no database, the bot's engine tests that it can reach the
// pasted one before anything else is shown. The person then sees the
// database and its tables, may untick tables and label personal data, and
// approves; the service runs the setup once.
//
// The page calls the service's ConnectRPC methods with fetch and a JSON
// POST, no generated client. The admin connection string lives only in one
// private field of Flow: never in storage, the address, a log or a message
// on the page. The input box is emptied as soon as it is read, the field
// after RunSetup whatever its answer, and on every way back to the paste
// step. The hand-off ticket is kept the same way and never shown.
import { ALG_ES256, PORTAL, PROD_RP_ID, b64urlDecode, b64urlEncode, hex, sha256, utf8 } from "./codec.js";
import { busy } from "./page.js";
import { labelRow as sharedLabelRow } from "./pickviews.js";
import { browserFetch } from "./transport.js";
import { startTabs } from "./remove.js";
import { ENTITY_WORDS, Labels, MAX_LABELS, answersFor, fingerprintText, hostOf, labelOf, restNote, tableName, trustRootFrom, trustText } from "./picks.js";
import { ADD_AGAIN, activePasskeys, checkView, passkeyLabel, passkeyLine, revokeLines, signalRemoved, unlabeledColumns } from "./connectupdate.js";
import { confirmView, factsDiffer, paintConfirm, stringFacts } from "./confirm.js";

// The pieces the local setup page shares with this one.
export { ENTITY_WORDS, Labels, MAX_LABELS, answersFor, fingerprintText, hostOf, labelOf, restNote, tableName, trustRootFrom, trustText };

// CONNECT_SERVICE is the only origin this page connects to; the page's
// policy (its meta CSP and the edge function's header) allows it alone.
export const CONNECT_SERVICE = "https://connect.basaltvault.app";
export const SERVICE_PATH = "/basalt.connect.v1.SetupService/";
// PAGE_HOST is the one host this page runs at and tells the person to see
// in the address bar.
export const PAGE_HOST = "portal.basaltvault.app";
// WAITLIST is where the final screen's optional line points: a plain link,
// opened in a new tab. The page sends nothing there itself.
export const WAITLIST = "https://basaltvault.app/#waitlist";

const TRY_AGAIN_LINE = "Try again later, or ask your bot for a new link.";

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
const POSTGRES_URL = /^postgres(?:ql)?:\/\//i;
export const NOT_POSTGRES = "Basalt works with Postgres databases; paste a connection string that starts with postgresql://";

// The polls (CONTRACT.md, The reach check and The address hand-off): every
// 5 seconds; the reach check for up to a minute; the pick-up is late after
// 2 minutes, and the page stops asking when the hold's 30 minutes are up.
export const POLL_MS = 5000;
export const REACH_WAIT_MS = 60000;
export const LATE_MS = 120000;
export const WATCH_MS = 30 * 60000;

// Refusal is a refusal of the connect service: reason and message come from
// its basalt.connect.v1.Refusal detail, or are fixed words of this page.
// trustRoot is the certificate authority the database presents, for the
// person to trust (CONTRACT.md, Trusting a certificate authority on the
// page), or null.
export class Refusal extends Error {
  constructor(reason, message, retryAfterSeconds = 0, trustRoot = null) {
    super(message);
    this.name = "Refusal";
    this.reason = reason;
    this.retryAfterSeconds = retryAfterSeconds;
    this.trustRoot = trustRoot;
  }
}

const UNREACHABLE = "The connect service could not be reached. Check your connection and try again.";
const UNREADABLE = "The connect service sent an answer this page cannot read.";

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
    return new Refusal(reason, message, retry, trustRootFrom(reason, d.trustRoot));
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
  throw new Refusal("UNKNOWN", UNREADABLE);
}

// refusalText is what the page shows for a refusal: its message, when to
// try again, and what to do next (every reason but a limit, which passes):
// try again later or ask the bot for a new link.
export function refusalText(err) {
  if (!(err instanceof Refusal)) return "Something went wrong on this page. Nothing was sent.";
  const lines = [err.message];
  if (err.retryAfterSeconds > 0) lines.push(`Try again in ${err.retryAfterSeconds} seconds.`);
  if (err.reason !== "RATE_LIMITED" && err.reason !== "BUSY") lines.push(TRY_AGAIN_LINE);
  return lines.join("\n");
}

const CHECK_DOMAIN = "basalt-passkey-check.1\n";

// publicKeyCoordinates is the P-256 point's x and y: the last 64 bytes of
// the SubjectPublicKeyInfo, after the 0x04 of an uncompressed point.
function publicKeyCoordinates(spki) {
  if (spki.length < 65 || spki[spki.length - 65] !== 0x04) throw new Error("the passkey's public key is not an uncompressed P-256 point");
  return { x: spki.slice(spki.length - 64, spki.length - 32), y: spki.slice(spki.length - 32) };
}

// passkeyCheckCode is the passkey check code (CONTRACT.md, Connect): the
// first 10 bytes of sha256("basalt-passkey-check.1\n" || x || y), in
// lowercase hex as five groups of four. spki is the public key the browser
// returned, never one the service sent.
export async function passkeyCheckCode(spki) {
  const { x, y } = publicKeyCoordinates(spki);
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
  if (!mine) return list.length === 0 ? "" : "The service reports a passkey registered that this page did not create. Something is wrong: do not use this database's passkeys until you have checked them. Once your bot is set up, ask it for BasaltDB's status: the engine lists each passkey of the database with its check code, read from the database. Remove any passkey you did not create on the connect page (have your agent run basalt init --remote again).";
  const others = list.filter((p) => p?.credentialId !== mine.credentialId);
  const same = list.find((p) => p?.credentialId === mine.credentialId);
  if (others.length > 0) return `The service reports a passkey registered that this page did not create. Something is wrong: stop. Once your bot is set up, ask it for BasaltDB's status: the engine lists each passkey of the database with its check code, read from the database. Remove every passkey whose code is not ${mine.checkCode} on the connect page (have your agent run basalt init --remote again).`;
  if (!same) return `The service does not report the passkey this page created. Something is wrong: stop. Once your bot is set up, ask it for BasaltDB's status: the engine lists each passkey of the database with its check code, read from the database. Your passkey's code is ${mine.checkCode}; remove any passkey you did not create on the connect page (have your agent run basalt init --remote again).`;
  if (same.checkCode !== mine.checkCode) return `The service reports a different check code for your passkey than this page computed. Something is wrong: stop. Once your bot is set up, ask it for BasaltDB's status: the engine lists each passkey of the database with its check code, read from the database. Remove any passkey whose code is not ${mine.checkCode} on the connect page (have your agent run basalt init --remote again).`;
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

const KINDS = new Set(["INSTALL", "AGENT", "UPGRADE"]);
const WANTS = {
  INSTALL: "wants access to your database",
  AGENT: "wants to change its access to your database",
  UPGRADE: "wants to upgrade Basalt in your database",
};

// ---- What the screens show, from the service's answers ----

const strings = (v) => (Array.isArray(v) ? v.filter((s) => typeof s === "string") : []);

// botName is the agent's name as the code carries it, else "Your bot".
export function botName(summary) {
  return typeof summary?.agent === "string" && summary.agent !== "" ? summary.agent : "Your bot";
}

// expiryCountdown is the page's expiry line from the code's expiresAt:
// "expires in 7 min", in whole minutes, or expired once now is at or past it.
export function expiryCountdown(expiresAt, nowMs) {
  if (typeof expiresAt !== "string") return { expired: true, text: "" };
  const end = Date.parse(expiresAt);
  if (Number.isNaN(end)) return { expired: true, text: "" };
  const left = end - nowMs;
  if (left <= 0) return { expired: true, text: "" };
  const min = Math.max(1, Math.ceil(left / 60_000));
  return { expired: false, text: `expires in ${min} min` };
}

const OPEN_LINK = {
  EXPIRED: (bot) => `This link expired. Ask ${bot} for a new one.`,
  ALREADY_USED: (bot) => `This link was already used. Ask ${bot} for a new one.`,
  REPLACED: (bot) => `This link was replaced by a newer link. Ask ${bot} for a new one.`,
};

// openLinkMessage is the page with no setup steps for a link the service
// refused on open, or when the countdown reaches zero.
export function openLinkMessage(err, bot = "your bot") {
  if (!(err instanceof Refusal) || !OPEN_LINK[err.reason]) return null;
  if (typeof err.message === "string" && err.message.includes("Ask ")) return err.message;
  return OPEN_LINK[err.reason](bot);
}

// isConnectOnly: a code that names no database; only this page runs it.
export function isConnectOnly(summary) {
  return !summary?.target;
}

// databaseView is how a database is named: large (the Supabase project ref,
// else the host), the line under it, and the one-line form of the contract
// (`Supabase project <ref>, database <db>` or `<host>:<port>, database <db>`).
export function databaseView(t) {
  if (!t || typeof t !== "object") return null;
  const db = String(t.database ?? "");
  if (t.supabaseRef) {
    const ref = String(t.supabaseRef);
    return { big: ref, sub: `Supabase project · database ${db}`, line: `Supabase project ${ref}, database ${db}` };
  }
  const host = String(t.host ?? "");
  const port = Number.isInteger(t.port) && t.port > 0 ? t.port : 5432;
  return { big: host, sub: `Port ${port} · database ${db}`, line: `${host}:${port}, database ${db}` };
}

// tableRows is screen 4's list: the tables the agent will get, each with
// what it may do, and whether the person may untick them. Ticks come only
// from CheckSetup's ticked (CONTRACT.md, Tables on the connect page): an
// allTables INSTALL code, and an AGENT code that runs as an INSTALL (a
// dropped role, or a kept role holding no table), whose code may name no
// tables at all; the rows are then CheckSetup's listing. A re-run and an
// upgrade with nothing to do show none. A service that sends no ticked
// (one older than the field; proto3 JSON also leaves out a false) gets the
// old rule: ticks for an allTables INSTALL code, which ticked always covers.
export function tableRows(summary, check) {
  const allTables = strings(summary?.allTablesSchemas).length > 0;
  const ticked = typeof check?.ticked === "boolean" ? check.ticked : summary?.kind === "INSTALL" && allTables;
  let rows;
  if (ticked || allTables) {
    const readOnly = new Set(strings(check?.readOnly));
    rows = strings(check?.tables).map((name) => ({ name, access: readOnly.has(name) ? "noKey" : "write" }));
  } else {
    rows = [...strings(summary?.write).map((name) => ({ name, access: "write" })), ...strings(summary?.read).map((name) => ({ name, access: "read" }))];
  }
  const ticks = ticked && !check?.alreadyRan && !check?.nothingToDo;
  const excluded = (Array.isArray(check?.excluded) ? check.excluded : []).filter((e) => typeof e?.table === "string");
  return { rows, ticks, excluded };
}

// reachText is screen 3c's advice for the reason the engine reported.
export function reachText(reason, bot) {
  switch (reason) {
    case "TLS_NOT_VERIFIED":
      return `The database's certificate could not be verified from ${bot}'s server for this host. Check that the string is your database's own address, or use a host whose certificate a public authority signed.`;
    case "ADDRESS_REFUSED":
      return `This address is private: ${bot}'s server will not connect to it.`;
    case "TRUST_ROOT_MISMATCH":
      return `${bot}'s server sees a different certificate authority for this database than the one you trusted, so it trusts neither. Check the certificate against your provider's console. If it changes again, something between ${bot}'s server and your database may be in the way.`;
    default:
      return "Supabase: use the Session pooler string instead of the direct one.";
  }
}

// disclosure is what the paste step says goes where (CONTRACT.md, The
// connect page).
export function disclosure(summary) {
  if (!isConnectOnly(summary)) {
    return "Your database password goes to Basalt Vault's connect service for this one setup and is never stored.";
  }
  if (summary.kind === "INSTALL") {
    return "Your database password goes to Basalt Vault's connect service for this one setup and is never stored. The database's address (not the password) is kept in the service's memory for up to 30 minutes: while your bot tests that its server can reach it, without signing in, and after you approve, until your bot picks it up. Until then your bot asks the service for it regularly, for up to 24 hours.";
  }
  return "Your database password goes to Basalt Vault's connect service for this one setup and is never stored. The database's address (not the password) is kept in the service's memory for up to 30 minutes, until your bot picks it up.";
}

const defaultSleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

// Flow is the page's state, in its fixed order. Every step checks the one
// before it ran; the admin connection string and the hand-off ticket are
// private fields.
export class Flow {
  #databaseUrl = "";
  #ticket = "";
  // #trustRoot is the SHA-256 the person trusted, sent with CheckSetup and
  // RunSetup; "" when they trusted none.
  #trustRoot = "";

  constructor({ fetch: fetchFn, credentials, sleep = defaultSleep, now = () => Date.now() }) {
    this.fetch = fetchFn;
    this.credentials = credentials;
    this.sleep = sleep;
    this.now = now;
    this.step = "code";
    this.code = "";
    this.summary = null;
    this.challenge = null;
    this.passkey = null; // { registration, checkCode } once created
    this.signed = false;
    this.check = null;
    // asking is the certificate authority the trust step asks about.
    this.asking = null;
  }

  async describe(code) {
    if (this.step !== "code") throw new Error("the code is already read");
    const out = await call(this.fetch, "DescribeSetup", { code });
    const summary = out.summary;
    const challenge = out.challenge;
    if (!summary || typeof summary !== "object" || !challenge || typeof challenge !== "object" || !KINDS.has(summary.kind)) {
      throw new Refusal("UNKNOWN", UNREADABLE);
    }
    this.code = code;
    this.summary = summary;
    this.challenge = challenge;
    this.step = "bot";
    return summary;
  }

  // confirmBot is "Yes, same code": the passkey step comes next.
  confirmBot() {
    if (this.step !== "bot") throw new Error("not at the code check");
    this.step = "passkey";
  }

  // backTo is Back to the code check or the passkey step, from the passkey
  // or paste step. A passkey made or signed stays done.
  backTo(step) {
    if ((step !== "bot" && step !== "passkey") || (this.step !== "passkey" && this.step !== "paste")) throw new Error("cannot go back there");
    this.step = step;
  }

  // passkeyContinue goes on from the passkey step once it was done.
  passkeyContinue() {
    if (this.step !== "passkey" || !this.passkeyDone) throw new Error("not at the passkey step");
    this.step = "paste";
  }

  // stop is "No, it's different": nothing more happens on this page.
  stop() {
    this.step = "stopped";
  }

  get connectOnly() {
    return isConnectOnly(this.summary);
  }

  // updateCheck: a code with a target that changes an agent or upgrades
  // the guard gets the Update check after the paste (CONTRACT.md, Update on
  // the connect page).
  get updateCheck() {
    return !this.connectOnly && (this.summary?.kind === "AGENT" || this.summary?.kind === "UPGRADE");
  }

  // confirm is the confirm step, "Is this your database?" (CONTRACT.md,
  // The connect page): at the trust step, what the pasted string names and
  // the certificate authority to trust, with the bot's pin when the code
  // carries one; after CheckSetup, what the service found when it signed in.
  confirm() {
    const bot = botName(this.summary);
    if (this.step === "trust" && this.asking) {
      return confirmView({ facts: stringFacts(this.#databaseUrl), asking: this.asking, trustPin: this.summary?.trustPin ?? "", bot });
    }
    const t = this.check?.database ?? {};
    const facts = { database: this.check?.currentDatabase || t.database, host: t.host, port: t.port, user: this.check?.sessionUser ?? "" };
    return confirmView({ facts, certificate: this.check?.certificate ?? null, bot });
  }

  // needsNewPasskey: an INSTALL creates the approval passkey at the passkey
  // step, unless the person already has one for this database.
  get needsNewPasskey() {
    return this.summary?.kind === "INSTALL";
  }

  get passkeyDone() {
    return this.passkey !== null || this.signed;
  }

  async createPasskey() {
    if (this.step !== "passkey" && this.step !== "questions") throw new Error("not at the passkey step");
    this.passkey = await createPasskey(this.credentials, this.challenge);
    if (this.step === "passkey") this.step = "paste";
  }

  // signExisting is the passkey the person already has: for a later code,
  // and for an INSTALL on a database that has one ("Use it").
  async signExisting() {
    if (this.step !== "passkey") throw new Error("not at the passkey step");
    await signOnce(this.credentials);
    this.signed = true;
    this.step = "paste";
  }

  // skipSign lets a person whose passkey is on no device at hand go on with
  // a later code; the page has warned them first.
  skipSign() {
    if (this.step !== "passkey" || this.needsNewPasskey) throw new Error("not at the passkey step");
    this.step = "paste";
  }

  // checkSetup takes the connection string the person pasted. On a refusal
  // the string is dropped: the person pastes it again.
  async checkSetup(databaseUrl) {
    if (this.step !== "paste") throw new Error("not at the paste step");
    const url = String(databaseUrl ?? "").trim();
    if (url === "") throw new Refusal("CONNECTION_STRING_REFUSED", "Paste your database's connection string first.");
    if (url.length > MAX_URL_CHARS) throw new Refusal("CONNECTION_STRING_REFUSED", "That is too long to be a connection string.");
    if (!POSTGRES_URL.test(url)) throw new Refusal("NOT_POSTGRES", NOT_POSTGRES);
    this.#databaseUrl = url;
    this.#trustRoot = "";
    return this.#checkOrAsk();
  }

  // #checkOrAsk is CheckSetup. A refusal that carries a certificate
  // authority to trust keeps the string and goes to the trust step, where
  // nothing is sent until the person answers; any other drops it.
  async #checkOrAsk() {
    try {
      await this.#check();
    } catch (err) {
      this.#ticket = "";
      if (err instanceof Refusal && err.trustRoot) {
        this.asking = err.trustRoot;
        this.step = "trust";
      } else {
        this.#databaseUrl = "";
        this.#trustRoot = "";
        this.step = "paste";
      }
      throw err;
    }
    this.step = "questions";
    return this.check;
  }

  // trust is Yes on the confirm step, the person's click: CheckSetup again
  // with the certificate authority they were shown. Only this sends a
  // trustRoot.
  async trust() {
    if (this.step !== "trust" || !this.asking) throw new Error("not at the trust step");
    this.#trustRoot = this.asking.sha256;
    this.asking = null;
    return this.#checkOrAsk();
  }

  // cancelTrust is "No, go back": the string is dropped, back to the paste
  // step.
  cancelTrust() {
    if (this.step !== "trust") throw new Error("not at the trust step");
    this.#databaseUrl = "";
    this.#trustRoot = "";
    this.asking = null;
    this.step = "paste";
  }

  // check is one CheckSetup; an answer that arrives after loop was
  // cancelled (the person went back) changes nothing.
  async #check(loop = null) {
    const req = { code: this.code, databaseUrl: this.#databaseUrl };
    if (this.#trustRoot !== "") req.trustRoot = this.#trustRoot;
    const out = await call(this.fetch, "CheckSetup", req);
    if (loop?.cancelled) return;
    this.check = {
      questions: Array.isArray(out.questions) ? out.questions : [],
      passkeyNeeded: out.passkeyNeeded === true,
      notes: strings(out.notes),
      nothingToDo: out.nothingToDo === true,
      database: out.database && typeof out.database === "object" ? out.database : null,
      tables: strings(out.tables),
      readOnly: strings(out.readOnly),
      excluded: Array.isArray(out.excluded) ? out.excluded : [],
      columns: Array.isArray(out.columns) ? out.columns : [],
      alreadyRan: out.alreadyRan === true,
      // Whether tables are listed with ticks and RunSetup needs the ticked
      // ones (CONTRACT.md, Tables on the connect page).
      // Absent (not false) from a service older than the field.
      ticked: typeof out.ticked === "boolean" ? out.ticked : undefined,
      // The confirm step's: the role the string signed in as, and what
      // verified the certificate.
      sessionUser: typeof out.sessionUser === "string" ? out.sessionUser : "",
      currentDatabase: typeof out.currentDatabase === "string" ? out.currentDatabase : "",
      certificate: out.certificate && typeof out.certificate === "object" ? out.certificate : null,
      // For a code with a target: every active passkey of the database
      // (CONTRACT.md, Update on the connect page).
      passkeys: activePasskeys(out.passkeys),
    };
    this.#ticket = typeof out.ticket === "string" ? out.ticket : "";
  }

  // revokePasskey is Remove on the passkey list: RevokePasskey with the
  // code, the string the page holds and the trusted certificate, for one
  // active passkey. The string stays for the fixes that follow; a refusal
  // of the string or the database drops it (the person pastes it again),
  // one of the passkey alone (ANSWERS_INVALID) keeps it.
  async revokePasskey(credentialId) {
    if (this.step !== "questions" || this.#databaseUrl === "" || !this.updateCheck) throw new Error("not at the passkey list");
    const req = { code: this.code, databaseUrl: this.#databaseUrl, credentialId };
    if (this.#trustRoot !== "") req.trustRoot = this.#trustRoot;
    let out;
    try {
      out = await call(this.fetch, "RevokePasskey", req);
    } catch (err) {
      if (!(err instanceof Refusal) || err.reason !== "ANSWERS_INVALID") this.backToPaste();
      throw err;
    }
    const removed = this.check.passkeys.find((p) => p.credentialId === credentialId) ?? null;
    this.check.passkeys = this.check.passkeys.filter((p) => p.credentialId !== credentialId);
    const remaining = Number.isInteger(out.remaining) && out.remaining > 0 ? out.remaining : 0;
    // No portal passkey left: the approval registers one.
    if (remaining === 0) this.check.passkeyNeeded = true;
    return { removed, remaining, lines: strings(out.lines) };
  }

  // recheck is "Retry" without a preview ticket (the service's caps were
  // full): CheckSetup again with the string the page still holds.
  async recheck(loop) {
    if (this.step !== "questions" || this.#databaseUrl === "") throw new Error("not at the reach check");
    try {
      await this.#check(loop);
    } catch (err) {
      if (loop.cancelled) return;
      this.backToPaste();
      throw err;
    }
  }

  // backToPaste is every way back to the paste step: the string, the check
  // and the ticket are dropped.
  backToPaste() {
    if (this.step !== "questions" && this.step !== "paste" && this.step !== "trust") throw new Error("not past the paste step");
    this.#databaseUrl = "";
    this.#ticket = "";
    this.#trustRoot = "";
    this.asking = null;
    this.check = null;
    this.step = "paste";
  }

  // reachApplies: a connect-only INSTALL code gets the reach check before
  // anything else is shown (CONTRACT.md, The reach check).
  get reachApplies() {
    return this.connectOnly && this.summary?.kind === "INSTALL" && this.check !== null && !this.check.alreadyRan && !this.check.nothingToDo;
  }

  get hasTicket() {
    return this.#ticket !== "";
  }

  // status is one HandoffStatus with the newest ticket, which it keeps;
  // UNKNOWN sends OfferAddress once per poll loop (offered tracks it).
  async #status(loop) {
    const out = await call(this.fetch, "HandoffStatus", { ticket: this.#ticket });
    // A late answer for a loop the person left (Back, another string, Go
    // on anyway) neither brings its ticket back nor offers its hold.
    if (loop.cancelled) return out;
    if (typeof out.ticket === "string" && out.ticket !== "") this.#ticket = out.ticket;
    if (out.state === "UNKNOWN" && !loop.offered) {
      loop.offered = true;
      await call(this.fetch, "OfferAddress", { ticket: this.#ticket });
    }
    return out;
  }

  // reach polls HandoffStatus with the preview ticket for up to a minute and
  // returns the engine's report: { result: "REACHABLE" }, { result:
  // "UNREACHABLE", reason }, or { result: "UNCHECKED" } (no ticket, no
  // report in time, or a refusal). loop.cancelled stops it.
  async reach(loop) {
    if (this.#ticket === "") return { result: "UNCHECKED" };
    const deadline = this.now() + REACH_WAIT_MS;
    for (;;) {
      let out;
      try {
        out = await this.#status(loop);
      } catch {
        return { result: "UNCHECKED" };
      }
      if (loop.cancelled) return { result: "CANCELLED" };
      // A report counts only for the preview: a SET_UP hold's has none.
      const r = out.reach;
      if (out.phase === "PREVIEW" && r && typeof r === "object") {
        if (r.result === "REACHABLE") return { result: "REACHABLE" };
        if (r.result === "UNREACHABLE") return { result: "UNREACHABLE", reason: typeof r.reason === "string" ? r.reason : "" };
      }
      if (this.now() >= deadline) return { result: "UNCHECKED" };
      await this.sleep(POLL_MS);
      if (loop.cancelled) return { result: "CANCELLED" };
    }
  }

  get passkeyMissing() {
    return this.check?.passkeyNeeded === true && !this.passkey && !this.check.alreadyRan;
  }

  // runSetup sends the answers and the person's choices: includedTables
  // when the tables had ticks, the labels when they were offered. A re-run
  // sends neither, and no passkey, since it registers nothing. The
  // connection string is cleared whatever the answer; after a refusal the
  // person pastes it again.
  async runSetup(answers, choices = {}) {
    if (this.step !== "questions") throw new Error("not at the approve step");
    if (this.passkeyMissing) throw new Refusal("PASSKEY_REQUIRED", "Create the passkey first.");
    const req = { code: this.code, databaseUrl: this.#databaseUrl, answers };
    if (this.#trustRoot !== "") req.trustRoot = this.#trustRoot;
    let sentPasskey = false;
    if (!this.check.alreadyRan) {
      if (Array.isArray(choices.includedTables)) req.includedTables = choices.includedTables;
      if (Array.isArray(choices.columnClasses) && choices.columnClasses.length > 0) req.columnClasses = choices.columnClasses;
      if (choices.restPublic === true) req.restPublic = true;
      if (this.passkey) {
        req.challenge = this.challenge;
        req.passkey = { ...this.passkey.registration };
        sentPasskey = true;
      }
    }
    this.#ticket = "";
    try {
      const out = await call(this.fetch, "RunSetup", req);
      this.step = "done";
      this.#ticket = typeof out.ticket === "string" ? out.ticket : "";
      return {
        warnings: strings(out.warnings),
        passkeys: Array.isArray(out.passkeys) ? out.passkeys : [],
        nothingToDo: out.nothingToDo === true,
        reconnected: out.reconnected === true,
        handoff: this.#ticket !== "",
        sentPasskey,
      };
    } catch (err) {
      this.step = "paste";
      this.check = null;
      throw err;
    } finally {
      this.#databaseUrl = "";
      this.#trustRoot = "";
    }
  }

  // watch polls HandoffStatus with the set-up ticket until the engine
  // collects the address, telling onState "waiting", "late" (after 2
  // minutes), "collected" or "gone" (the ticket was refused or expired).
  async watch(loop, onState) {
    const start = this.now();
    let late = false;
    onState("waiting");
    while (!loop.cancelled && this.#ticket !== "") {
      let out = null;
      try {
        out = await this.#status(loop);
      } catch (err) {
        // A tab woken after a while may find the network back later, and
        // a limit passes; another refusal (an expired ticket) ends the
        // watch.
        if (err instanceof Refusal && err.reason === "RATE_LIMITED" && err.retryAfterSeconds > 0) {
          await this.sleep(err.retryAfterSeconds * 1000);
        } else if (!(err instanceof Refusal) || err.reason !== "UNREACHABLE") {
          onState("gone");
          return;
        }
      }
      if (loop.cancelled) return;
      if (out && out.state === "COLLECTED" && out.phase !== "PREVIEW") {
        onState("collected");
        return;
      }
      const elapsed = this.now() - start;
      if (!late && elapsed >= LATE_MS) {
        late = true;
        onState("late");
      }
      if (elapsed >= WATCH_MS) return;
      await this.sleep(POLL_MS);
    }
  }

  // holdsConnectionString and holdsTicket are for the tests.
  get holdsConnectionString() {
    return this.#databaseUrl !== "";
  }

  get holdsTicket() {
    return this.#ticket !== "";
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

// The screens, in order, with the progress segment each fills and where
// Back goes. Every screen but the result carries the address-bar strip.
const SCREENS = [
  "s-code", "s-bot", "s-stop", "s-passkey", "s-paste", "s-confirm", "s-checking", "s-unreach",
  "s-doctor", "s-passkeys", "s-revoke", "s-addpk", "s-tables", "s-labels", "s-approve", "s-done",
];
const PROGRESS = {
  "s-code": 1, "s-bot": 1, "s-stop": 1, "s-passkey": 2, "s-paste": 3, "s-confirm": 3, "s-checking": 3, "s-unreach": 3,
  "s-doctor": 4, "s-passkeys": 4, "s-revoke": 4, "s-addpk": 4, "s-tables": 4, "s-labels": 5, "s-approve": 6,
};

function showScreen(name) {
  for (const s of SCREENS) show(s, s === name);
  const step = PROGRESS[name] ?? 0;
  show("addr-warn", name !== "s-done");
  show("progress", step > 0);
  const bar = $("progress");
  for (let i = 0; i < bar.children.length; i++) bar.children[i].className = i < step ? "on" : "";
  $("progress").setAttribute("aria-label", `Step ${step} of 6`);
}

function fail(message) {
  for (const s of SCREENS) show(s, false);
  show("back", false);
  show("progress", false);
  setText("error-text", message);
  show("error");
}

function fillDetails(s, connectOnly, nowMs, expires) {
  const facts = $("facts");
  clear(facts);
  if (expires) expires.node = null;
  const fact = (label, value, id) => {
    if (!value) return;
    const row = el("li");
    row.appendChild(el("strong", "", label + ": "));
    const val = el("span", "", value);
    if (id) {
      val.id = id;
      if (expires) expires.node = val;
    }
    row.appendChild(val);
    facts.appendChild(row);
  };
  fact("Agent", s.agent ? `${s.agent} (role ${s.role})` : "");
  fact("Database", connectOnly ? "the one you paste below" : databaseView(s.target)?.line ?? "");
  fact("Changes rows in", strings(s.write).join(", "));
  fact("Reads", strings(s.read).join(", "));
  fact("Engine fingerprint", typeof s.engineFingerprint === "string" ? s.engineFingerprint : "");
  const left = expiryCountdown(s.expiresAt, nowMs);
  fact("Code expires", left.expired ? "" : left.text, "code-expires-value");
  const lines = $("summary-lines");
  clear(lines);
  for (const line of strings(s.lines)) lines.appendChild(el("li", "", line));
}

// mark sets a check line: "wait" (a spinner), "ok" (a tick) or hidden.
function mark(id, state, text) {
  const li = $(id);
  li.hidden = state === "hidden";
  li.className = `check ${state}`;
  setText(id, text);
}

// start runs the page. env carries the browser's location, fetch,
// credentials and, for the tests, sleep and now.
export function start(env) {
  const { location } = env;
  if (location.origin !== PORTAL) {
    fail(`This page only runs at ${PORTAL}. Close it: the address bar shows another site.`);
    return null;
  }
  const flow = new Flow(env);
  setText("host", PAGE_HOST);
  show("main");
  // Two tabs: Connect a bot (the default) and Remove BasaltDB, which needs
  // no setup code (#remove opens it).
  startTabs(env, { removeOnly: location.hash === "#remove", rpc: { call, Refusal, notPostgres: NOT_POSTGRES } });

  // loop is the poll that runs now; a new one, Back and every way to
  // another screen cancel it.
  let loop = { cancelled: true };
  const newLoop = () => {
    loop.cancelled = true;
    loop = { cancelled: false, offered: false };
    return loop;
  };
  const expires = {};
  let screen = "s-code";
  let included = null; // the ticked tables, when the tables had ticks
  let labels = null;
  let labelMode = "skip";
  let reachOk = false;
  // fixLabels: on an update, the person chose to label the unlabeled
  // columns (Fix these, or Label on their row).
  let fixLabels = false;
  // revoking is the passkey the remove screen asks about.
  let revoking = null;
  // Back is offered on these screens; on the checking screen only once
  // CheckSetup answered (checkReach shows it).
  const back = {
    "s-passkey": "s-bot", "s-paste": "s-passkey", "s-unreach": "s-paste", "s-tables": "s-paste", "s-labels": "s-tables",
    "s-doctor": "s-paste", "s-passkeys": "s-doctor", "s-revoke": "s-passkeys", "s-addpk": "s-doctor",
  };
  // checkScreen is where the screens after the check go back to: the
  // Update check for a code with a target, else the tables.
  const checkScreen = () => (flow.updateCheck ? "s-doctor" : "s-tables");

  const go = (name) => {
    screen = name;
    showScreen(name);
    const to = name === "s-approve" ? (labelsApply() ? "s-labels" : checkScreen()) : back[name];
    show("back", Boolean(to));
  };
  const bot = () => botName(flow.summary);

  // paintExpiry refreshes the countdown. At zero, before the person has
  // confirmed the code, it shows only the expired page and no setup steps.
  // After "Yes, same code" the run may finish past expiresAt, so it is left alone.
  const paintExpiry = () => {
    if (!flow.summary) return false;
    const left = expiryCountdown(flow.summary.expiresAt, flow.now());
    if (expires.node && !left.expired) expires.node.textContent = left.text;
    if (left.expired && (flow.step === "bot" || flow.step === "code")) {
      fail(OPEN_LINK.EXPIRED(bot()));
      return true;
    }
    return false;
  };
  if (env.sleep === defaultSleep && typeof setInterval === "function") {
    const id = setInterval(() => { if (paintExpiry()) clearInterval(id); }, 1000);
  }

  // ---- 1: is this your bot? ----
  const describe = async (code) => {
    setText("code-status", "Reading the setup code…");
    try {
      const s = await flow.describe(code);
      setText("code-status", "");
      const name = bot();
      setText("avatar", name.charAt(0).toUpperCase());
      setText("bot-name", name);
      setText("bot-wants", WANTS[s.kind]);
      setText("fingerprint", typeof s.fingerprint === "string" ? s.fingerprint : "");
      fillDetails(s, flow.connectOnly, flow.now(), expires);
      go("s-bot");
    } catch (err) {
      const open = openLinkMessage(err, "your bot");
      if (open) {
        fail(open);
        return;
      }
      go("s-code");
      setText("code-status", refusalText(err));
    }
  };

  $("code-read").addEventListener("click", async () => {
    const code = readCode($("code-paste").value);
    if (!code) {
      setText("code-status", "No setup code found in that text. Paste the code your bot sent; it starts with basalt-setup.1.");
      return;
    }
    const done = busy($("code-read"), "Checking…");
    if (!done) return;
    $("code-paste").value = "";
    try {
      await describe(code);
    } finally {
      done();
    }
  });

  $("same-code").addEventListener("click", () => {
    if (paintExpiry()) return;
    flow.confirmBot();
    showPasskey();
  });

  $("different-code").addEventListener("click", () => {
    flow.stop();
    go("s-stop");
  });

  // ---- 2: the passkey ----
  const showPasskey = () => {
    const install = flow.needsNewPasskey;
    if (flow.passkeyDone) {
      setText("passkey-title", flow.passkey ? "Passkey created" : "Signed with your passkey");
      setText("passkey-go", "Continue");
    } else if (install) {
      setText("passkey-title", "Create your approval passkey");
      setText("passkey-lead", "You'll use it to approve your bot's bigger changes.");
      setText("passkey-go", "Create passkey");
    } else {
      setText("passkey-title", "Sign with your passkey");
      setText("passkey-lead", "Use the passkey you already have for this database. Only the real site can ask for it: if your device offers none, check the address bar before you go on.");
      setText("passkey-go", "Sign with your passkey");
    }
    show("passkey-lead", !flow.passkeyDone);
    show("passkey-existing", install && !flow.passkeyDone);
    // I don't have it: a person who lost their only device still reaches
    // the passkey list (CONTRACT.md, The connect page, step 3).
    show("passkey-skip", !install && !flow.passkeyDone);
    setText("passkey-status", "");
    go("s-passkey");
  };

  const passkeyDone = (text) => {
    setText("passkey-status", text);
    showPaste("");
  };

  $("passkey-go").addEventListener("click", async () => {
    if (flow.passkeyDone) {
      flow.passkeyContinue();
      showPaste("");
      return;
    }
    const done = busy($("passkey-go"), "Waiting for your passkey…");
    if (!done) return;
    setText("passkey-status", "");
    try {
      if (flow.needsNewPasskey) await flow.createPasskey();
      else await flow.signExisting();
      passkeyDone("");
    } catch (err) {
      setText("passkey-status", passkeyError(err));
      // Only a later code can go on without signing; an INSTALL needs a
      // passkey, new or the one the database has.
      if (!flow.needsNewPasskey) show("passkey-skip");
    } finally {
      done();
    }
  });

  $("passkey-use").addEventListener("click", async () => {
    const done = busy($("passkey-use"), "Waiting for your passkey…");
    if (!done) return;
    setText("passkey-status", "");
    try {
      await flow.signExisting();
      passkeyDone("");
    } catch (err) {
      setText("passkey-status", `${passkeyError(err)} Create a new passkey instead.`);
    } finally {
      done();
    }
  });

  $("passkey-skip").addEventListener("click", () => {
    flow.skipSign();
    show("passkey-skip", false);
    showPaste("Went on without signing. If you have a passkey for this database and this page never offered it, stop: this may not be the real site.");
  });

  // ---- 3: the connection string ----
  const hideString = () => {
    $("database-url").type = "password";
    $("reveal").setAttribute("aria-pressed", "false");
    $("reveal").setAttribute("aria-label", "Show connection string");
  };

  const showPaste = (problem) => {
    newLoop();
    if (flow.step === "questions" || flow.step === "trust") flow.backToPaste();
    hideString();
    setText("disclosure", disclosure(flow.summary));
    setText("paste-error", problem);
    show("paste-error", problem !== "");
    go("s-paste");
  };

  $("reveal").addEventListener("click", () => {
    const shown = $("database-url").type === "password";
    $("database-url").type = shown ? "text" : "password";
    $("reveal").setAttribute("aria-pressed", shown ? "true" : "false");
    $("reveal").setAttribute("aria-label", shown ? "Hide connection string" : "Show connection string");
  });
  // Every new paste starts hidden.
  $("database-url").addEventListener("paste", hideString);

  $("check").addEventListener("click", async () => {
    const input = $("database-url");
    const typed = input.value;
    input.value = "";
    hideString();
    const done = busy($("check"), "Checking…");
    if (!done) return;
    setText("checking-title", "Checking your database…");
    mark("chk-login", "wait", "Signing in to the database");
    mark("chk-tables", "hidden", "");
    mark("chk-reach", "hidden", "");
    show("checking-note", false);
    show("nocheck", false);
    try {
      if (POSTGRES_URL.test(typed.trim())) go("s-checking");
      await flow.checkSetup(typed);
    } catch (err) {
      if (flow.step === "trust") showConfirm("");
      else showPaste(err instanceof Refusal && err.reason === "NOT_POSTGRES" ? NOT_POSTGRES : refusalText(err));
      return;
    } finally {
      done();
    }
    showConfirm("");
  });

  // ---- 3a: Is this your database? One action: the database, its host,
  // who the string signs in as and the certificate. For a certificate
  // authority the provider runs itself (the trust step), Yes is also the
  // person's trust in it, and it alone sends the trustRoot. The bot's pin
  // changes only the words (CONTRACT.md, The bot's pin). ----
  let shownFacts = null; // what the confirm step showed
  const showConfirm = (problem) => {
    const view = flow.confirm();
    shownFacts = view.facts;
    paintConfirm(document, view);
    setText("confirm-error", problem);
    show("confirm-error", problem !== "");
    go("s-confirm");
  };
  $("confirm-go").addEventListener("click", async () => {
    if (screen !== "s-confirm") return;
    const done = busy($("confirm-go"), "Checking…");
    if (!done) return;
    try {
      if (flow.step === "trust") {
        setText("checking-title", "Checking your database…");
        mark("chk-login", "wait", "Signing in to the database");
        mark("chk-tables", "hidden", "");
        mark("chk-reach", "hidden", "");
        show("checking-note", false);
        show("nocheck", false);
        go("s-checking");
        try {
          await flow.trust();
        } catch (err) {
          done();
          if (flow.step === "trust") showConfirm(err.message);
          else showPaste(refusalText(err));
          return;
        }
        // The step showed what the string names; once signed in, the service
        // says what it reached. Anything else is asked again.
        if (factsDiffer(shownFacts, flow.confirm().facts)) {
          done();
          return showConfirm("");
        }
      }
      await checked();
    } finally {
      done();
    }
  });
  $("confirm-back").addEventListener("click", () => {
    if (screen !== "s-confirm") return;
    if (flow.step === "trust") flow.cancelTrust();
    showPaste("");
  });

  // checked shows what CheckSetup found, then the reach check where it
  // applies.
  const checked = async () => {
    mark("chk-login", "ok", "Signed in to the database");
    const n = tableRows(flow.summary, flow.check).rows.length;
    if (n > 0) mark("chk-tables", "ok", `Found ${n} ${n === 1 ? "table" : "tables"}`);
    reachOk = false;
    if (flow.updateCheck) {
      showDoctor(true);
      return;
    }
    if (!flow.reachApplies) {
      showTables(true);
      return;
    }
    await checkReach();
  };

  // ---- 3b and 3c: can the bot reach it? ----
  const checkReach = async () => {
    const mine = newLoop();
    go("s-checking");
    show("back");
    show("nocheck", false);
    mark("chk-reach", "wait", `Can ${bot()} reach it?`);
    setText("checking-note", "Takes up to a minute. Your bot only tests the connection; it can't sign in yet.");
    show("checking-note");
    const r = await flow.reach(mine);
    if (mine.cancelled) return;
    if (r.result === "REACHABLE") {
      reachOk = true;
      mark("chk-reach", "ok", `${bot()} can reach it`);
      showTables(true);
    } else if (r.result === "UNREACHABLE") {
      setText("unreach-title", `${bot()} can't reach this database`);
      setText("unreach-text", reachText(r.reason, bot()));
      go("s-unreach");
    } else {
      mark("chk-reach", "hidden", "");
      show("checking-note", false);
      setText("nocheck-text", `Couldn't check whether ${bot()} can reach it. Tell ${bot()} "check your status" in the chat, then retry.`);
      show("nocheck");
    }
  };

  $("retry-reach").addEventListener("click", async () => {
    const done = busy($("retry-reach"), "Checking…");
    if (!done) return;
    try {
      if (!flow.hasTicket) {
        const mine = newLoop();
        try {
          await flow.recheck(mine);
        } catch (err) {
          if (!mine.cancelled) showPaste(refusalText(err));
          return;
        }
        // The person went back while CheckSetup ran: stay where they are.
        if (mine.cancelled) return;
      }
      await checkReach();
    } finally {
      done();
    }
  });

  $("go-on").addEventListener("click", () => {
    newLoop();
    showTables(true);
  });

  $("paste-again").addEventListener("click", () => showPaste(""));

  // ---- 4: the database and its tables ----
  const labelsApply = () => {
    const c = flow.check;
    if (!c || c.alreadyRan || labels === null) return false;
    if (flow.updateCheck) return fixLabels && labels.of(labelTables()).length > 0;
    if (c.nothingToDo || flow.summary.kind === "UPGRADE") return false;
    return labels.of(tablesNow()).length > 0;
  };
  const tablesNow = () => included ?? tableRows(flow.summary, flow.check).rows.map((r) => r.name);
  // labelTables are the tables whose columns the labels screen shows: on
  // an update, those of the unlabeled columns alone (an UPGRADE names no
  // table: its columns are every readable one).
  const labelTables = () => (flow.updateCheck ? [...new Set(labels.columns.map((c) => c.table))] : tablesNow());

  // ---- 4 on an update: the check ----
  // showDoctor shows the check screen; fresh (after CheckSetup) starts the
  // labels from the unlabeled columns alone.
  const showDoctor = (fresh = false) => {
    newLoop();
    const c = flow.check;
    if (fresh) {
      included = null;
      labels = new Labels(unlabeledColumns(c.columns));
      fixLabels = false;
      labelMode = "skip";
    }
    const view = checkView(c);
    const db = c.database?.database ?? flow.summary.target?.database ?? "";
    setText("doc-top", `BasaltDB / Setup · ${db}`);
    setText("doc-title", view.title);
    setText("doc-sub", view.sub);
    const rows = $("doc-rows");
    clear(rows);
    for (const r of view.rows) {
      const row = el("div", `fix-row ${r.mark}`);
      row.appendChild(el("span", "fix-mark", r.mark === "good" ? "✓" : "!"));
      const body = el("div", "fix-body");
      body.appendChild(el("strong", "", r.title));
      if (r.text) body.appendChild(el("span", "muted", r.text));
      row.appendChild(body);
      if (r.action) {
        const act = el("button", "link fix-act", r.action);
        act.type = "button";
        act.addEventListener("click", () => rowAction(r.kind));
        row.appendChild(act);
      }
      rows.appendChild(row);
    }
    show("doc-pending", flow.passkey !== null);
    const notes = $("doc-notes");
    clear(notes);
    for (const n of c.notes) notes.appendChild(el("li", "", n));
    show("doc-notes", c.notes.length > 0);
    setText("doc-go", view.button);
    go("s-doctor");
  };

  const rowAction = (kind) => {
    if (kind === "LABELS") {
      fixLabels = true;
      showLabels();
    } else if (kind === "PASSKEY_ADD") showAddPasskey("You'll use it to approve your bot's bigger changes.");
    else if (kind === "PASSKEYS") showPasskeys("");
  };

  // Fix these walks the rows in order: the labels, then the approval, which
  // registers a passkey when the database has no portal one.
  $("doc-go").addEventListener("click", () => {
    fixLabels = labels.columns.length > 0;
    if (labelsApply()) showLabels();
    else showApprove();
  });

  // ---- The passkey list ----
  const showPasskeys = (done) => {
    const list = $("pk-list");
    clear(list);
    for (const p of flow.check.passkeys) {
      const row = el("div", "fix-row pk-row");
      const body = el("div", "fix-body");
      body.appendChild(el("strong", "", passkeyLabel(p)));
      body.appendChild(el("span", "muted", passkeyLine(p, flow.now())));
      row.appendChild(body);
      const rm = el("button", "pk-remove", "Remove");
      rm.type = "button";
      rm.addEventListener("click", () => showRevoke(p));
      row.appendChild(rm);
      list.appendChild(row);
    }
    setText("pk-done", done);
    show("pk-done", done !== "");
    show("pk-error", false);
    go("s-passkeys");
  };

  const showRevoke = (p) => {
    revoking = p;
    const lines = $("revoke-lines");
    clear(lines);
    for (const l of revokeLines(p, flow.check.passkeys)) lines.appendChild(el("li", "", l));
    show("revoke-error", false);
    go("s-revoke");
  };

  $("revoke-go").addEventListener("click", async () => {
    const done = busy($("revoke-go"), "Removing…");
    if (!done) return;
    try {
      const out = await flow.revokePasskey(revoking.credentialId);
      await signalRemoved(env.PublicKeyCredential ?? globalThis.PublicKeyCredential, out.removed);
      revoking = null;
      if (out.remaining === 0) showAddPasskey(ADD_AGAIN);
      else showPasskeys(out.lines.join("\n") || "The passkey is removed.");
    } catch (err) {
      if (flow.step === "paste") showPaste(refusalText(err, false));
      else {
        setText("revoke-error", err instanceof Refusal ? err.message : refusalText(err, false));
        show("revoke-error");
      }
    } finally {
      done();
    }
  });

  $("revoke-cancel").addEventListener("click", () => showPasskeys(""));
  $("pk-add").addEventListener("click", () => showAddPasskey("You'll use it to approve your bot's bigger changes."));

  // The add screen makes the passkey now; the approval registers it.
  const showAddPasskey = (lead) => {
    setText("addpk-lead", lead);
    setText("addpk-status", flow.passkey ? "Passkey created. It is registered when you approve." : "");
    $("addpk-go").textContent = flow.passkey ? "Continue" : "Create passkey";
    go("s-addpk");
  };

  $("addpk-go").addEventListener("click", async () => {
    if (flow.passkey) {
      showDoctor();
      return;
    }
    const done = busy($("addpk-go"), "Waiting for your passkey…");
    if (!done) return;
    setText("addpk-status", "");
    try {
      await flow.createPasskey();
      done();
      showDoctor();
    } catch (err) {
      setText("addpk-status", passkeyError(err));
    } finally {
      done();
    }
  });

  // showTables shows screen 4; fresh (after CheckSetup) ticks every table
  // and starts the labels from the database's classes, else it keeps the
  // person's choices (Back from a later screen).
  const showTables = (fresh = false) => {
    newLoop();
    const c = flow.check;
    const view = databaseView(c.database ?? flow.summary.target);
    setText("db-label", `This is the database ${bot()} will use`);
    setText("db-name", view?.big ?? "");
    setText("db-sub", view?.sub ?? "");
    setText("db-reach", `✓ ${bot()} can reach it`);
    show("db-reach", reachOk);
    show("already-ran", c.alreadyRan);
    const { rows, ticks, excluded } = tableRows(flow.summary, c);
    if (fresh) {
      included = ticks ? rows.map((r) => r.name) : null;
      labels = new Labels(c.columns);
    }
    const list = $("tables");
    clear(list);
    for (const r of rows) {
      const item = el("label", "tick");
      if (ticks) {
        const box = el("input");
        box.type = "checkbox";
        box.checked = included.includes(r.name);
        box.value = r.name;
        box.addEventListener("change", () => {
          included = rows.filter((x) => x.name === box.value ? box.checked : included.includes(x.name)).map((x) => x.name);
          countTables(rows.length);
        });
        item.appendChild(box);
      }
      item.appendChild(el("span", "mono", tableName(r.name)));
      if (r.access === "noKey") item.appendChild(el("span", "muted", "read only (no row ID)"));
      if (r.access === "read") item.appendChild(el("span", "muted", "read only"));
      list.appendChild(item);
    }
    show("tables-box", rows.length > 0 && !c.alreadyRan);
    countTables(rows.length);
    setText("tables-note", ticks
      ? `${bot()} can read and change every row of the ticked tables, and can't see the unticked ones.`
      : `${bot()} can use every row of these tables, and can't see any other.`);
    setText("excluded", excluded.length > 0 ? `Not offered: ${excluded.map((e) => `${tableName(e.table)} (owned by another role)`).join(", ")}` : "");
    show("excluded", excluded.length > 0);
    const notes = $("notes");
    clear(notes);
    for (const n of c.notes) notes.appendChild(el("li", "", n));
    show("notes", c.notes.length > 0);
    go("s-tables");
  };

  const countTables = (n) => {
    const m = included ? included.length : n;
    setText("tables-count", `${m} of ${n}`);
    $("tables-next").disabled = included !== null && included.length === 0;
    setText("tables-error", included !== null && included.length === 0 ? "Tick at least one table." : "");
    show("tables-error", included !== null && included.length === 0);
  };

  $("tables-next").addEventListener("click", () => {
    if (labelsApply()) showLabels();
    else {
      labelMode = "skip";
      showApprove();
    }
  });

  // ---- 5: personal data ----
  const showLabels = () => {
    const box = $("label-tables");
    clear(box);
    const cols = labels.of(labelTables());
    const byTable = new Map();
    for (const c of cols) {
      if (!byTable.has(c.table)) byTable.set(c.table, []);
      byTable.get(c.table).push(c);
    }
    let first = true;
    for (const [table, list] of byTable) {
      const d = el("details", "label-table");
      d.open = first;
      first = false;
      const head = el("summary");
      head.appendChild(el("span", "mono", tableName(table)));
      head.appendChild(el("span", "muted", ` ${list.length} ${list.length === 1 ? "column" : "columns"}`));
      d.appendChild(head);
      for (const c of list) d.appendChild(labelRow(c));
      box.appendChild(d);
    }
    setText("unlabeled-warn", `Columns without a label aren't masked: ${bot()} reads them as they are, and they can be sent to its AI provider. They'll be blocked once PII protection ships, until you label them.`);
    show("labels-error", false);
    $("rest-mark").checked = labelMode === "rest";
    $("rest-leave").checked = labelMode !== "rest";
    restCount();
    go("s-labels");
  };

  // restCount shows the choice for the columns left unlabeled only while
  // there are some, and the note under "Mark them as not personal" while
  // it is chosen: the choice is the confirmation.
  const restCount = () => {
    const n = labels.unlabeled(labelTables()).length;
    show("rest-choice", n > 0);
    const note = $("rest-note");
    const lines = $("rest-mark").checked ? restNote({ count: n, forced: labels.changes(labelTables()).length + n > MAX_LABELS }) : [];
    clear(note);
    for (const line of lines) note.appendChild(el("span", "", line));
    note.hidden = lines.length === 0;
  };

  const labelRow = (c) => sharedLabelRow(c, labels, restCount);

  const labelsProblem = (text) => {
    setText("labels-error", text);
    show("labels-error", text !== "");
    return text !== "";
  };

  // Continue keeps the labels the person picked, and with "Mark them as
  // not personal" marks the rest as its note says.
  $("labels-next").addEventListener("click", () => {
    if (labelsProblem(labels.problem(labelTables()))) return;
    labelMode = !$("rest-choice").hidden && $("rest-mark").checked ? "rest" : "changes";
    showApprove();
  });

  for (const id of ["rest-leave", "rest-mark"]) $(id).addEventListener("change", restCount);

  // ---- 6: approve ----
  const showApprove = () => {
    const c = flow.check;
    const view = databaseView(c.database ?? flow.summary.target);
    setText("ap-bot", bot());
    setText("ap-db", view?.big ?? "");
    const parts = [];
    const n = tablesNow().length;
    if (!c.alreadyRan && n > 0) parts.push(`${n} ${n === 1 ? "table" : "tables"}`);
    if (labelsApply() && labelMode !== "skip") {
      const k = labels.changes(labelTables()).length;
      if (k > 0) parts.push(`${k} ${k === 1 ? "column" : "columns"} marked`);
      if (labelMode === "rest" && labels.unlabeled(labelTables()).length > 0) parts.push("the rest not personal");
    }
    if (flow.updateCheck && flow.passkey) parts.push("a passkey added");
    setText("ap-counts", parts.join(" · "));
    show("ap-counts", parts.length > 0);
    show("ap-limits", flow.summary.kind !== "UPGRADE" && !c.alreadyRan && !c.nothingToDo);
    setText("approve-status", "");
    go("s-approve");
  };

  $("approve").addEventListener("click", async () => {
    const done = busy($("approve"), flow.passkeyMissing ? "Waiting for your passkey…" : flow.updateCheck ? "Updating…" : "Setting up…");
    if (!done) return;
    newLoop();
    // No way back while the setup runs.
    show("back", false);
    try {
      // The database has no passkey and none was made yet: make it now.
      if (flow.passkeyMissing) {
        try {
          await flow.createPasskey();
        } catch (err) {
          setText("approve-status", passkeyError(err));
          show("back");
          return;
        }
        done.label(flow.updateCheck ? "Updating…" : "Setting up…");
      }
      const choices = {};
      if (included) choices.includedTables = included;
      if (labelsApply()) Object.assign(choices, labels.request(labelTables(), labelMode));
      setText("approve-status", "Running the setup…");
      let result;
      try {
        result = await flow.runSetup(answersFor(flow.check.questions, included), choices);
      } catch (err) {
        ranRefused(err);
        return;
      }
      // The setup ran: show it, outside the try, so a display error is
      // never reported as a refusal.
      done();
      await showDone(result);
    } finally {
      done();
    }
  });

  const ranRefused = (err) => {
    // A challenge past its 15 minutes, one for another code, or a passkey
    // the service refused needs a fresh start (a new challenge and a new
    // passkey); sending the same registration again would be refused again.
    if (err instanceof Refusal && (err.reason.startsWith("CHALLENGE_") || err.reason === "PASSKEY_INVALID")) {
      fail(refusalText(err) + "\nOpen the link from your bot again to start over.");
      return;
    }
    // No answer arrived: the setup may have run. Pasting again would be
    // refused USED, so show the page's own check code and send the person
    // to the bot.
    if (err instanceof Refusal && (err.reason === "UNREACHABLE" || err.reason === "UNKNOWN")) {
      fail(`${err.message}\nThis page cannot tell whether the setup ran. Tell your bot "done" so it checks; if it says the setup is still pending, open the link from your bot again.`);
      if (flow.passkey) {
        setText("error-check-code", flow.passkey.checkCode);
        show("error-code");
      }
      return;
    }
    let text = refusalText(err);
    if (err instanceof Refusal && err.reason === "TABLES_CHANGED") text += "\nPaste the connection string again to see the tables as they are now.";
    else if (err instanceof Refusal && err.reason === "CLASSES_CHANGED") text += "\nPaste the connection string again to see the labels as they are now.";
    else text += "\nPaste the connection string again to retry.";
    showPaste(text);
  };

  // ---- 7: done ----
  const showDone = async (result) => {
    const c = flow.check;
    const db = databaseView(c?.database ?? flow.summary.target);
    setText("done-title", result.nothingToDo ? "Nothing to do: the guard is already at that version. Nothing changed." : "✓ Set up: one step left in the chat");
    mark("done-setup", "ok", "Database set up");
    show("reconnected", result.reconnected);
    const warnings = $("warnings");
    clear(warnings);
    for (const w of result.warnings) warnings.appendChild(el("li", "", w));
    show("warnings", result.warnings.length > 0);
    // A re-run registers no passkey: no check code to compare or show.
    const mine = flow.passkey && result.sentPasskey && !result.reconnected ? { credentialId: flow.passkey.registration.credentialId, checkCode: flow.passkey.checkCode } : null;
    if (mine) setText("check-code", mine.checkCode);
    show("check-code", mine !== null);
    const problem = result.reconnected || (flow.passkey && !result.sentPasskey) ? "" : compareCheckCodes(mine, result.passkeys);
    setText("check-problem", problem);
    show("check-problem", problem !== "");
    if (result.handoff) {
      setText("chat-text", mine ? `${bot()} will ask you to confirm the database and show this passkey code:` : `${bot()} will ask you to confirm the database.`);
    } else {
      setText("chat-text", mine ? `Tell ${bot()} "done" so it checks now. It names this passkey code when it picks up the setup:` : `Tell ${bot()} "done" so it checks now.`);
    }
    go("s-done");
    show("back", false);
    if (!result.handoff) {
      mark("done-pickup", "hidden", "");
      setText("pickup-text", "");
      return;
    }
    const mine2 = newLoop();
    await flow.watch(mine2, (state) => {
      if (state === "waiting") {
        mark("done-pickup", "wait", `${bot()} picked up the address`);
        setText("pickup-text", "Waiting for your bot to pick up the address…");
      } else if (state === "late") {
        setText("pickup-text", "Your bot hasn't picked it up yet. Tell it to check its status.");
      } else if (state === "collected") {
        mark("done-pickup", "ok", `${bot()} picked up the address`);
        setText("pickup-text", `Your bot picked up the address of ${db?.line ?? "your database"}. It will ask you in the chat to confirm this database.`);
      } else {
        setText("pickup-text", "Your bot hasn't picked it up yet. Tell it to check its status; if it still waits, open the link from your bot again.");
      }
    });
  };

  // ---- Back ----
  $("back").addEventListener("click", () => {
    newLoop();
    if (screen === "s-passkey") {
      flow.backTo("bot");
      go("s-bot");
    } else if (screen === "s-paste") {
      flow.backTo("passkey");
      showPasskey();
    }
    else if (["s-checking", "s-unreach", "s-tables", "s-confirm", "s-doctor"].includes(screen)) showPaste("");
    else if (screen === "s-passkeys" || screen === "s-addpk") showDoctor();
    else if (screen === "s-revoke") showPasskeys("");
    else if (screen === "s-labels") {
      if (flow.updateCheck) showDoctor();
      else showTables();
    } else if (screen === "s-approve") {
      if (labelsApply()) showLabels();
      else if (flow.updateCheck) showDoctor();
      else showTables();
    }
  });

  const code = readCode(location.hash.replace(/^#/, ""));
  if (code) return { flow, ready: describe(code), paintExpiry };
  go("s-code");
  return { flow, ready: Promise.resolve(), paintExpiry };
}

// Only in a browser: the tests load this module without a document.
if (typeof document !== "undefined" && typeof window !== "undefined" && window.location) {
  start({ location: window.location, fetch: browserFetch, credentials: navigator.credentials });
}

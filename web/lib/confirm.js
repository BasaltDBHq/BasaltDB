// The confirm step both setup pages share, "Is this your database?"
// (CONTRACT.md, The install of a real database, and The connect page): one
// action after the admin connection string is accepted, in which the person
// checks the database, its host, who the string signs in as and the
// certificate together. For a certificate authority the database's provider
// runs itself, confirming is also the person's trust in it, for this host
// only. Pure functions, and one painter for the screen's elements, so the
// local setup page and the connect page show the same words.
import { fingerprintText } from "./picks.js";

const SHA256_HEX = /^[0-9a-f]{64}$/;
const DEFAULT_PORT = 5432;

// rdns splits an RFC 2253 subject, as the engine and the connect service
// give it, into [type, value] pairs, its escapes undone.
function rdns(subject) {
  const out = [];
  let part = "";
  let escaped = false;
  const flush = () => {
    const eq = part.indexOf("=");
    if (eq > 0) out.push([part.slice(0, eq).trim().toUpperCase(), part.slice(eq + 1)]);
    part = "";
  };
  for (const ch of String(subject ?? "")) {
    if (escaped) {
      part += ch;
      escaped = false;
    } else if (ch === "\\") escaped = true;
    else if (ch === "," || ch === "+") flush();
    else part += ch;
  }
  flush();
  return out;
}

// nameOf is a certificate authority's short name from its RFC 2253
// subject, as the engine names one (its common name, else its first
// organization, else the whole subject). The server chose it: it is shown
// as text, and it names, it proves nothing.
export function nameOf(subject) {
  const parts = rdns(subject);
  const of = (type) => parts.find(([t, v]) => t === type && v.trim() !== "")?.[1].trim();
  return of("CN") ?? of("O") ?? String(subject ?? "");
}

// stringFacts are what the admin string the page holds names: its
// database, host, port and user, read on the page before anything logged
// in (the refusal of a certificate comes before the login). Never the
// password. null for a string the page cannot read.
export function stringFacts(databaseUrl) {
  let u;
  try {
    u = new URL(String(databaseUrl ?? ""));
  } catch {
    return null;
  }
  const q = u.searchParams;
  const decode = (s) => {
    try {
      return decodeURIComponent(s);
    } catch {
      return s;
    }
  };
  const host = (q.get("host") || u.hostname).replace(/^\[|\]$/g, "");
  if (host === "") return null;
  const port = Number(q.get("port") || u.port) || DEFAULT_PORT;
  const user = q.get("user") || decode(u.username);
  const database = q.get("dbname") || decode(u.pathname.replace(/^\//, "")) || user;
  return { database, host, port, user };
}

// certificateLine is how the confirm step names a check's certificate:
// verified by a public authority or a provider the engine knows, with ✓;
// a root this host was given (a pin, an operator's profile, sslrootcert)
// by its name; not checked, or not encrypted, as a warning.
export function certificateLine(c) {
  const issuer = typeof c?.issuer === "string" ? c.issuer : "";
  switch (c?.kind) {
    case "PUBLIC":
    case "PROVIDER":
      return { text: issuer ? `✓ Verified by ${issuer}` : "✓ Verified", tone: "same" };
    case "OWN":
      return { text: issuer || "Your own certificate authority", tone: "" };
    case "NOT_VERIFIED":
      return { text: "Not checked: the connection string doesn't ask for it", tone: "diff" };
    case "NONE":
      return { text: "None: the connection isn't encrypted", tone: "diff" };
  }
  return { text: "Not known", tone: "diff" };
}

const hostLine = (host, port) => `${host}:${Number.isInteger(port) && port > 0 ? port : DEFAULT_PORT}`;

const SUB = "Check these, then continue.";
const OWN_SUB = "Your provider signs its own security certificate, so confirming also trusts it for this database only.";

// confirmView is the confirm step. input:
//   facts: { database, host, port, user } (a check's answer, else
//     stringFacts of the string the page holds);
//   certificate: the check's certificate, when the string logged in;
//   asking: the refusal's certificate authority to trust ({ subject,
//     sha256, expiresAt }), when it did not;
//   renewal: { pinnedSubject } on the Update check's new certificate (the
//     subject of the certificate the engine has pinned);
//   trustPin, bot: the connect page's code's pin and the bot's name.
// It returns { variant, title, sub, rows, ok, before, go, weak, back,
// fingerprint, trusts }. trusts says that Yes sends asking's SHA-256 as
// trustRoot: only a click on Yes does.
export function confirmView({ facts, certificate = null, asking = null, renewal = null, trustPin = "", bot = "your bot" }) {
  const f = facts ?? { database: "", host: "", port: DEFAULT_PORT, user: "" };
  const rows = (cert) => [
    { label: "Database", value: String(f.database ?? ""), tone: "" },
    { label: "Host", value: hostLine(String(f.host ?? ""), f.port), tone: "" },
    { label: "Signed in as", value: String(f.user ?? ""), tone: "" },
    { label: "Certificate", ...cert },
  ];
  const base = { title: "Is this your database?", sub: SUB, ok: "", before: "", go: "Yes, this is it", weak: false, back: "No, go back", fingerprint: "", trusts: false };
  if (!asking) {
    const line = certificateLine(certificate);
    return { ...base, variant: "VERIFIED", rows: rows({ value: line.text, tone: line.tone }) };
  }
  const name = nameOf(asking.subject);
  const fingerprint = `SHA-256: ${fingerprintText(asking.sha256)}`;
  const own = { ...base, rows: rows({ value: name, tone: "" }), fingerprint, trusts: true };
  const pin = typeof trustPin === "string" && SHA256_HEX.test(trustPin) ? trustPin : "";
  if (pin !== "" && pin === asking.sha256) return { ...own, variant: "MATCH", ok: `✓ Matches what ${bot} trusts` };
  if (!renewal && pin === "") return { ...own, variant: "OWN", sub: `${SUB} ${OWN_SUB}` };
  // A certificate other than the one pinned: the Update check's, or the
  // connect page's for a bot whose pin differs. Same issuer only when the
  // old one's name is known and is this one's; otherwise the cautious words.
  const before = renewal?.pinnedSubject ? nameOf(renewal.pinnedSubject) : "";
  const renewed = { ...own, title: "Is this still your database?", back: "Not expecting this? Stop here" };
  if (before !== "" && before === name) {
    return { ...renewed, variant: "RENEWED", sub: "Providers renew certificates about once a year.", ok: "✓ Same issuer as before", go: "Yes, trust the new certificate" };
  }
  let was = "";
  if (before !== "") was = `Before: ${before}`;
  else if (pin !== "") was = `Before: SHA-256 ${fingerprintText(pin)}`;
  return {
    ...renewed,
    variant: "NEW_ISSUER",
    sub: "The certificate now comes from someone new. Check with your provider first. Your agents stay paused.",
    rows: rows({ value: name, tone: "diff" }),
    before: was,
    go: "Trust it anyway",
    weak: true,
    back: "Stop here",
  };
}

// paintConfirm shows view on the page's confirm screen: the elements
// confirm-title, confirm-sub, confirm-facts, confirm-ok, confirm-before,
// confirm-go, confirm-back, confirm-details and confirm-fp. Every value is
// set as text: the issuer is the server's.
export function paintConfirm(doc, view) {
  const $ = (id) => doc.getElementById(id);
  const text = (id, value) => {
    $(id).textContent = value;
    $(id).hidden = value === "";
  };
  $("confirm-title").textContent = view.title;
  text("confirm-sub", view.sub);
  const facts = $("confirm-facts");
  facts.textContent = "";
  for (const r of view.rows) {
    const row = doc.createElement("div");
    const label = doc.createElement("span");
    label.textContent = r.label;
    const value = doc.createElement("strong");
    value.textContent = r.value;
    if (r.tone) value.className = r.tone;
    row.appendChild(label);
    row.appendChild(value);
    facts.appendChild(row);
  }
  text("confirm-ok", view.ok);
  text("confirm-before", view.before);
  $("confirm-go").textContent = view.go;
  $("confirm-go").className = view.weak ? "secondary" : "";
  $("confirm-back").textContent = view.back;
  $("confirm-fp").textContent = view.fingerprint;
  $("confirm-details").hidden = view.fingerprint === "";
}

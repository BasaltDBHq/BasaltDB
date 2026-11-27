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

const URL_SCHEME = /^postgres(ql)?:\/\//i;
const KV_SSLMODE = /(^|\s)sslmode=('[^']*'|\S*)/;

// urlParts splits a postgres:// string into the part before its query
// (scheme, user and password, host, path), the query without its ?, and
// the fragment with its #. The user and host part ends at the first / after
// the scheme, so an @ or ? in the query never reads as one, and a password
// keeps whatever it holds (a / in it must be encoded, as in any URL); a
// string with no path ends it at the first ? or #.
function urlParts(s) {
  const scheme = URL_SCHEME.exec(s)[0].length;
  const slash = s.indexOf("/", scheme);
  let from = slash;
  if (slash < 0) {
    const ends = [s.indexOf("?", scheme), s.indexOf("#", scheme)].filter((i) => i >= 0);
    from = ends.length > 0 ? Math.min(...ends) : s.length;
  }
  const hash = s.indexOf("#", from);
  const bodyEnd = hash < 0 ? s.length : hash;
  const q = s.indexOf("?", from);
  if (q < 0 || q > bodyEnd) return { head: s.slice(0, bodyEnd), query: null, frag: s.slice(bodyEnd) };
  return { head: s.slice(0, q), query: s.slice(q + 1, bodyEnd), frag: s.slice(bodyEnd) };
}

// keyOf is a query pair's key, decoded as the driver reads it
// (ssl%6Dode is sslmode).
const keyOf = (pair) => [...new URLSearchParams(pair).keys()][0] ?? "";

// sslModeOf is the sslmode a connection string names: a postgres:// URL's
// query parameter (its decoded key, the last one when there are several,
// as the driver takes it) or a key=value string's, "prefer" (the driver's
// default) when it names none.
export function sslModeOf(databaseUrl) {
  const s = String(databaseUrl ?? "");
  if (URL_SCHEME.test(s)) {
    const { query } = urlParts(s);
    const modes = query === null ? [] : new URLSearchParams(query).getAll("sslmode");
    return modes.at(-1) || "prefer";
  }
  const m = KV_SSLMODE.exec(s);
  return (m ? m[2].replace(/^'|'$/g, "") : "") || "prefer";
}

// withVerifyFull is the string the page holds with only its sslmode set to
// verify-full (every pair whose decoded key is sslmode), or added when it
// names none: every other byte stays, the password's encoding and the other
// parameters too (a URL round trip would change them).
export function withVerifyFull(databaseUrl) {
  const s = String(databaseUrl ?? "");
  if (!URL_SCHEME.test(s)) {
    if (KV_SSLMODE.test(s)) return s.replace(KV_SSLMODE, "$1sslmode=verify-full");
    return `${s} sslmode=verify-full`;
  }
  const { head, query, frag } = urlParts(s);
  if (query === null || query === "") return `${head}?sslmode=verify-full${frag}`;
  let found = false;
  const pairs = query.split("&").map((pair) => {
    if (keyOf(pair) !== "sslmode") return pair;
    found = true;
    return "sslmode=verify-full";
  });
  if (!found) pairs.push("sslmode=verify-full");
  return `${head}?${pairs.join("&")}${frag}`;
}

// notCheckedBox is the warning under the facts for a connection that is
// encrypted but does not check the certificate (kind NOT_VERIFIED): with
// the provider whose roots BasaltDB has built in, the one-click check;
// without one, what to change in the string.
function notCheckedBox(provider, sslMode) {
  const mode = `sslmode=${sslMode || "prefer"}`;
  if (provider) {
    return {
      text: `Your connection string has ${mode}: it's encrypted, but nothing checks the certificate is ${provider}'s. BasaltDB has ${provider}'s certificates built in, so it can check.`,
      check: "Check the certificate",
    };
  }
  return { text: `Your connection string has ${mode}: it's encrypted, but nothing checks the certificate is your database's. To check it, use sslmode=verify-full in the connection string.`, check: "" };
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
//   renewal: { pinnedSubject, sameIssuer } on the Update check's new
//     certificate: the subject of the certificate the engine has pinned,
//     shown as Before, and the engine's answer whether the new one has its
//     key or was signed by it (names are never compared: anyone can give a
//     certificate any name);
//   trustPin, bot: the connect page's code's pin and the bot's name;
//   sslMode: the sslmode of the string the page holds, named by the
//     warning of a certificate not checked (NOT_VERIFIED);
//   mismatch: the provider's name, after Check the certificate found a
//     certificate that is not the provider's.
// It returns { variant, facts, title, sub, rows, ok, before, go, weak,
// back, fingerprint, trusts, warn, warnTone, check }. trusts says that Yes
// sends asking's SHA-256 as trustRoot: only a click on Yes does. warn is
// the box under the facts ("" for none) and check its button's words ("" for
// none).
export function confirmView({ facts, certificate = null, asking = null, renewal = null, trustPin = "", bot = "your bot", sslMode = "", mismatch = "" }) {
  const f = facts ?? { database: "", host: "", port: DEFAULT_PORT, user: "" };
  const rows = (cert) => [
    { label: "Database", value: String(f.database ?? ""), tone: "" },
    { label: "Host", value: hostLine(String(f.host ?? ""), f.port), tone: "" },
    { label: "Signed in as", value: String(f.user ?? ""), tone: "" },
    { label: "Certificate", ...cert },
  ];
  const base = { facts: f, title: "Is this your database?", sub: SUB, ok: "", before: "", go: "Yes, this is it", weak: false, back: "No, go back", fingerprint: "", trusts: false, warn: "", warnTone: "", check: "" };
  if (mismatch) {
    return {
      ...base,
      variant: "MISMATCH",
      rows: [
        { label: "Host", value: hostLine(String(f.host ?? ""), f.port), tone: "" },
        { label: "Certificate", value: "Didn't match", tone: "diff" },
      ],
      warn: `This database's certificate didn't match ${mismatch}'s, so nothing was sent. Something between you and ${mismatch} may be reading your traffic, such as a work network that inspects encrypted connections.`,
      warnTone: "bad",
      go: "Go back",
      weak: true,
      back: "Continue without checking",
    };
  }
  if (!asking && certificate?.kind === "NOT_VERIFIED") {
    const box = notCheckedBox(typeof certificate.provider === "string" ? certificate.provider : "", sslMode);
    return {
      ...base,
      variant: "NOT_CHECKED",
      rows: rows({ value: "Not checked", tone: "diff" }),
      warn: box.text,
      warnTone: "warn",
      check: box.check,
      go: "Yes, this is it, without checking",
      weak: true,
    };
  }
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
  // engine says so from the keys; otherwise the cautious words.
  const before = renewal?.pinnedSubject ? nameOf(renewal.pinnedSubject) : "";
  const renewed = { ...own, title: "Is this still your database?", back: "Not expecting this? Stop here" };
  if (renewal?.sameIssuer === true) {
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

// factsDiffer reports whether what the server says it reached (after) is
// not what the confirm step showed from the string (before): then the
// person is asked again, with the server's facts.
export function factsDiffer(before, after) {
  const norm = (f) => [String(f?.database ?? ""), String(f?.host ?? "").toLowerCase(), Number(f?.port) || DEFAULT_PORT, String(f?.user ?? "")].join("\u0000");
  return norm(before) !== norm(after);
}

// paintConfirm shows view on the page's confirm screen: the elements
// confirm-title, confirm-sub, confirm-facts, confirm-ok, confirm-before,
// confirm-go, confirm-back, confirm-details and confirm-fp, and with box
// (the local setup page's install, the one page that has them) the warning
// box: confirm-warn, confirm-warn-text and confirm-check. Every value is set
// as text: the issuer is the server's.
export function paintConfirm(doc, view, { box = false } = {}) {
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
  if (!box) return;
  $("confirm-warn").hidden = !view.warn;
  $("confirm-warn").className = `strip ${view.warnTone || "warn"} box-action`;
  $("confirm-warn-text").textContent = view.warn ?? "";
  $("confirm-check").textContent = view.check ?? "";
  $("confirm-check").hidden = !view.check;
}

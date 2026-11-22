// The connect page's Update check (CONTRACT.md, Update on the connect
// page): what the check screen, the passkey list and the bot's pin show,
// from CheckSetup's answer for a code with a target. Pure functions only:
// the page wires them in connect.js. The words are the local setup page's
// (CONTRACT.md, The Update check), with the portal's passkeys in place of
// this computer's.
import { PROD_RP_ID } from "./codec.js";
import { fingerprintText, tableName } from "./picks.js";

// MAX_NAMED is how many unlabeled columns the row names before "…".
export const MAX_NAMED = 20;
const SHA256_HEX = /^[0-9a-f]{64}$/;
const DAY_MS = 86_400_000;
const DAYS_PER_WEEK = 7;
// Up to two weeks the age is said in days, past that in weeks.
const DAYS_BEFORE_WEEKS = 14;
const MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

const plural = (n, one, many) => `${n} ${n === 1 ? one : many}`;

// isUnlabeled: a column with no class stored, or UNCLASSIFIED.
export function isUnlabeled(c) {
  return !c?.class || c.class === "UNCLASSIFIED";
}

// unlabeledColumns are CheckSetup's columns that have no label, in its
// order: the only columns the labels screen shows on an update.
export function unlabeledColumns(columns) {
  return (Array.isArray(columns) ? columns : []).filter((c) => typeof c?.table === "string" && typeof c?.column === "string" && isUnlabeled(c));
}

// activePasskeys are CheckSetup's passkeys that the page can read.
export function activePasskeys(passkeys) {
  return (Array.isArray(passkeys) ? passkeys : []).filter((p) => typeof p?.credentialId === "string" && p.credentialId !== "");
}

// portalCount is how many of them sign on the portal's pages.
export function portalCount(passkeys) {
  return activePasskeys(passkeys).filter((p) => p.rpId === PROD_RP_ID).length;
}

// checkView is the check screen: the rows that need the person (unlabeled
// columns, no portal passkey), then the Passkeys row, the title and the line
// under it, and the button.
export function checkView(check) {
  const cols = unlabeledColumns(check?.columns);
  const portal = portalCount(check?.passkeys);
  const devices = plural(portal, "device can approve", "devices can approve");
  const rows = [];
  if (cols.length > 0) {
    const names = cols.slice(0, MAX_NAMED).map((c) => `${tableName(c.table)}.${c.column}`).join(", ");
    rows.push({
      kind: "LABELS", mark: "warn", action: "Label",
      title: cols.length === 1 ? "1 new column has no label" : `${cols.length} new columns have no label`,
      text: cols.length > MAX_NAMED ? `${names}, …` : names,
    });
  }
  if (portal === 0) {
    rows.push({ kind: "PASSKEY_ADD", mark: "warn", action: "Add", title: "No passkey can approve", text: "Your agents' larger writes wait until you add one." });
  }
  const needs = rows.length;
  if (needs === 0) {
    return {
      needs,
      title: "All good",
      sub: "BasaltDB is running and your agents can connect.",
      rows: [
        { kind: "LABELS_OK", mark: "good", title: "Every column has a label", text: "", action: "" },
        { kind: "CERTIFICATE_OK", mark: "good", title: "Database certificate checked", text: "", action: "" },
        { kind: "PASSKEYS", mark: "good", title: "Passkeys", text: devices, action: "Manage" },
      ],
      button: "Continue",
    };
  }
  if (portal > 0) rows.push({ kind: "PASSKEYS", mark: "good", title: "Passkeys", text: devices, action: "Manage" });
  return { needs, title: needs === 1 ? "1 thing needs you" : `${needs} things need you`, sub: "Everything else is working.", rows, button: "Fix these" };
}

// dayMonth is a time as "3 Nov", in UTC.
export function dayMonth(iso) {
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return "";
  const d = new Date(t);
  return `${d.getUTCDate()} ${MONTHS[d.getUTCMonth()]}`;
}

// usedText is when a passkey was last used: today, N days ago, N weeks
// ago, or never.
export function usedText(lastUsedAt, nowMs) {
  const t = typeof lastUsedAt === "string" && lastUsedAt !== "" ? Date.parse(lastUsedAt) : Number.NaN;
  if (Number.isNaN(t)) return "never";
  const days = Math.max(0, Math.floor((nowMs - t) / DAY_MS));
  if (days === 0) return "today";
  if (days < DAYS_BEFORE_WEEKS) return plural(days, "day ago", "days ago");
  return plural(Math.floor(days / DAYS_PER_WEEK), "week ago", "weeks ago");
}

// passkeyLine is a passkey's line in the list: `Added <day month> · used
// …`, with `on <host>` after the date for one that signs on another site's
// pages than the portal's.
export function passkeyLine(p, nowMs) {
  const added = dayMonth(p?.createdAt);
  const where = p?.rpId && p.rpId !== PROD_RP_ID ? ` on ${p.rpId}` : "";
  return `Added ${added}${where} · used ${usedText(p?.lastUsedAt, nowMs)}`;
}

// passkeyLabel is a passkey's name in the list, or a plain word.
export function passkeyLabel(p) {
  return typeof p?.label === "string" && p.label !== "" ? p.label : "Unnamed passkey";
}

// revokeLines is what the page says before it removes p from passkeys.
export function revokeLines(p, passkeys) {
  const lines = [`This removes the passkey ${passkeyLabel(p)}, added ${dayMonth(p?.createdAt)}. It can no longer approve writes or sign undos.`];
  const others = activePasskeys(passkeys).filter((k) => k.credentialId !== p?.credentialId && k.rpId === PROD_RP_ID);
  if (p?.rpId === PROD_RP_ID && others.length === 0) {
    lines.push("It is the last passkey for this site: until you add one, your agents' held writes and undos wait.");
  }
  return lines;
}

// ADD_AGAIN is the add screen after the last portal passkey went.
export const ADD_AGAIN = "Add a passkey so your agents can be approved again.";

// pinView is the trust step for a code that carries the bot's pin
// (CONTRACT.md, The bot's pin): "MATCH" when the database presents the
// certificate the bot trusts, "CHANGED" with both fingerprints when it
// presents another, null without a readable pin (the plain question).
export function pinView(trustPin, asking) {
  if (typeof trustPin !== "string" || !SHA256_HEX.test(trustPin) || !asking) return null;
  if (asking.sha256 === trustPin) return { state: "MATCH", fingerprint: fingerprintText(asking.sha256) };
  return {
    state: "CHANGED",
    now: fingerprintText(asking.sha256),
    was: fingerprintText(trustPin),
    detail: `${asking.subject}, valid until ${asking.expiresAt.slice(0, 10)}`,
  };
}

// signalRemoved tells the browser a removed portal passkey is gone
// (PublicKeyCredential.signalUnknownCredential, feature-detected), as the
// local page does for its own. A browser without it does nothing; it never
// throws.
export async function signalRemoved(pkc, p) {
  if (p?.rpId !== PROD_RP_ID || typeof pkc?.signalUnknownCredential !== "function") return false;
  try {
    await pkc.signalUnknownCredential({ rpId: PROD_RP_ID, credentialId: p.credentialId });
    return true;
  } catch {
    return false;
  }
}

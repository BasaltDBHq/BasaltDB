// The connect page's Update check (CONTRACT.md, Update on the connect
// page): what the check screen, the passkey list and the bot's pin show,
// from CheckSetup's answer for a code with a target. Pure functions only:
// the page wires them in connect.js. The words are the local setup page's
// (CONTRACT.md, The Update check), with the portal's passkeys in place of
// this computer's.
import { PROD_RP_ID } from "./codec.js";
import { ALL_GOOD, devicesText, NO_PASSKEY, needTitle, unlabeledRow } from "./doctor.js";
import { tableName } from "./picks.js";

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
  const devices = devicesText(portal);
  const rows = [];
  if (cols.length > 0) {
    rows.push({ kind: "LABELS", mark: "warn", action: "Label", ...unlabeledRow(cols.length, cols.map((c) => `${tableName(c.table)}.${c.column}`)) });
  }
  if (portal === 0) rows.push({ kind: "PASSKEY_ADD", mark: "warn", action: "Add", ...NO_PASSKEY });
  const needs = rows.length;
  const passkeysRow = { kind: "PASSKEYS", mark: "good", title: "Passkeys", text: devices, action: "Manage" };
  if (needs === 0) {
    const [labelsOk, certOk] = ALL_GOOD.rows;
    return {
      needs,
      title: ALL_GOOD.title,
      sub: ALL_GOOD.sub,
      rows: [
        { kind: "LABELS_OK", mark: "good", title: labelsOk, text: "", action: "" },
        { kind: "CERTIFICATE_OK", mark: "good", title: certOk, text: "", action: "" },
        passkeysRow,
      ],
      button: "Continue",
    };
  }
  if (portal > 0) rows.push(passkeysRow);
  return { needs, title: needTitle(needs), sub: "Everything else is working.", rows, button: "Fix these" };
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

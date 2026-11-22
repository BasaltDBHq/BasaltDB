// Runs with `node --test web/lib/*.test.mjs` (make web-check). The confirm
// step both setup pages share, "Is this your database?" (CONTRACT.md, The
// install of a real database, The connect page, The Update check).
import { test } from "node:test";
import assert from "node:assert/strict";

import { certificateLine, confirmView, nameOf, paintConfirm, stringFacts } from "./confirm.js";

const FACTS = { database: "shop_db", host: "db.acme.internal", port: 5432, user: "postgres" };
const CLOUD_SQL = "CN=Google Cloud SQL Server CA,O=Google\\, Inc,C=US,2.5.4.46=#130131";
const ASKING = { subject: CLOUD_SQL, sha256: "ab".repeat(32), expiresAt: "2035-01-31T00:00:00Z" };
const FP = Array(32).fill("AB").join(":");
const facts = (v) => v.rows.map((r) => `${r.label}: ${r.value}`);

test("an authority's short name: its common name, else its organization, else the subject", () => {
  assert.equal(nameOf(CLOUD_SQL), "Google Cloud SQL Server CA");
  assert.equal(nameOf("O=Acme\\, Inc,C=US"), "Acme, Inc");
  assert.equal(nameOf("CN=a\\+b+OU=x"), "a+b");
  assert.equal(nameOf("C=US"), "C=US");
  assert.equal(nameOf(""), "");
});

// pw is a connection string with a sample password, split so no scanner
// takes it for a real one.
const pw = (scheme, user, rest) => [`${scheme}://${user}`, rest].join(":");

test("what the string names, read on the page, never its password", () => {
  assert.deepEqual(stringFacts(pw("postgresql", "postgres", "s3cret@db.acme.internal:6543/shop_db?sslmode=require")), { database: "shop_db", host: "db.acme.internal", port: 6543, user: "postgres" });
  assert.deepEqual(stringFacts(pw("postgres", "admin", "pw@[2001:db8::1]/app")), { database: "app", host: "2001:db8::1", port: 5432, user: "admin" });
  assert.deepEqual(stringFacts(pw("postgres", "u%40x", "pw@h/")), { database: "u@x", host: "h", port: 5432, user: "u@x" }, "no database: the user's, as Postgres does");
  assert.deepEqual(stringFacts("postgres://pw@h/d?user=bob&dbname=other&host=h2&port=1"), { database: "other", host: "h2", port: 1, user: "bob" });
  assert.equal(stringFacts("not a url"), null);
  assert.ok(!JSON.stringify(stringFacts(pw("postgres", "a", "s3cret@h/d"))).includes("s3cret"));
});

test("the certificate line by kind: ✓ only for an authority that verified it", () => {
  assert.deepEqual(certificateLine({ kind: "PUBLIC", issuer: "ISRG Root X1" }), { text: "✓ Verified by ISRG Root X1", tone: "same" });
  assert.deepEqual(certificateLine({ kind: "PROVIDER", issuer: "Amazon RDS" }), { text: "✓ Verified by Amazon RDS", tone: "same" });
  assert.deepEqual(certificateLine({ kind: "OWN", issuer: "Google Cloud SQL Server CA" }), { text: "Google Cloud SQL Server CA", tone: "" });
  for (const kind of ["NOT_VERIFIED", "NONE", "WHATEVER"]) {
    const l = certificateLine({ kind, issuer: "Looks Legit CA" });
    assert.equal(l.tone, "diff", kind);
    assert.ok(!l.text.startsWith("✓"), kind);
    assert.ok(!l.text.includes("Looks Legit"), "an unchecked issuer is not named");
  }
  assert.equal(certificateLine(null).tone, "diff");
});

test("a public authority: Is this your database?, Yes, this is it, and nothing to trust", () => {
  const v = confirmView({ facts: FACTS, certificate: { kind: "PROVIDER", issuer: "Amazon RDS" } });
  assert.equal(v.variant, "VERIFIED");
  assert.equal(v.title, "Is this your database?");
  assert.equal(v.sub, "Check these, then continue.");
  assert.deepEqual(facts(v), ["Database: shop_db", "Host: db.acme.internal:5432", "Signed in as: postgres", "Certificate: ✓ Verified by Amazon RDS"]);
  assert.equal(v.go, "Yes, this is it");
  assert.equal(v.back, "No, go back");
  assert.equal(v.trusts, false);
  assert.equal(v.fingerprint, "");
});

test("the provider's own authority: the same step, whose Yes also trusts it; the fingerprint under Details", () => {
  const v = confirmView({ facts: FACTS, asking: ASKING });
  assert.equal(v.variant, "OWN");
  assert.equal(v.title, "Is this your database?");
  assert.equal(v.sub, "Check these, then continue. Your provider signs its own security certificate, so confirming also trusts it for this database only.");
  assert.equal(v.rows[3].value, "Google Cloud SQL Server CA");
  assert.equal(v.fingerprint, `SHA-256: ${FP}`);
  assert.equal(v.trusts, true);
  assert.equal(v.ok, "");
});

test("the bot's pin matches: ✓ Matches what <bot> trusts, still a click", () => {
  const v = confirmView({ facts: FACTS, asking: ASKING, trustPin: "ab".repeat(32), bot: "familite-bot" });
  assert.equal(v.variant, "MATCH");
  assert.equal(v.ok, "✓ Matches what familite-bot trusts");
  assert.equal(v.sub, "Check these, then continue.");
  assert.equal(v.go, "Yes, this is it");
  assert.equal(v.trusts, true);
  for (const bad of ["", "AB".repeat(32), "ab".repeat(31), undefined]) assert.equal(confirmView({ facts: FACTS, asking: ASKING, trustPin: bad }).variant, "OWN", String(bad));
});

test("renewed by the same issuer: Is this still your database?", () => {
  const v = confirmView({ facts: FACTS, asking: ASKING, renewal: { pinnedSubject: "CN=Google Cloud SQL Server CA,O=Google\\, Inc,C=US,2.5.4.46=#130132" }, trustPin: "cd".repeat(32) });
  assert.equal(v.variant, "RENEWED", "the name, not the whole subject: a provider's renewal changes its serial attributes");
  assert.equal(v.title, "Is this still your database?");
  assert.equal(v.sub, "Providers renew certificates about once a year.");
  assert.equal(v.ok, "✓ Same issuer as before");
  assert.equal(v.go, "Yes, trust the new certificate");
  assert.equal(v.weak, false);
  assert.equal(v.back, "Not expecting this? Stop here");
  assert.equal(v.trusts, true);
});

test("a new issuer, or one not known: the cautious words and the weaker button", () => {
  const v = confirmView({ facts: FACTS, asking: { ...ASKING, subject: "CN=Unknown Org CA" }, renewal: { pinnedSubject: CLOUD_SQL }, trustPin: "cd".repeat(32) });
  assert.equal(v.variant, "NEW_ISSUER");
  assert.equal(v.title, "Is this still your database?");
  assert.equal(v.sub, "The certificate now comes from someone new. Check with your provider first. Your agents stay paused.");
  assert.deepEqual(v.rows[3], { label: "Certificate", value: "Unknown Org CA", tone: "diff" });
  assert.equal(v.before, "Before: Google Cloud SQL Server CA");
  assert.equal(v.go, "Trust it anyway");
  assert.equal(v.weak, true);
  assert.equal(v.back, "Stop here");
  assert.equal(v.ok, "");
  // The connect page's code carries the pin, not its issuer: never "Same issuer".
  const portal = confirmView({ facts: FACTS, asking: ASKING, trustPin: "cd".repeat(32) });
  assert.equal(portal.variant, "NEW_ISSUER");
  assert.equal(portal.before, `Before: SHA-256 ${Array(32).fill("CD").join(":")}`);
  assert.equal(confirmView({ facts: FACTS, asking: ASKING, renewal: { pinnedSubject: "" } }).before, "");
});

// A document of plain nodes, as the pages' tests build them.
function doc() {
  const make = (tag) => ({ tagName: tag, children: [], hidden: false, className: "", _t: "",
    get textContent() { return this._t + this.children.map((c) => c.textContent).join(""); },
    set textContent(v) { this.children = []; this._t = String(v); },
    appendChild(c) { this.children.push(c); return c; } });
  const ids = ["confirm-title", "confirm-sub", "confirm-facts", "confirm-ok", "confirm-before", "confirm-go", "confirm-back", "confirm-details", "confirm-fp"];
  const nodes = Object.fromEntries(ids.map((id) => [id, make("p")]));
  return { nodes, getElementById: (id) => nodes[id], createElement: make };
}

test("the painter sets every value as text and shows only what the step has", () => {
  const d = doc();
  paintConfirm(d, confirmView({ facts: { ...FACTS, database: "<b>x</b>" }, asking: ASKING }));
  assert.equal(d.nodes["confirm-facts"].children.length, 4);
  assert.equal(d.nodes["confirm-facts"].children[0].children[1].textContent, "<b>x</b>");
  assert.equal(d.nodes["confirm-details"].hidden, false);
  assert.equal(d.nodes["confirm-fp"].textContent, `SHA-256: ${FP}`);
  assert.equal(d.nodes["confirm-ok"].hidden, true);
  assert.equal(d.nodes["confirm-go"].className, "");
  paintConfirm(d, confirmView({ facts: FACTS, certificate: { kind: "PUBLIC", issuer: "R" } }));
  assert.equal(d.nodes["confirm-facts"].children.length, 4, "painted again, not added to");
  assert.equal(d.nodes["confirm-details"].hidden, true);
});

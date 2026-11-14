// The portal manifest: "sha256  path" for every file the engine embeds and
// the portal serves (web/embed.go), sorted by path.
//
//   node scripts/web-manifest.mjs --write   rewrite web/portal.sha256
//   node scripts/web-manifest.mjs --check   fail when it is out of date
//
// Run after scripts/web-sri.mjs: the pages carry the integrity hashes.
import { createHash } from "node:crypto";
import { readdirSync, readFileSync, writeFileSync, existsSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..", "web");
const out = join(root, "portal.sha256");

const files = [
  ...["approve", "revert", "register", "passkeys", "engines"].map((d) => `${d}/index.html`),
  ...readdirSync(join(root, "lib")).filter((f) => f.endsWith(".js")).map((f) => `lib/${f}`),
  "style.css",
  ...readdirSync(join(root, "fonts")).filter((f) => f.endsWith(".woff2") || f === "OFL.txt").map((f) => `fonts/${f}`),
].sort();

const text = files
  .map((p) => `${createHash("sha256").update(readFileSync(join(root, p))).digest("hex")}  ${p}\n`)
  .join("");

const mode = process.argv[2];
if (mode === "--write") writeFileSync(out, text);
else if (mode === "--check") {
  if (!existsSync(out) || readFileSync(out, "utf8") !== text) {
    console.error("web/portal.sha256 is out of date; run: make web-sri");
    process.exit(1);
  }
} else {
  console.error("usage: web-manifest.mjs --write | --check");
  process.exit(2);
}

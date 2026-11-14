// The portal manifest: "sha256  path" for every file the engine embeds and
// the portal serves (web/embed.go), sorted by path.
//
//   node scripts/web-manifest.mjs --write [webdir]   rewrite web/portal.sha256
//   node scripts/web-manifest.mjs --check [webdir]   fail when it is out of date
//
// Run after scripts/web-sri.mjs: the pages carry the integrity hashes.
import { createHash } from "node:crypto";
import { readFileSync, writeFileSync, existsSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { embedded } from "./web-sri.mjs";

const root = resolve(process.argv[3] ?? join(dirname(fileURLToPath(import.meta.url)), "..", "web"));
const out = join(root, "portal.sha256");

// The file list is the //go:embed line of web/embed.go, the same set the
// engine serves, so the two cannot drift.
const files = [...embedded(root)].sort();

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
  console.error("usage: web-manifest.mjs --write | --check [webdir]");
  process.exit(2);
}

// node --test scripts/web-sri.test.mjs (run by make web-check)
import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { cpSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { run } from "./web-sri.mjs";

const web = join(dirname(fileURLToPath(import.meta.url)), "..", "web");
const sri = (b) => "sha384-" + createHash("sha384").update(b).digest("base64");

// check copies web/ to a temp dir, lets edit change the approve page, and
// returns the exit code of --check and what it printed.
function check(edit) {
  const root = mkdtempSync(join(tmpdir(), "web-sri-"));
  const logged = [];
  const orig = console.error;
  try {
    cpSync(web, root, { recursive: true });
    const page = join(root, "approve", "index.html");
    writeFileSync(page, edit(readFileSync(page, "utf8"), root));
    console.error = (m) => logged.push(String(m));
    return { code: run("--check", root), out: logged.join("\n") };
  } finally {
    console.error = orig;
    rmSync(root, { recursive: true, force: true });
  }
}

const notEmbedded = (root) =>
  `<script type="module" src="../portal.sha256" integrity="${sri(readFileSync(join(root, "portal.sha256")))}"></script>`;

test("the pages as committed pass", () => {
  assert.deepEqual(check((h) => h), { code: 0, out: "" });
});

test("a script naming a file that is not embedded fails, after the sri block", () => {
  const r = check((h, root) => h.replace("<!-- sri:end -->", "<!-- sri:end -->\n  " + notEmbedded(root)));
  assert.equal(r.code, 1);
  assert.match(r.out, /\.\.\/portal\.sha256 is not an embedded file/);
});

test("a script naming a file that is not embedded fails, before the sri block", () => {
  const r = check((h, root) => h.replace("<!-- sri:begin", notEmbedded(root) + "\n  <!-- sri:begin"));
  assert.equal(r.code, 1);
  assert.match(r.out, /is not an embedded file/);
});

test("a modulepreload naming a file that is not embedded fails", () => {
  const r = check((h, root) => h.replace("<!-- sri:begin",
    `<link rel="modulepreload" href="../portal.sha256" integrity="${sri(readFileSync(join(root, "portal.sha256")))}">\n  <!-- sri:begin`));
  assert.equal(r.code, 1);
  assert.match(r.out, /is not an embedded file/);
});

test("a reference outside web/ or to another origin fails", () => {
  let r = check((h) => h.replace("<!-- sri:end -->", '<!-- sri:end -->\n  <script type="module" src="../../go.mod" integrity="sha384-AAAA"></script>'));
  assert.equal(r.code, 1);
  assert.match(r.out, /leaves the embedded files/);
  r = check((h) => h.replace("<!-- sri:end -->", '<!-- sri:end -->\n  <script type="module" src="https://example.com/x.js" integrity="sha384-AAAA"></script>'));
  assert.equal(r.code, 1);
  assert.match(r.out, /not relative/);
});

test("a script after the sri block without integrity, or with a stale hash, fails", () => {
  let r = check((h) => h.replace("<!-- sri:end -->", '<!-- sri:end -->\n  <script type="module" src="../lib/approve.js"></script>'));
  assert.equal(r.code, 1);
  assert.match(r.out, /not in a checked form/);
  r = check((h) => h.replace("<!-- sri:end -->", '<!-- sri:end -->\n  <script type="module" src="../lib/approve.js" integrity="sha384-AAAA"></script>'));
  assert.equal(r.code, 1);
  assert.match(r.out, /stale integrity/);
});

test("a decoy attribute cannot point the check at another file", () => {
  const decoys = [
    (h, root) => `<script type="module" data-src="../lib/approve.js" data-integrity="${sri(readFileSync(join(root, "lib", "approve.js")))}" src="../portal.sha256" integrity="${sri(readFileSync(join(root, "portal.sha256")))}"></script>`,
    (h, root) => `<script type="module" title='src="../lib/approve.js" integrity="${sri(readFileSync(join(root, "lib", "approve.js")))}"' src="../portal.sha256" integrity="${sri(readFileSync(join(root, "portal.sha256")))}"></script>`,
    (h, root) => `<SCRIPT type="module" src="../portal.sha256" integrity="${sri(readFileSync(join(root, "portal.sha256")))}"></SCRIPT>`,
    () => `<link rel="module&#112;reload" href="../portal.sha256">`,
  ];
  for (const tag of decoys) {
    const r = check((h, root) => h.replace("<!-- sri:end -->", "<!-- sri:end -->\n  " + tag(h, root)));
    assert.equal(r.code, 1);
    assert.match(r.out, /not in a checked form/);
  }
});

test("a stylesheet naming a file that is not embedded fails", () => {
  const r = check((h) => h.replace('href="../style.css"', 'href="../portal.sha256"'));
  assert.equal(r.code, 1);
  assert.match(r.out, /is not an embedded file/);
});

test("a modulepreload after the script fails", () => {
  const r = check((h, root) => h.replace("<!-- sri:end -->", `<!-- sri:end -->\n  <link rel="modulepreload" href="../lib/approve.js" integrity="${sri(readFileSync(join(root, "lib", "approve.js")))}">`));
  assert.equal(r.code, 1);
  assert.match(r.out, /after the module script/);
});

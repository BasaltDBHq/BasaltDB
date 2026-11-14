// Runs with `node --test web/lib/*.test.mjs` (make web-check): the request
// file and pasted blocks of a hash link, against the shared vectors the Go
// reference and the engine run too (api/mcp/links/request-file.json).
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import { BlockAssembler, readRequestFile, requestHash } from "./requestfile.js";

const vectors = JSON.parse(
  readFileSync(new URL("../../api/mcp/links/request-file.json", import.meta.url), "utf8"),
);

test("h of every vector's request text", async () => {
  for (const v of vectors.vectors) {
    assert.equal(await requestHash(v.text), v.h, v.name);
    assert.ok(v.link.endsWith(`#h=${v.h}`), v.name);
  }
});

test("pasted blocks rebuild the request, or say why not", async () => {
  for (const c of vectors.pastes) {
    const a = new BlockAssembler(vectors.vectors[c.vector].h);
    const refused = [];
    c.pastes.forEach((p, i) => {
      if (a.add(p).length > 0) refused.push(i);
    });
    assert.deepEqual(refused, c.refused ?? [], c.name);
    const got = await a.text();
    if (c.error) assert.deepEqual(got, { error: c.error }, c.name);
    else assert.deepEqual(got, { text: c.text }, c.name);
  }
});

test("each vector's own blocks, shuffled, rebuild it", async () => {
  for (const v of vectors.vectors) {
    if (!v.blocks) continue;
    const a = new BlockAssembler(v.h);
    for (const b of [...v.blocks].reverse()) assert.deepEqual(a.add(b), [], v.name);
    assert.deepEqual(a.missing(), [], v.name);
    assert.deepEqual(await a.text(), { text: v.text }, v.name);
  }
});

test("a file is read against the link's h", async () => {
  for (const c of vectors.files) {
    const got = await readRequestFile(c.file, vectors.vectors[c.vector].h);
    if (c.error) assert.deepEqual(got, { error: c.error }, c.name);
    else assert.deepEqual(got, { text: c.text }, c.name);
  }
});

test("missing names the blocks still to paste", () => {
  const v = vectors.vectors.find((x) => x.blocks && x.blocks.length === 3);
  const a = new BlockAssembler(v.h);
  assert.deepEqual(a.missing(), []);
  a.add(v.blocks[1]);
  assert.deepEqual(a.missing(), [1, 3]);
});

import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { test } from "node:test";
import { buildReceipt } from "../dist/receipt.js";

const golden = JSON.parse(
  await readFile(new URL("../schema/golden-vectors.v1.json", import.meta.url), "utf8"),
).vectors[0];

test("fixed receipt vector is byte-stable across operating systems", () => {
  const receipt = buildReceipt(golden.seed, golden.result, golden.finalizedAt);
  assert.deepEqual(receipt, golden.receipt);
});

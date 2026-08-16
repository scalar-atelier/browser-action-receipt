import assert from "node:assert/strict";
import { test } from "node:test";
import {
  executePreparedAction,
  sha256Hex,
} from "../dist/index.js";
import {
  StableAdapter,
  approved,
  prepared,
  secondsAfter,
  temporaryLedger,
} from "./helpers.mjs";

test("receipt excludes source, input, URL, and raw-error canaries", async (t) => {
  const ledger = await temporaryLedger(t);
  const handle = prepared({ operationId: "00000000-0000-4000-8000-000000000040" });
  const outcome = await executePreparedAction({
    prepared: handle,
    decision: approved(handle),
    adapter: new StableAdapter(),
    ledger,
    now: secondsAfter(2),
    capture: async () => ({
      artifactRef: "fixture.capture.privacy",
      contentHash: sha256Hex("captured-output-not-source"),
    }),
  });
  assert.equal(outcome.kind, "recorded");
  const serialized = JSON.stringify(outcome.receipt);
  for (const canary of [
    "fixture-secret-input",
    "token=never-store",
    "fragment",
    "/account",
    "button|submit|Publish",
    "ref-sensitive-canary-7f5f1f0d",
    "Publish the selected draft",
    "This will submit the draft to example.test",
  ]) {
    assert.equal(serialized.includes(canary), false, `receipt leaked ${canary}`);
  }
});

test("unsafe capture references become a redacted capture failure", async (t) => {
  const ledger = await temporaryLedger(t);
  const handle = prepared({ operationId: "00000000-0000-4000-8000-000000000041" });
  const outcome = await executePreparedAction({
    prepared: handle,
    decision: approved(handle),
    adapter: new StableAdapter(),
    ledger,
    now: secondsAfter(2),
    capture: async () => ({
      artifactRef: "https://example.test/private?token=leak",
      contentHash: sha256Hex("result"),
    }),
  });
  assert.equal(outcome.kind, "recorded");
  assert.equal(outcome.receipt.result.status, "committed");
  assert.equal(outcome.receipt.result.evidenceStatus, "capture_failed");
  assert.equal(JSON.stringify(outcome.receipt).includes("example.test/private"), false);
});

test("safe-alphabet capture references are hashed before persistence", async (t) => {
  const ledger = await temporaryLedger(t);
  const handle = prepared({ operationId: "00000000-0000-4000-8000-000000000042" });
  const rawReference = "oauth_token_supersecret";
  const outcome = await executePreparedAction({
    prepared: handle,
    decision: approved(handle),
    adapter: new StableAdapter(),
    ledger,
    now: secondsAfter(2),
    capture: async () => ({ artifactRef: rawReference, contentHash: sha256Hex("result") }),
  });
  assert.equal(outcome.kind, "recorded");
  assert.equal(outcome.receipt.result.artifactRefSha256, sha256Hex(rawReference));
  assert.equal(JSON.stringify(outcome.receipt).includes(rawReference), false);
});

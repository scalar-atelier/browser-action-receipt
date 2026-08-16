import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { fileURLToPath } from "node:url";
import { test } from "node:test";
import {
  ContractError,
  FileReceiptLedger,
  executePreparedAction,
} from "../dist/index.js";
import {
  StableAdapter,
  approved,
  prepared,
  secondsAfter,
  temporaryLedger,
} from "./helpers.mjs";

const execFileAsync = promisify(execFile);

test("concurrent duplicate operation invokes the adapter at most once", async (t) => {
  const ledger = await temporaryLedger(t);
  const handle = prepared({ operationId: "00000000-0000-4000-8000-000000000030" });
  const adapter = new StableAdapter();
  const decision = approved(handle);
  const outcomes = await Promise.all(
    Array.from({ length: 24 }, () =>
      executePreparedAction({ prepared: handle, decision, adapter, ledger, now: secondsAfter(2) }),
    ),
  );
  assert.equal(adapter.calls, 1);
  assert.equal(outcomes.filter((item) => item.kind === "recorded").length, 1);
  assert(outcomes.every((item) => ["recorded", "duplicate_final", "duplicate_in_progress"].includes(item.kind)));
});

test("a sequential duplicate returns the original receipt without invoking a new adapter", async (t) => {
  const ledger = await temporaryLedger(t);
  const handle = prepared({ operationId: "00000000-0000-4000-8000-000000000034" });
  const firstAdapter = new StableAdapter();
  const decision = approved(handle);
  const first = await executePreparedAction({
    prepared: handle,
    decision,
    adapter: firstAdapter,
    ledger,
    now: secondsAfter(2),
  });
  const secondAdapter = new StableAdapter();
  const second = await executePreparedAction({
    prepared: handle,
    decision,
    adapter: secondAdapter,
    ledger,
    now: secondsAfter(2),
  });
  assert.equal(first.kind, "recorded");
  assert.equal(second.kind, "duplicate_final");
  assert.equal(second.receipt.receiptSha256, first.receipt.receiptSha256);
  assert.equal(firstAdapter.calls, 1);
  assert.equal(secondAdapter.calls, 0);
});

test("exclusive claim admits exactly one independent Node process", async (t) => {
  const ledger = await temporaryLedger(t);
  const seedPath = join(ledger.root, "seed.json");
  const seed = {
    schemaVersion: "browser-action-claim/v1",
    operationId: "00000000-0000-4000-8000-000000000033",
    action: "click",
    riskClass: "R1",
    approval: {
      decision: "approved",
      channel: "host",
      decidedAt: "2026-08-16T00:00:00.500Z",
      bindingSha256: "1".repeat(64),
    },
    target: {
      origin: "https://example.test",
      pathnameSha256: "2".repeat(64),
      fingerprintSha256: "3".repeat(64),
      pageGenerationSha256: "4".repeat(64),
    },
    preparedAt: "2026-08-16T00:00:00.000Z",
    claimedAt: "2026-08-16T00:00:01.000Z",
  };
  await writeFile(seedPath, JSON.stringify(seed));
  const worker = fileURLToPath(new URL("./claim-worker.mjs", import.meta.url));
  const results = await Promise.all(
    Array.from({ length: 12 }, () =>
      execFileAsync(process.execPath, [worker, ledger.root, seedPath], { encoding: "utf8" }),
    ),
  );
  assert.equal(results.filter(({ stdout }) => stdout === "claimed").length, 1);
  assert.equal(results.filter(({ stdout }) => stdout === "duplicate_in_progress").length, 11);
});

test("same operation ID with a different bound request is a conflict", async (t) => {
  const ledger = await temporaryLedger(t);
  const operationId = "00000000-0000-4000-8000-000000000035";
  const first = prepared({ operationId, payload: { ref: "first" } });
  const firstAdapter = new StableAdapter();
  const recorded = await executePreparedAction({
    prepared: first,
    decision: approved(first),
    adapter: firstAdapter,
    ledger,
    now: secondsAfter(2),
  });
  const second = prepared({ operationId, payload: { ref: "different" } });
  const secondAdapter = new StableAdapter();
  const conflict = await executePreparedAction({
    prepared: second,
    decision: approved(second),
    adapter: secondAdapter,
    ledger,
    now: secondsAfter(2),
  });
  assert.equal(recorded.kind, "recorded");
  assert.equal(conflict.kind, "operation_conflict");
  assert.equal(firstAdapter.calls, 1);
  assert.equal(secondAdapter.calls, 0);
});

test("a fabricated claim handle cannot finalize another process claim", async (t) => {
  const ledger = await temporaryLedger(t);
  const seed = {
    schemaVersion: "browser-action-claim/v1",
    operationId: "00000000-0000-4000-8000-000000000036",
    action: "click",
    riskClass: "R2",
    approval: {
      decision: "approved",
      channel: "host",
      decidedAt: "2026-08-16T00:00:01.000Z",
      bindingSha256: "1".repeat(64),
    },
    target: {
      origin: "https://example.test",
      pathnameSha256: "2".repeat(64),
      fingerprintSha256: "3".repeat(64),
      pageGenerationSha256: "4".repeat(64),
    },
    preparedAt: "2026-08-16T00:00:00.000Z",
    claimedAt: "2026-08-16T00:00:01.500Z",
  };
  const claim = await ledger.claim(seed);
  assert.equal(claim.kind, "claimed");
  await assert.rejects(
    () => ledger.finalize({ operationId: seed.operationId }, { status: "committed", errorCode: null }),
    (error) => error instanceof ContractError && error.code === "claim_handle_invalid",
  );
});

test("tampering with a receipt fails validation", async (t) => {
  const ledger = await temporaryLedger(t);
  const handle = prepared({ operationId: "00000000-0000-4000-8000-000000000031" });
  const outcome = await executePreparedAction({
    prepared: handle,
    decision: approved(handle),
    adapter: new StableAdapter(),
    ledger,
    now: secondsAfter(2),
  });
  assert.equal(outcome.kind, "recorded");
  const path = join(ledger.receiptsDirectory, `${handle.operationId}.json`);
  const receipt = JSON.parse(await readFile(path, "utf8"));
  receipt.target.origin = "https://example.org";
  await writeFile(path, JSON.stringify(receipt));
  await assert.rejects(() => ledger.readReceipt(handle.operationId), /Receipt hash does not match/);
});

test("a stale claim recovers as unknown and is never executed", async (t) => {
  const ledger = await temporaryLedger(t);
  const handle = prepared({ operationId: "00000000-0000-4000-8000-000000000032" });
  const adapter = new StableAdapter();
  const originalClaim = ledger.claim.bind(ledger);
  let capturedSeed;
  ledger.claim = async (seed) => {
    capturedSeed = seed;
    return originalClaim(seed);
  };
  const decision = approved(handle);
  const blockingAdapter = {
    capability: "atomic-compare-and-act/v1",
    async compareAndAct() {
      throw new Error("simulate process loss after claim");
    },
  };
  await executePreparedAction({ prepared: handle, decision, adapter: blockingAdapter, ledger, now: secondsAfter(2) });
  await rm(join(ledger.receiptsDirectory, `${handle.operationId}.json`));
  assert(capturedSeed);
  const recovered = await ledger.recoverUnknownClaims(secondsAfter(3));
  assert.equal(recovered.length, 1);
  assert.equal(recovered[0].result.status, "unknown_after_claim");
  assert.equal(adapter.calls, 0);
});

test("symlink ledger root is rejected", async (t) => {
  const parent = await mkdtemp(join(tmpdir(), "browser-action-ledger-link-"));
  t.after(async () => rm(parent, { recursive: true, force: true }));
  const target = join(parent, "target");
  const link = join(parent, "link");
  await new FileReceiptLedger(target).initialize();
  await symlink(target, link, process.platform === "win32" ? "junction" : "dir");
  await assert.rejects(() => new FileReceiptLedger(link).initialize(), ContractError);
});

test("arbitrary operation paths cannot be prepared", () => {
  assert.throws(
    () => prepared({ operationId: "../../escape" }),
    (error) => error instanceof ContractError && error.code === "operation_id_invalid",
  );
});

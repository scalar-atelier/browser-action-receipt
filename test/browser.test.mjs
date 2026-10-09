import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { test } from "node:test";
import {
  BrowserReceiptLedger,
  createTargetObservation,
  executePreparedAction,
  makeApprovalDecision,
  prepareAction,
  verifyReceipt,
} from "../dist/browser.js";

const BASE_TIME = new Date("2026-08-16T00:00:00.000Z");
const golden = JSON.parse(
  await readFile(new URL("../schema/golden-vectors.v1.json", import.meta.url), "utf8"),
).vectors[0];

class MemoryStore {
  claims = new Map();
  receipts = new Map();

  async claim(seed) {
    const existing = this.claims.get(seed.operationId);
    if (existing) {
      const receipt = this.receipts.get(seed.operationId);
      return receipt
        ? { kind: "duplicate_final", receipt }
        : { kind: "duplicate_in_progress", operationId: seed.operationId };
    }
    this.claims.set(seed.operationId, structuredClone(seed));
    return { kind: "claimed" };
  }

  async publish(receipt) {
    const existing = this.receipts.get(receipt.operationId);
    if (existing) return { kind: "duplicate_final", receipt: existing };
    this.receipts.set(receipt.operationId, structuredClone(receipt));
    return { kind: "stored" };
  }
}

async function fixture(operationId) {
  const observation = await createTargetObservation({
    url: "https://example.test/account?token=never-store#fragment",
    targetFingerprint: "button|submit|Publish|https://example.test/publish|",
    pageGeneration: "document-1",
    observedAt: BASE_TIME.toISOString(),
  });
  const prepared = await prepareAction({
    action: "click",
    riskClass: "R2",
    observation,
    payload: { ref: "ref-sensitive-canary-7f5f1f0d", text: "typed-input-canary" },
    approvalDisplay: { title: "Publish", detail: "Publish the selected draft" },
    operationId,
    now: BASE_TIME,
  });
  return { observation, prepared };
}

test("browser entry verifies the same public golden vector as Node", async () => {
  assert.deepEqual(await verifyReceipt(golden.receipt), golden.receipt);
  await assert.rejects(() => verifyReceipt({ ...golden.receipt, rawInput: "must-not-exist" }));
});

test("browser entry commits a stable target once and records a privacy-minimal receipt", async () => {
  const store = new MemoryStore();
  const ledger = new BrowserReceiptLedger(store);
  const { observation, prepared } = await fixture("00000000-0000-4000-8000-000000000201");
  let calls = 0;
  const decision = makeApprovalDecision(prepared.approvalRequest, "approved", {
    now: new Date(BASE_TIME.getTime() + 1_000),
  });
  const input = {
    prepared,
    decision,
    ledger,
    now: new Date(BASE_TIME.getTime() + 2_000),
    adapter: {
      capability: "atomic-compare-and-act/v1",
      async compareAndAct() {
        calls += 1;
        return { status: "committed", observation };
      },
    },
  };
  const first = await executePreparedAction(input);
  const duplicate = await executePreparedAction(input);
  assert.equal(first.receipt.result.status, "committed");
  assert.equal(duplicate.kind, "duplicate_final");
  assert.equal(calls, 1);
  const serialized = JSON.stringify(first.receipt);
  for (const secret of ["token=never-store", "Publish", "ref-sensitive-canary-7f5f1f0d", "typed-input-canary", "/account"]) {
    assert.equal(serialized.includes(secret), false, `receipt leaked ${secret}`);
  }
});

test("browser entry blocks denial and target changes before an external action", async () => {
  const deniedFixture = await fixture("00000000-0000-4000-8000-000000000202");
  let deniedCalls = 0;
  const denied = await executePreparedAction({
    prepared: deniedFixture.prepared,
    decision: makeApprovalDecision(deniedFixture.prepared.approvalRequest, "denied", {
      now: new Date(BASE_TIME.getTime() + 1_000),
    }),
    ledger: new BrowserReceiptLedger(new MemoryStore()),
    now: new Date(BASE_TIME.getTime() + 2_000),
    adapter: {
      capability: "atomic-compare-and-act/v1",
      async compareAndAct() {
        deniedCalls += 1;
        return { status: "committed", observation: deniedFixture.observation };
      },
    },
  });
  assert.equal(denied.receipt.result.status, "blocked");
  assert.equal(deniedCalls, 0);

  const changedFixture = await fixture("00000000-0000-4000-8000-000000000203");
  const changedObservation = await createTargetObservation({
    url: "https://example.test/account",
    targetFingerprint: "button|submit|Changed||",
    pageGeneration: "document-2",
    observedAt: new Date(BASE_TIME.getTime() + 1_500).toISOString(),
  });
  let externalActions = 0;
  const changed = await executePreparedAction({
    prepared: changedFixture.prepared,
    decision: makeApprovalDecision(changedFixture.prepared.approvalRequest, "approved", {
      now: new Date(BASE_TIME.getTime() + 1_000),
    }),
    ledger: new BrowserReceiptLedger(new MemoryStore()),
    now: new Date(BASE_TIME.getTime() + 2_000),
    adapter: {
      capability: "atomic-compare-and-act/v1",
      async compareAndAct() {
        return { status: "target_changed", observation: changedObservation };
      },
    },
  });
  assert.equal(changed.receipt.result.status, "aborted_target_changed");
  assert.equal(externalActions, 0);
});

for (const clockRollback of [false, true]) test(`browser time boundary while claiming blocks the adapter (rollback: ${clockRollback})`, async (t) => {
  t.mock.timers.enable({ apis: ["Date"], now: BASE_TIME.getTime() + 2_000 });
  const { observation, prepared } = await fixture("00000000-0000-4000-8000-000000000204");
  const store = new MemoryStore();
  const claim = store.claim.bind(store);
  store.claim = async (seed) => {
    const result = await claim(seed);
    if (clockRollback) t.mock.timers.setTime(BASE_TIME.getTime() - 1);
    else t.mock.timers.tick(121_000);
    return result;
  };
  let calls = 0;
  const outcome = await executePreparedAction({
    prepared,
    decision: makeApprovalDecision(prepared.approvalRequest, "approved", { now: new Date(BASE_TIME.getTime() + 1_000) }),
    ledger: new BrowserReceiptLedger(store),
    adapter: {
      capability: "atomic-compare-and-act/v1",
      async compareAndAct() { calls++; return { status: "committed", observation }; },
    },
  });
  assert.equal(calls, 0);
  assert.equal(outcome.receipt.result.status, "blocked");
  assert.equal(outcome.receipt.result.errorCode, clockRollback ? "clock_invalid" : "approval_expired");
  assert.equal(outcome.receipt.approval.decision, clockRollback ? "invalid" : "expired");
  assert.deepEqual(await verifyReceipt(outcome.receipt), outcome.receipt);
});

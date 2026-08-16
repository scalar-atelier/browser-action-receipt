import assert from "node:assert/strict";
import { test } from "node:test";
import {
  executePreparedAction,
  makeApprovalDecision,
  prepareAction,
  sha256Hex,
} from "../dist/index.js";
import {
  BASE_TIME,
  ChangedTargetAdapter,
  StableAdapter,
  approved,
  observation,
  prepared,
  secondsAfter,
  temporaryLedger,
} from "./helpers.mjs";

test("stable approved target commits once and captures opaque evidence", async (t) => {
  const ledger = await temporaryLedger(t);
  const handle = prepared();
  const adapter = new StableAdapter();
  const outcome = await executePreparedAction({
    prepared: handle,
    decision: approved(handle),
    adapter,
    ledger,
    now: secondsAfter(2),
    capture: async () => ({ artifactRef: "fixture.capture.1", contentHash: sha256Hex("result") }),
  });
  assert.equal(outcome.kind, "recorded");
  assert.equal(outcome.receipt.result.status, "committed");
  assert.equal(outcome.receipt.result.evidenceStatus, "captured");
  assert.equal(outcome.receipt.result.artifactRefSha256, sha256Hex("fixture.capture.1"));
  assert.equal(JSON.stringify(outcome.receipt).includes("fixture.capture.1"), false);
  assert.equal(adapter.calls, 1);
});

test("even an R1 DOM mutation requires an approval decision", async (t) => {
  const ledger = await temporaryLedger(t);
  const handle = prepared({
    riskClass: "R1",
    operationId: "00000000-0000-4000-8000-000000000002",
  });
  const adapter = new StableAdapter();
  const outcome = await executePreparedAction({ prepared: handle, adapter, ledger, now: secondsAfter(2) });
  assert.equal(outcome.kind, "recorded");
  assert.equal(outcome.receipt.approval.decision, "invalid");
  assert.equal(outcome.receipt.result.status, "blocked");
  assert.equal(adapter.calls, 0);
});

test("changed target aborts without invoking the adapter action", async (t) => {
  const ledger = await temporaryLedger(t);
  const handle = prepared({ operationId: "00000000-0000-4000-8000-000000000003" });
  const adapter = new ChangedTargetAdapter();
  const outcome = await executePreparedAction({
    prepared: handle,
    decision: approved(handle),
    adapter,
    ledger,
    now: secondsAfter(2),
  });
  assert.equal(outcome.kind, "recorded");
  assert.equal(outcome.receipt.result.status, "aborted_target_changed");
  assert.equal(adapter.externalActions, 0);
});

for (const scenario of ["missing", "denied", "expired", "wrong_binding"]) {
  test(`${scenario} approval is blocked before adapter invocation`, async (t) => {
    const ledger = await temporaryLedger(t);
    const handle = prepared({
      operationId: {
        missing: "00000000-0000-4000-8000-000000000010",
        denied: "00000000-0000-4000-8000-000000000011",
        expired: "00000000-0000-4000-8000-000000000012",
        wrong_binding: "00000000-0000-4000-8000-000000000013",
      }[scenario],
    });
    const adapter = new StableAdapter();
    let decision;
    let now = secondsAfter(2);
    if (scenario === "denied") {
      decision = makeApprovalDecision(handle.approvalRequest, "denied", { now: secondsAfter(1) });
    } else if (scenario === "expired") {
      decision = approved(handle);
      now = new Date(BASE_TIME.getTime() + 121_000);
    } else if (scenario === "wrong_binding") {
      decision = { ...approved(handle), bindingSha256: "0".repeat(64) };
    }
    const outcome = await executePreparedAction({ prepared: handle, decision, adapter, ledger, now });
    assert.equal(outcome.kind, "recorded");
    assert.equal(outcome.receipt.result.status, "blocked");
    assert.equal(adapter.calls, 0);
  });
}

test("payload mutation after prepare does not change the executed payload", async (t) => {
  const ledger = await temporaryLedger(t);
  const sourcePayload = { ref: "b1", nested: { value: "original" } };
  const handle = prepareAction({
    action: "click",
    riskClass: "R2",
    observation: observation(),
    payload: sourcePayload,
    approvalDisplay: { title: "Publish", detail: "Publish the selected draft" },
    operationId: "00000000-0000-4000-8000-000000000020",
    now: BASE_TIME,
  });
  sourcePayload.nested.value = "mutated";
  const adapter = new StableAdapter();
  await executePreparedAction({
    prepared: handle,
    decision: approved(handle),
    adapter,
    ledger,
    now: secondsAfter(2),
  });
  assert.deepEqual(adapter.payloads, [{ ref: "b1", nested: { value: "original" } }]);
  assert(Object.isFrozen(adapter.payloads[0]));
  assert(Object.isFrozen(adapter.payloads[0].nested));
});

test("a contradictory committed observation is an adapter contract violation", async (t) => {
  const ledger = await temporaryLedger(t);
  const handle = prepared({ operationId: "00000000-0000-4000-8000-000000000021" });
  const adapter = {
    capability: "atomic-compare-and-act/v1",
    async compareAndAct() {
      return {
        status: "committed",
        observation: observation({ targetFingerprint: "different" }),
      };
    },
  };
  const outcome = await executePreparedAction({
    prepared: handle,
    decision: approved(handle),
    adapter,
    ledger,
    now: secondsAfter(2),
  });
  assert.equal(outcome.kind, "recorded");
  assert.equal(outcome.receipt.result.status, "unknown_after_adapter");
  assert.equal(outcome.receipt.result.errorCode, "adapter_contract_violation");
});

for (const [label, compareAndAct] of [
  ["throwing", async () => { throw new Error("side effect may already exist"); }],
  ["malformed", async () => null],
  ["claimed failure", async () => ({ status: "failed", errorCode: "oauth_token_supersecret" })],
]) {
  test(`${label} adapter result is recorded as unknown, not failed`, async (t) => {
    const ledger = await temporaryLedger(t);
    const handle = prepared({
      operationId: {
        throwing: "00000000-0000-4000-8000-000000000023",
        malformed: "00000000-0000-4000-8000-000000000024",
        "claimed failure": "00000000-0000-4000-8000-000000000026",
      }[label],
    });
    const outcome = await executePreparedAction({
      prepared: handle,
      decision: approved(handle),
      adapter: { capability: "atomic-compare-and-act/v1", compareAndAct },
      ledger,
      now: secondsAfter(2),
    });
    assert.equal(outcome.kind, "recorded");
    assert.equal(outcome.receipt.result.status, "unknown_after_adapter");
    assert.equal(JSON.stringify(outcome.receipt).includes("side effect may already exist"), false);
    assert.equal(JSON.stringify(outcome.receipt).includes("oauth_token_supersecret"), false);
  });
}

test("clock rollback blocks before adapter invocation", async (t) => {
  const ledger = await temporaryLedger(t);
  const handle = prepared({ operationId: "00000000-0000-4000-8000-000000000025" });
  const adapter = new StableAdapter();
  const outcome = await executePreparedAction({
    prepared: handle,
    decision: approved(handle),
    adapter,
    ledger,
    now: new Date(BASE_TIME.getTime() - 1),
  });
  assert.equal(outcome.kind, "recorded");
  assert.equal(outcome.receipt.result.status, "blocked");
  assert.equal(outcome.receipt.result.errorCode, "clock_invalid");
  assert.equal(adapter.calls, 0);
});

test("capture failure does not rewrite a committed action as failed", async (t) => {
  const ledger = await temporaryLedger(t);
  const handle = prepared({ operationId: "00000000-0000-4000-8000-000000000022" });
  const outcome = await executePreparedAction({
    prepared: handle,
    decision: approved(handle),
    adapter: new StableAdapter(),
    ledger,
    now: secondsAfter(2),
    capture: async () => {
      throw new Error("raw capture exception must not persist");
    },
  });
  assert.equal(outcome.kind, "recorded");
  assert.equal(outcome.receipt.result.status, "committed");
  assert.equal(outcome.receipt.result.evidenceStatus, "capture_failed");
  assert.equal(outcome.receipt.result.evidenceErrorCode, "capture_failed");
  assert.equal(JSON.stringify(outcome.receipt).includes("raw capture"), false);
});

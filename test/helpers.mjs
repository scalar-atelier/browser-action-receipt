import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  FileReceiptLedger,
  createTargetObservation,
  makeApprovalDecision,
  prepareAction,
} from "../dist/index.js";

export const BASE_TIME = new Date("2026-08-16T00:00:00.000Z");

export function secondsAfter(seconds) {
  return new Date(BASE_TIME.getTime() + seconds * 1000);
}

export function observation(overrides = {}) {
  return createTargetObservation({
    url: "https://example.test/account?token=never-store#fragment",
    targetFingerprint: "button|submit|Publish|/submit",
    pageGeneration: "document-1",
    observedAt: BASE_TIME.toISOString(),
    ...overrides,
  });
}

export function prepared(options = {}) {
  return prepareAction({
    action: "click",
    riskClass: "R2",
    observation: observation(),
    payload: { ref: "ref-sensitive-canary-7f5f1f0d", text: "fixture-secret-input" },
    approvalDisplay: {
      title: "Publish the selected draft",
      detail: "This will submit the draft to example.test",
    },
    operationId: "00000000-0000-4000-8000-000000000001",
    now: BASE_TIME,
    ...options,
  });
}

export function approved(handle, now = secondsAfter(1)) {
  return makeApprovalDecision(handle.approvalRequest, "approved", { now });
}

export async function temporaryLedger(t) {
  const root = await mkdtemp(join(tmpdir(), "browser-action-receipt-"));
  t.after(async () => rm(root, { recursive: true, force: true }));
  return new FileReceiptLedger(root);
}

export class StableAdapter {
  capability = "atomic-compare-and-act/v1";
  calls = 0;
  payloads = [];

  async compareAndAct(input) {
    this.calls += 1;
    this.payloads.push(input.payload);
    return { status: "committed", observation: input.expected };
  }
}

export class ChangedTargetAdapter {
  capability = "atomic-compare-and-act/v1";
  calls = 0;
  externalActions = 0;

  async compareAndAct(input) {
    this.calls += 1;
    const current = observation({
      targetFingerprint: "button|submit|Delete everything|/destroy",
      observedAt: secondsAfter(2).toISOString(),
    });
    if (current.targetFingerprintSha256 !== input.expected.targetFingerprintSha256) {
      return { status: "target_changed", observation: current };
    }
    this.externalActions += 1;
    return { status: "committed", observation: current };
  }
}

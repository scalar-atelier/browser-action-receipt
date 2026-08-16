import assert from "node:assert/strict";
import { test } from "node:test";
import { buildReceipt } from "../dist/receipt.js";

test("fixed receipt vector is byte-stable across operating systems", () => {
  const receipt = buildReceipt(
    {
      schemaVersion: "browser-action-claim/v1",
      operationId: "00000000-0000-4000-8000-000000000099",
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
    },
    {
      status: "committed",
      errorCode: null,
      artifactRefSha256: "5".repeat(64),
      contentHash: "6".repeat(64),
      evidenceStatus: "captured",
    },
    "2026-08-16T00:00:02.000Z",
  );
  assert.equal(receipt.receiptSha256, "09e047a8cdb81c854b7a79ed8ae503e2e904ed9b86072f2c340418ff907793ea");
});

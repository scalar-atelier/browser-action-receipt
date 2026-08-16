import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { test } from "node:test";
import Ajv2020 from "ajv/dist/2020.js";
import { buildReceipt } from "../dist/receipt.js";

const schema = JSON.parse(
  await readFile(new URL("../schema/browser-action-receipt.v1.schema.json", import.meta.url), "utf8"),
);
const validate = new Ajv2020({ strict: true, allErrors: true }).compile(schema);

function fixtureReceipt() {
  return buildReceipt(
    {
      schemaVersion: "browser-action-claim/v1",
      operationId: "00000000-0000-4000-8000-000000000098",
      action: "submit",
      riskClass: "R3",
      approval: {
        decision: "approved",
        channel: "native",
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
    { status: "committed", errorCode: null },
    "2026-08-16T00:00:02.000Z",
  );
}

test("public JSON schema accepts a runtime receipt", () => {
  const receipt = fixtureReceipt();
  assert.equal(validate(receipt), true, JSON.stringify(validate.errors));
});

test("public JSON schema rejects unknown fields and statuses", () => {
  const withSecret = { ...fixtureReceipt(), rawInput: "must-not-exist" };
  assert.equal(validate(withSecret), false);
  const withUnknownStatus = structuredClone(fixtureReceipt());
  withUnknownStatus.result.status = "maybe_committed";
  assert.equal(validate(withUnknownStatus), false);
  const withMismatchedCode = structuredClone(fixtureReceipt());
  withMismatchedCode.result.status = "aborted_target_changed";
  withMismatchedCode.result.errorCode = "adapter_threw";
  assert.equal(validate(withMismatchedCode), false);
});

test("runtime and public schema reject impossible approval/result combinations", () => {
  const impossible = structuredClone(fixtureReceipt());
  impossible.approval = {
    decision: "invalid",
    channel: null,
    decidedAt: null,
    bindingSha256: "1".repeat(64),
  };
  assert.equal(validate(impossible), false);
  assert.throws(() =>
    buildReceipt(
      {
        schemaVersion: "browser-action-claim/v1",
        operationId: "00000000-0000-4000-8000-000000000097",
        action: "submit",
        riskClass: "R3",
        approval: impossible.approval,
        target: impossible.target,
        preparedAt: "2026-08-16T00:00:00.000Z",
        claimedAt: "2026-08-16T00:00:01.500Z",
      },
      { status: "committed", errorCode: null },
      "2026-08-16T00:00:02.000Z",
    ),
  );
});

import assert from "node:assert/strict";
import { test } from "node:test";
import {
  ContractError,
  canonicalJson,
  createTargetObservation,
  prepareAction,
} from "../dist/index.js";
import { BASE_TIME } from "./helpers.mjs";

test("canonical JSON is deterministic and rejects ambiguous input", () => {
  assert.equal(canonicalJson({ z: 1, a: [true, null, "x"] }), '{"a":[true,null,"x"],"z":1}');
  assert.throws(() => canonicalJson({ value: 1.5 }), ContractError);
  assert.throws(() => canonicalJson({ value: Number.NaN }), ContractError);
  assert.throws(() => canonicalJson({ value: undefined }), ContractError);
  assert.throws(() => canonicalJson(JSON.parse('{"__proto__":"x"}')), ContractError);
  const cyclic = {};
  cyclic.self = cyclic;
  assert.throws(() => canonicalJson(cyclic), ContractError);
});

test("observation stores origin and hashes path while dropping query and fragment", () => {
  const first = createTargetObservation({
    url: "https://example.test/path?secret=one#first",
    targetFingerprint: "button|Publish",
    pageGeneration: "generation-1",
    observedAt: BASE_TIME.toISOString(),
  });
  const second = createTargetObservation({
    url: "https://example.test/path?secret=two#second",
    targetFingerprint: "button|Publish",
    pageGeneration: "generation-1",
    observedAt: BASE_TIME.toISOString(),
  });
  assert.equal(first.origin, "https://example.test");
  assert.equal(first.pathnameSha256, second.pathnameSha256);
  assert(!JSON.stringify(first).includes("secret"));
  assert(!JSON.stringify(first).includes("/path"));
});

test("prepared handle is opaque, frozen, and contains no payload", () => {
  const payload = { ref: "b1", text: "do-not-expose" };
  const handle = prepareAction({
    action: "type",
    riskClass: "R2",
    observation: createTargetObservation({
      url: "https://example.test/form",
      targetFingerprint: "input|email",
      pageGeneration: "generation-1",
      observedAt: BASE_TIME.toISOString(),
    }),
    payload,
    approvalDisplay: { title: "Enter email", detail: "Types an email into the selected field" },
    operationId: "00000000-0000-4000-8000-000000000002",
    now: BASE_TIME,
  });
  assert(Object.isFrozen(handle));
  assert(Object.isFrozen(handle.approvalRequest));
  assert.equal("payload" in handle, false);
  assert.equal(JSON.stringify(handle).includes("do-not-expose"), false);
});

test("approval display rejects control, bidi, zero-width, and non-canonical text", () => {
  for (const title of ["Publish\u0000hidden", "Publish\u202Ehidden", "Publish\u200Bhidden", " Publish"]) {
    assert.throws(
      () =>
        prepareAction({
          action: "click",
          riskClass: "R2",
          observation: createTargetObservation({
            url: "https://example.test/form",
            targetFingerprint: "button|Publish",
            pageGeneration: "generation-1",
            observedAt: BASE_TIME.toISOString(),
          }),
          payload: { ref: "b1" },
          approvalDisplay: { title, detail: "Visible detail" },
          operationId: "00000000-0000-4000-8000-000000000004",
          now: BASE_TIME,
        }),
      ContractError,
    );
  }
});

test("canonical JSON never invokes accessors", () => {
  const value = {};
  Object.defineProperty(value, "secret", {
    enumerable: true,
    get() {
      throw new Error("getter executed");
    },
  });
  assert.throws(
    () => canonicalJson(value),
    (error) => error instanceof ContractError && error.code === "json_property_invalid",
  );
});

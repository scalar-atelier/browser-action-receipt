# browser-action-receipt

> **Approval is not execution. If the target changed after approval, it does not click—and leaves a receipt.**

`browser-action-receipt` is a small TypeScript trust primitive for DOM-target browser actions. It binds one prepared action, payload, target observation, and approval decision; claims the operation once; delegates one atomic compare-and-act call; and writes a privacy-minimal terminal receipt.

**Status:** `v0.2.0`. It is not a security boundary by itself.

## What it does

- rejects every supported DOM mutation without a matching, unexpired approval;
- rejects approval reuse across operations, targets, or payloads;
- claims each UUID operation once across processes;
- records `committed`, `blocked`, `aborted_target_changed`, or explicit crash/adapter ambiguity;
- stores no raw typed text, URL query/fragment, DOM label, locator, cookie, token, or page body.

## What it does not do

- prove that a human approved the action—the embedding host owns the approval UI and identity;
- make a non-atomic adapter safe—the adapter must compare and act inside one browser execution context;
- secure coordinate-based computer use;
- prevent a malicious local user from rewriting a receipt and recomputing its unkeyed hash;
- provide legal non-repudiation, prompt-injection protection, a DOM adapter, or cloud storage.

See [claims and limitations](docs/CLAIMS_AND_LIMITATIONS.md) and the [threat model](docs/THREAT_MODEL.md) before integrating it.

## Verify the source checkout

Install the package:

```sh
npm install @scalar-atelier/browser-action-receipt
```

Or verify the source checkout:

```sh
git clone https://github.com/scalar-atelier/browser-action-receipt.git
cd browser-action-receipt
npm ci
npx playwright install chromium
npm run verify
```

Node.js 22 or newer is required. Runtime dependency count is zero; Playwright and TypeScript are development-only.

## Minimal host flow

```ts
const target = await createTargetObservation({
  url: page.url(), targetFingerprint, pageGeneration,
});
const prepared = await prepareAction({
  action: "click", riskClass: "R2", observation: target, payload: { ref: "b1" },
  approvalDisplay: { title: "Publish draft", detail: "Submit this draft to example.test" },
});
const decision = makeApprovalDecision(prepared.approvalRequest, "approved");
const outcome = await executePreparedAction({ prepared, decision, adapter, ledger });
```

The adapter, not this library, must implement `atomic-compare-and-act/v1`. A correct DOM adapter re-finds the target, reconstructs the fingerprint, compares it with the prepared target, and invokes the action in the same browser task. If it cannot provide that seam, it must not declare the capability.

Use the async Web Crypto build in a browser or Tauri webview:

```ts
import {
  BrowserReceiptLedger,
  createTargetObservation,
  executePreparedAction,
  prepareAction,
} from "@scalar-atelier/browser-action-receipt/browser";

const ledger = new BrowserReceiptLedger(tauriReceiptStore);
```

`tauriReceiptStore` only atomically claims and publishes opaque package-built values. Receipt assembly and verification stay inside this package. Both runtime entries consume the same public schema and [`golden-vectors.v1.json`](schema/golden-vectors.v1.json).

## Receipt shape

The receipt stores origin plus hashes of pathname, target fingerprint, page generation, and any local artifact reference. It never stores the raw action payload, approval wording, artifact reference, adapter error, URL query, or page content. Run `npm run demo` to produce the deterministic stable and changed-target outcomes used by the tests.

The executable schema is [`schema/browser-action-receipt.v1.schema.json`](schema/browser-action-receipt.v1.schema.json). The library performs stricter semantic validation than JSON Schema alone, including hash verification and cross-field invariants.

## Failure semantics

| Situation | External action | Durable result |
|---|---:|---|
| Approval denied, missing, invalid, or expired | 0 | `blocked` |
| Target differs at atomic commit | 0 for a conforming adapter | `aborted_target_changed` |
| Operation already has a final receipt | 0 | original receipt returned as `duplicate_final` |
| Operation is currently claimed | 0 | `duplicate_in_progress`; no second receipt |
| Same operation UUID is reused for a different bound request | 0 | `operation_conflict` |
| Process disappears after claim | unknown | explicit recovery writes `unknown_after_claim`; never auto-retries |
| Adapter throws or contradicts its result after invocation | unknown | `unknown_after_adapter`; never auto-retries |
| Action commits but capture fails | 1 | `committed` + `capture_failed` |

`recover` is an explicit startup operation after the host knows the previous writer is gone. Running it against a live writer can misclassify an active claim.

## Commands

```sh
browser-action-receipt verify path/to/receipt.json
browser-action-receipt recover path/to/ledger --before 2026-08-16T00:00:00.000Z
```

The CLI prints stable status codes, not receipt contents or browser data.

## Integration boundary

The host must render the library-provided action, risk, origin, title, and detail without hiding or rewriting them. The library binds those fields to the payload, but it cannot determine whether host-authored wording truthfully describes arbitrary payload semantics. Risk classification is also host-owned and informational; it never bypasses approval. The official demo compares origin, pathname, page generation, and target fingerprint synchronously with the action in one page task.

## Security and contributions

Please report vulnerabilities through [GitHub private vulnerability reporting](SECURITY.md). Contributions require a DCO sign-off and tests for changed claims. The project is MIT-licensed; its origin and clean-room boundary are documented in [ORIGIN.md](docs/ORIGIN.md).

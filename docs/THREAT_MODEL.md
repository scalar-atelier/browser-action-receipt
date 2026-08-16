# Threat model

## Assets

- the user's intent to act on one observed DOM target;
- the exact prepared payload held in memory;
- operation uniqueness;
- terminal status and optional evidence-reference hash;
- absence of sensitive page and input data from durable receipts.

## Adversaries and failures

### Stale target / TOCTOU

The page navigates or swaps the element after approval. A conforming adapter reconstructs the target fingerprint and performs the comparison and action in one browser task. A mismatch returns `target_changed` without invoking the fixture action.

### Approval substitution

A caller reuses approval from another operation, changes the displayed authorization text or payload after approval, changes the target, or extends expiry. The binding covers operation ID, action, risk, full prepared observation, human-readable approval display, payload, and a random nonce. The nonce is not persisted. Mismatch and expiry are terminal `blocked` receipts.

### Replay and concurrency

Multiple processes use the same operation UUID. The ledger atomically publishes a complete claim before the adapter runs and gives only the winner an in-memory finalization handle. A same-request loser returns the existing receipt or `duplicate_in_progress`; a different bound request returns `operation_conflict`. None invokes the adapter.

### Crash after side effect

The process exits after claiming, possibly after the external action, but before final receipt write. The claim is retained forever. On a later single-writer startup, an explicit cutoff-based recovery records `unknown_after_claim`. It never retries the action.

### Receipt leakage

The receipt projection excludes typed input, deterministic input-only hashes, raw pathname, query, fragment, labels, locators, body, headers, cookies, tokens, user/session IDs, raw artifact references, and raw errors. Origin and low-entropy hashes can still reveal information; they are pseudonymous, not confidential.

### Filesystem manipulation

Operation IDs are lowercase UUID v4 values and never become arbitrary paths. Ledger directories and files reject obvious symbolic links and oversized records. Atomic no-overwrite linking prevents a second final receipt. A local attacker controlling the directory remains out of scope and can delete or rewrite files.

### Malicious or broken adapter

The adapter may lie about atomicity or return a false observation. The library detects malformed or contradictory responses and records `unknown_after_adapter`, but cannot undo an action the adapter already performed. Adapter source review and host-specific E2E are mandatory before claiming zero-call behavior.

## Security invariants

1. No supported DOM mutation without a valid approval reaches the adapter.
2. The payload supplied to the adapter is the cloned, frozen payload bound at prepare time.
3. A claimed operation never reaches the adapter twice through the same ledger.
4. A conforming adapter does not execute a changed target.
5. No automatic retry follows a crash-ambiguous claim.
6. Raw errors and source data never enter durable receipts.

The library rejects Unicode control/format characters in approval wording and binds the exact normalized wording, but it cannot prove that trusted host-authored prose is semantically honest. The host must derive risk and wording from reviewed application policy rather than page or model output.

## Deferred hardening

Receipt signatures, OS keystore integration, network transparency logs, multi-host consensus, and browser-vendor adapters are intentionally absent. Add one only with a concrete deployment and a protected key or atomic browser seam.

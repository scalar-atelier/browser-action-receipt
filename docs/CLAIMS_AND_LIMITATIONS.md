# Claims and limitations

## Claims earned by v0.1.0 tests

The claim is conditional: **given a conforming atomic adapter and a trusted approval host**, the library will not ask that adapter to execute when approval is missing/invalid/expired, the operation was already claimed, or the adapter reports that the prepared DOM target changed. Every v0.1 action requires approval; risk labels never bypass it.

The library also binds its in-memory payload and human-readable approval display into a nonce-hardened approval binding, passes only the frozen prepared payload to the adapter, and writes one redacted terminal receipt for the winning claim.

Each claim maps to a deterministic check:

| Claim | Check |
|---|---|
| Every supported mutation requires approval | `guard.test.mjs` R1/missing/denied/expired cases |
| Approval cannot move to another operation or payload | binding and mutation cases |
| One operation causes at most one adapter invocation | concurrent ledger case |
| Changed target does not invoke the fixture action | stable/swapped Playwright demo |
| Crash ambiguity is not retried | unknown-claim recovery case |
| Receipt omits sensitive source material | privacy canary case |
| Receipt alteration is detected | hash-tamper case |

## Explicit non-claims

This project does not prove:

- that a human, a particular person, or a hardware-backed authenticator approved an action;
- that host-authored approval wording truthfully describes arbitrary payload semantics;
- that the host assigned the right risk class; risk is receipt context, not an approval bypass;
- that an adapter truthfully implements its declared atomic capability;
- that a page is benign or that its text is not prompt injection;
- that a committed remote action succeeded outside the browser;
- the content of typed text—the receipt intentionally omits it and any deterministic input-only hash;
- receipt authorship or legal non-repudiation;
- confidentiality of low-entropy pathname or target hashes;
- safety for coordinate clicks, raw remote desktop control, browser extensions, or arbitrary JavaScript.

The local receipt hash detects accidental or unsophisticated alteration only. Anyone who can rewrite the receipt can recompute it. Add a host-owned signature or append-only external ledger only when the deployment actually has a protected signing key and needs that stronger claim.

## Trust boundaries

- **Trusted:** the host's approval UI and risk classification, its local identity/session binding, and the adapter implementation. The host must render action, risk, origin, title, and detail without hiding or rewriting them.
- **Untrusted:** model output, page content, action payload before validation, approval decision input before binding validation, receipt files read from disk, capture return values.
- **Out of scope:** an attacker who controls the host process, browser process, JavaScript runtime, or ledger directory.

## Atomicity caveat

The library can validate adapter outputs but cannot retroactively stop a dishonest adapter that acts before comparing. A `committed` result whose returned observation differs is stored as `unknown_after_adapter`, because the external side effect may already exist. Integration review must therefore inspect the adapter's compare-and-act implementation, not merely its capability string.

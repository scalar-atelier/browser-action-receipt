# Security policy

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability. Use GitHub's private vulnerability reporting flow:

<https://github.com/scalar-atelier/browser-action-receipt/security/advisories/new>

Include the affected commit, minimal reproduction, expected invariant, and observed side effect. Do not include real credentials, account data, or third-party private pages.

We will acknowledge a valid report within two business days. This is a response target, not an SLA or a promise of fix timing.

## Supported versions

Only the latest released `v0.1.x` version receives security fixes until a broader policy is published.

## Scope

High-impact examples include approval bypass, payload/target substitution, duplicate execution through the bundled ledger, receipt leakage of excluded data, path traversal, and an unsafe official adapter. A malicious embedding host or adapter that lies about atomicity is outside the library's enforcement boundary, but documentation that falsely implies otherwise is still a valid report.

# Contributing

This project accepts narrowly scoped fixes to the published contract, ledger, tests, and documentation.

1. Open an issue for a contract or behavior change before implementation.
2. Keep runtime dependencies at zero unless the standard library cannot meet a demonstrated requirement.
3. Add one deterministic regression for every changed security claim.
4. Run `npm run verify` from a clean checkout.
5. Sign off each commit with `git commit -s` to certify the [Developer Certificate of Origin 1.1](https://developercertificate.org/).

Do not submit real website captures, customer data, credentials, generated secrets, copied product UI, or proprietary adapter code. A green test does not authorize broadening the claims in README or `CLAIMS_AND_LIMITATIONS.md`.

# Changelog

## Unreleased — Prompt 2

- Added versioned, idempotent SQLite directory schema migration and monotonic sequence tracking.
- Added RSA-3072 enrollment key binding and RSA-PSS proof-of-possession, including optional administrator-pinned fingerprint checks.
- Added canonical-CBOR signed RDRs, nonce-bound lookup, signed directory-sync bundles, heartbeat directory sequence/revocation state, and per-router rate limiting.
- Added repeatable operator-owned WAN endpoint, gateway IP and prefix registration flags, router-wide revocation, and signed offline directory export.
- Updated API/proto schemas, traceability and security documentation. Prompt 2 CA/client test gate passed on Ubuntu 22.04 and 24.04 in CI run 38861558053; cross-repo integration passed with 12 datetime/cryptography deprecation warnings per platform.

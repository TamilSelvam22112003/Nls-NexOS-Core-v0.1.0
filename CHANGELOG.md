## Unreleased — NLD2 cross-repository validation (2026-10-24)

- The matching NetOS implementation branch now carries NLD2 data framing and metadata-mode enforcement. Core runtime code is unchanged; this commit triggers the Core cross-repository integration suite against the matching NetOS branch and verifies the normative wire-spec sections remain synchronized.
- Result is pending this commit's CI and does not imply that the full router network lab has passed.

## Unreleased — Metadata protection modes specification (2026-10-24)

- Specified versioned NLD2 data framing and explicit `source-only` / `source-destination` policies with authenticated visible-destination semantics.
- Specification only: runtime implementation and tests are pending; this entry does not claim either mode is implemented.

## Unreleased — SourceToken specification reconciliation (2026-10-24)

- Added a cross-repository integration assertion that the NetOS and Core master specification files are byte-identical, preventing future wire-format drift.
- Synchronized the Core master specification with the existing NetOS HMAC-SHA-256 SourceToken derivation, removing the conflicting AES block-encryption description.
- No runtime code or wire behavior changed. Cross-repository specification consistency must be rechecked by the dedicated validation gate.

# Changelog

## Unreleased — Prompt 2

- Added versioned, idempotent SQLite directory schema migration and monotonic sequence tracking.
- Added RSA-3072 enrollment key binding and RSA-PSS proof-of-possession, including optional administrator-pinned fingerprint checks.
- Added canonical-CBOR signed RDRs, nonce-bound lookup, signed directory-sync bundles, heartbeat directory sequence/revocation state, and per-router rate limiting.
- Added repeatable operator-owned WAN endpoint, gateway IP and prefix registration flags, router-wide revocation, and signed offline directory export.
- Updated API/proto schemas, traceability and security documentation. Prompt 2 CA/client test gate passed on Ubuntu 22.04 and 24.04 in CI run 38861558053; cross-repo integration passed with 12 datetime/cryptography deprecation warnings per platform.


## 2026-10-24 — Paired NLD2 implementation validation

- Trigger the cross-repository control-protocol and normative-spec compatibility suite against NetOS implementation head `d9d0ee5ecfd34e62bb55a53eb2a81a92cb76e841`. Core runtime remains unchanged by the data-plane mode implementation.
- The paired NetOS head also rate-limits persistent Trust Table expiry to a 250 ms cadence and retains NLD2 mode/replay/MTU regression tests. This entry records the validation target, not a pass claim; use this commit's Core CI results for the outcome.

## Unreleased — Bounded Router-CA control connections (2026-10-25)

- Added a global cap of 128 concurrent TCP control connections, covering unauthenticated handshakes and idle clients, rather than relying only on lookup-specific rate/concurrency limits.
- Set a 15-second unauthenticated control-handshake timeout; successful authentication switches to the 90-second application idle timeout.
- Added unit tests for the admission cap and guaranteed slot release on handler exceptions.
- Exact-head Core CI run 40166718326 passed on Ubuntu 22.04 and 24.04, including unit/security and cross-repository control integration tests.

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

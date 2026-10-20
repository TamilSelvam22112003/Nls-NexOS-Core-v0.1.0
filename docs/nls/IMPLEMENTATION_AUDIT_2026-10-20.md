# NLS implementation audit — 2026-10-20

## Scope and evidence

This is an initial repository-first audit on `feat/nls-v1`. It records only facts confirmed from files retrieved during this pass. It is not a security certification or a claim that the full acceptance suite was run.

- Repository: `TamilSelvam22112003/Nls-NexOS-Core-v0.1.0`
- Branch requested by project specification: `feat/nls-v1`
- Retrieved files: `docs/nls/MASTER_SPEC.md`, `src/nls_nexos_core/control_protocol.py`, `README.md`, `pyproject.toml`
- Local checkout, working-tree status, branch head SHA, and test execution are **not verified in this audit**.

## Confirmed implementation/specification boundaries

| ID | Finding | Evidence | Status |
|---|---|---|---|
| B-01 | NLS Control v1 uses `NLSC` framing and canonical JSON records. This is a distinct control-channel protocol from the NLH2 router-to-router handshake specified in the master spec; the two formats must not be conflated. | `src/nls_nexos_core/control_protocol.py`: `MAGIC=b"NLSC"`, `canonical()` | CONFIRMED |
| B-02 | The README reports signed Ed25519 control handshakes, ephemeral X25519, transcript-bound HKDF-SHA-256, directional AES-256-GCM records, sequence checks, SQLite registry, signed RDRs, and authenticated nonce-bound lookup. These are README claims, not independently verified test results in this audit. | `README.md` | DOCUMENTED; NOT INDEPENDENTLY VERIFIED |
| B-03 | The README explicitly classifies the control protocol as experimental and says independent cryptographic review and hostile-network interoperability testing have not been completed. | `README.md`, “Important security status” | CONFIRMED |
| B-04 | Core declares `cryptography>=41.0`, while NetOS declares `cryptography>=42.0`; both pin `cbor2==5.9.0`. Cross-repository dependency compatibility needs matrix validation. | `pyproject.toml` in both repositories | CONFIRMED |
| B-05 | Core's control channel uses TCP 4790 in the README; NetOS's NLS data transport is documented separately on UDP 4789. Control-channel and data-plane lifecycle must be tested independently. | `README.md` | DOCUMENTED; runtime behavior NOT VERIFIED |

## Known CI evidence to retain

The NetOS `docs/nls/CI_BASELINE_ISSUES.md` records selected job results, but the same document says Core run records and baseline job results were not retrieved. No Core CI status is inferred from NetOS evidence.

## Required next checks

1. Verify branch head and tags for both repositories and retrieve Core workflow/job results.
2. Trace registry lookup, signature verification, status/freshness, revocation, and administrative authorization in code.
3. Verify compatibility of the copied control-protocol definitions and add/run a cross-repository compatibility test.
4. Run unit, security, integration, and packaging checks in a reproducible environment.
5. Keep the control plane, NLH2 handshake, and NLS data plane explicitly separate in APIs and documentation.

## Status

Phase 1 is **PARTIALLY VERIFIED**. No product code was changed by this audit. No tests were run in a local checkout.
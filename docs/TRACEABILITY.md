# Router-CA traceability — Prompt 1 baseline

Prompt 1 established the evidence baseline. Prompt 2 implementation and gate evidence are recorded below; requirements assigned to prompts 3–5 remain not started until their gates.

| Requirement | Planned implementation file/function | Planned test | Status |
|---|---|---|---|
| R1 certificate/RDR binding | ca.py:CertificateAuthority.enroll; directory.py:record_for_router/signed_rdr; router nls/ca_client.py:lookup/directory_sync | test_ca_authorization.py; test_directory.py; cross-repo lookup | PASS for Prompt 2 CA/client scope; handshake S1 integration remains Prompt 3 |
| R2 vIP ownership | router nls/vip.py and CA RDR endpoint schema | expiry/reuse | not started |
| R3/R4 sealed handshake | router handshake.py and seal.py | handshake/tamper/amplification | not started |
| R6/R7 signed lookup/nonce freshness | api.py:handle_control_request; control.py lookup handler; router nls/ca_client.py:lookup | CA lookup/nonce verification is implemented; S3/S4 handshake cross-check remains Prompt 3 | partial |
| R8 key schedule | router nls/key_schedule.py | KDF vectors/all-zero DH | not started |
| R9/R10 sender-authenticated data AEAD | router nls/encapsulation.py:open_data | forgery/tamper | not started |
| R12 replay policy | router nls/replay.py:ReplayWindow | duplicate/window/poisoning | not started |
| R13 structured audit codes | control.py and api.py | canary log test | not started |
| R14 RSA PoP, signed RDR, directory-sync, revoke-router | models.py:EnrollmentRequest; ca.py:CertificateAuthority.enroll; directory.py:signed_rdr/signed_directory_bundle; api.py:handle_control_request; control.py:NLSControlServer._dispatch; cli.py:register/revoke_router/export_directory; database.py:Registry | test_ca_authorization.py; test_database.py; test_directory.py; test_directory_api.py; test_nls_control_cross_repo.py | PASS: CI run 38861558053 on Ubuntu 22.04/24.04 |
| Control protocol parity | router nls/control_protocol.py; src/nls_nexos_core/control_protocol.py | cross-repo compatibility; cross-repo lookup/sync integration | PASS: CI run 38861558053 |
| S1 authentication | CA certificate/RDR issuance and router validation | wrong/revoked/expired | not started |
| S2 vIP and M1/M2 | router vip/handshake | handshake/amplification/vIP | not started |
| S3 source cross-check | router handshake + CA lookup | S3 mismatch | not started |
| S4 destination cross-check | router handshake + CA lookup | S4 mismatch/forged CA | not started |
| S5 endpoint switch | router daemon/vIP | retired vIP rejected | not started |

No full protocol stage S1–S5 is marked complete in Prompt 2. Only the explicitly gated CA/client scope rows R1 and R14 have passed; handshake/data-plane work remains assigned to later prompts.

## Prompt 2 implementation evidence — gate passed for CA/client scope

- Versioned SQLite migration: `src/nls_nexos_core/database.py:Registry.initialize`; legacy migration and idempotence test: `tests/unit/test_database.py:test_legacy_schema_migration_is_idempotent`.
- Enrollment RSA PoP and optional administrator fingerprint pin: `src/nls_nexos_core/ca.py:CertificateAuthority.enroll`; tests in `tests/unit/test_ca_authorization.py`.
- Signed canonical-CBOR RDR/bundle and freshness: `src/nls_nexos_core/directory.py:signed_rdr/signed_directory_bundle`; signature tests in `tests/unit/test_directory.py`.
- Lookup, directory-sync, heartbeat sequence/revocation state and per-router rate limiting: `api.py:handle_control_request`, `control.py:NLSControlServer._dispatch`; cross-repo integration test is extended.
- Real CI output: unit/security suites `27 passed in 3.40s` (Ubuntu 22.04) and `27 passed in 1.98s` (Ubuntu 24.04). Cross-repository integration: `1 passed, 12 warnings in 2.42s` (Ubuntu 22.04) and `1 passed, 12 warnings in 1.69s` (Ubuntu 24.04). See [CI run 38861558053](https://github.com/TamilSelvam22112003/Nls-NexOS-Core-v0.1.0/actions/runs/38861558053). The 12 warnings are existing datetime/cryptography deprecations; they are recorded for Prompt 5.


## 2026-10-25 audit delta

The review of the current `feat/nls-v1` heads found that Core directory lookup has caller-certificate/status checks, auditing, per-router rate limiting, and per-router/global concurrent-lookup caps. The separate listener-level connection resource bound remains open.

Cross-repository control-protocol compatibility and Core control integration passed in CI run `40091955351` on Ubuntu 22.04 and 24.04. This result applies to NLSC only; it does not prove the router handshake or data-plane wire format conforms to the current master spec.

The shared spec blob matches across both `feat/nls-v1` branches. NetOS `main` has a different, newer `docs/nls/MASTER_SPEC.md` blob and must not be merged into the target branch without a reviewed spec synchronization decision.

Current highest-priority end-to-end gaps are: amended deterministic vIP/M1 fields; NLD2 data-plane framing and metadata modes; strict unknown-field rejection for RDR v2; M4-loss recovery; connection-level DoS bounds; and actual OSPF/OSPFv3 LSA propagation evidence. See `docs/nls/IMPLEMENTATION_AUDIT_2026-10-25.md` for the detailed review.

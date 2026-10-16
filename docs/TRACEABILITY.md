# Router-CA traceability — Prompt 1 baseline

All target implementation statuses are not started. Prompt 1 updates docs and scaffolds tests only.

| Requirement | Planned implementation file/function | Planned test | Status |
|---|---|---|---|
| R1 certificate/RDR binding | ca.py:CertificateAuthority.enroll; new directory.py:sign_rdr | wrong/expired/revoked cert | not started |
| R2 vIP ownership | router nls/vip.py and CA RDR endpoint schema | expiry/reuse | not started |
| R3/R4 sealed handshake | router handshake.py and seal.py | handshake/tamper/amplification | not started |
| R6/R7 signed lookup/nonce freshness | api.py:handle_control_request; control.py lookup handler | stale/forged lookup, S3/S4 mismatch | not started |
| R8 key schedule | router nls/key_schedule.py | KDF vectors/all-zero DH | not started |
| R9/R10 sender-authenticated data AEAD | router nls/encapsulation.py:open_data | forgery/tamper | not started |
| R12 replay policy | router nls/replay.py:ReplayWindow | duplicate/window/poisoning | not started |
| R13 structured audit codes | control.py and api.py | canary log test | not started |
| R14 RSA PoP, signed RDR, directory-sync, revoke-router | ca.py, api.py, control.py, database.py | PoP/lookup freshness/revocation | not started |
| Control protocol parity | router nls/control_protocol.py; src/nls_nexos_core/control_protocol.py | cross-repo compatibility | not started |
| S1 authentication | CA certificate/RDR issuance and router validation | wrong/revoked/expired | not started |
| S2 vIP and M1/M2 | router vip/handshake | handshake/amplification/vIP | not started |
| S3 source cross-check | router handshake + CA lookup | S3 mismatch | not started |
| S4 destination cross-check | router handshake + CA lookup | S4 mismatch/forged CA | not started |
| S5 endpoint switch | router daemon/vIP | retired vIP rejected | not started |

No target requirement is marked complete. Current evidence is in docs/SECURITY_MODEL.md.
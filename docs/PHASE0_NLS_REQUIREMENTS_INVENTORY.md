# Phase 0 — NLS Requirements Inventory (R1–R14)

**Inspected baseline:** `main` at `bdfbda6a9d6c293307851eeb70e858bc55ae3295`; paired router baseline `f6a3486a1aa4c4562191b2e37d8f382e0e6f3fe9`.  
**Scope:** source-code inspection only. No protocol code was changed for this phase. Tests were inspected but not executed; no test result is asserted.  
**Status definitions:** Implemented = code directly satisfies the normative requirement; Partial = a related mechanism exists but normative conditions are missing; Missing = no implementation found.

## R1–R14 inventory (cross-repository)

| Requirement | Status | CA repository evidence and gap |
|---|---|---|
| **R1 Router authentication** | **Partial** | `src/nls_nexos_core/control.py:NLSControlServer._authorize_client_certificate` validates X.509 router certificates, issuer/time, Ed25519 identity binding, CN, EKU, signature, active router record, and certificate status for the TCP 4790 control channel. This does not authenticate the separate NLS UDP handshake using a CA-issued certificate or signed live router record. |
| **R2 Temporary vIP as actual outer source with 10 s TTL** | **Missing** | No vIP allocation/pool, router interface assignment, TTL, or vIP lifecycle exists in the CA server. |
| **R3 M1 hybrid-encrypted source public keys** | **Missing** | No NLS data-plane M1 handling or hybrid-encryption protocol exists in this repository. |
| **R4 M2 encrypted destination certificate/gateway/SA/DH/nonce/IKE metadata** | **Missing** | The CA service does not construct or process M2. |
| **R5 Endpoint switch and vIP removal** | **Missing** | No router endpoint-transition control exists in the CA service. |
| **R6 Source validates M2 against signed CA record and sends M3** | **Partial** | `src/nls_nexos_core/api.py:handle_control_request` supports enrollment, sync, heartbeat, status, health, and close only. No `lookup(Router-ID)` API returns a signed authoritative router record for source-side M2 validation; no M3 handling exists. |
| **R7 Destination validates M3 against CA and sends M4** | **Missing** | No M3/M4 message types or transcript checks exist. |
| **R8 Session keys derived from both DH values/nonces/Router-IDs/transcript** | **Partial** | `src/nls_nexos_core/control_protocol.py:_derive_keys` derives directional AES-GCM keys for the separate NLS Control channel from X25519 and its client/server hello transcript. This is not the NLS router data-plane key schedule specified in R8. |
| **R9 Tunnel-mode session-key AES-256-GCM data encryption** | **Missing** | The CA does not implement router data-plane packet encryption. Its control channel uses AES-256-GCM records, which is a distinct protocol. |
| **R10 Tampered data packet rejection** | **Missing** | Control-channel AEAD rejects tampered control records, but there is no NLS data-plane packet receiver here. |
| **R11 Destination decrypt/forward** | **Missing** | No router data-plane forwarding exists in the CA server. |
| **R12 128-packet replay window and rekey** | **Partial** | Control records use strict sequence numbers in `control_protocol.py:_recv_protected` and `NLSControlRecordChannel`; policy defaults are 64 in `config.py:Settings` and `api.py:_policy`. This does not implement the NLS data-plane 128-packet sliding window or its 2^32-packet/one-hour rekey. |
| **R13 Silent wire failures, structured reason codes, secret-safe logs** | **Partial** | `src/nls_nexos_core/control.py:NLSControlServer._handle_client` logs control connection/request failures; `ca.py:CertificateAuthority.enroll` and `database.py:Registry.audit` record local audit events without token values. There is no shared structured reason-code contract for NLS M1–M4 failures. |
| **R14 Router-CA signed lookup record** | **Partial** | `ca.py:CertificateAuthority.enroll` issues X.509 certificates; `cli.py:revoke_certificate` and `database.py:Registry.revoke_certificate` support revocation; `api.py:_bundle` sends policy and revoked certificate serials over the encrypted control channel. The required authenticated `lookup(Router-ID)` response with Ed25519/RSA public keys, WAN/gateway IPs, serial, status, and a signature by the CA signing key is absent. Registry schema `database.py:SCHEMA` stores router identity/status, optional claimed IPv6/MAC, enrollment-token hash, and issued-certificate metadata, but not the required gateway/WAN/key bundle. |

## Existing CA capabilities and boundaries

- Enrollment validates a CSR, request freshness/replay state, global bootstrap token, per-router token binding, registry status, and optional claimed IP/MAC: `src/nls_nexos_core/ca.py:CertificateAuthority.enroll`.
- The CA signing key is RSA and requires at least 3072 bits; issued router certificates contain the CSR public key (Ed25519 in the router client), validity dates, identity CN/SAN, and client-auth EKU.
- The separate TCP 4790 NLS Control protocol uses signed Ed25519 hellos, X25519/HKDF-SHA256, directional AES-256-GCM records, and strict record sequence checking: `src/nls_nexos_core/control_protocol.py`.
- `api.py:_bundle` returns policy plus a revocation list; it does not cryptographically sign the returned registry state with the CA signing key.
- Tests cover enrollment token binding, control handshake/records, database request uniqueness, and a paired router/CA loopback integration test. They do not cover the required NLS M1–M4 workflow, live signed lookup, endpoint vIP behavior, or pcap properties.

## Required automated tests — baseline coverage observed

| Requested test | Baseline observation |
|---|---|
| End-to-end NLS data traffic | Paired repository loopback control/enrollment test exists at `tests/integration/test_nls_control_cross_repo.py`; it tests enrollment/sync/heartbeat, not NLS tunnel data. |
| Wrong/revoked/expired router certificate | CA control code checks validity/status; test suite has enrollment validation but no complete matrix for expired/revoked X.509 certificate on the NLS UDP handshake. |
| CA mismatch in S3/S4; forged CA response | Not found. |
| Tampered ciphertext / replay / out-of-window / vIP expiry and post-switch / SA downgrade / out-of-order M1–M4 / rekey / pcap check | No tests for these NLS data-plane requirements found in this repository. |
| CA unreachable fail-closed | Current control client retries on connection failure, but the NLS handshake does not perform live CA lookup. A protocol-specific fail-closed lookup test is absent. |

## Phase 0 conclusion

The CA has a working-looking enrollment/revocation/control-channel foundation, but **R14's signed router lookup record is not implemented**, and the existing control channel is not the requested NLS data-plane protocol.

**Gate status: Phase 0 inventory prepared; test baseline not executed.** Do not begin Phase 1 until this inventory and the test-execution plan are accepted. Keep the protocol labeled experimental.

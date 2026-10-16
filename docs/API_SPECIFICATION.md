# NLS Router-CA API specification — NLS v1 target

**Status:** normative target. Current TCP 4790 custom NLS Control Record Protocol implements health, enroll, sync, heartbeat, status and close. Lookup and signed directory operations below are not implemented by Prompt 1.

## Transport
The control channel is custom experimental NLS Control Record Protocol v1 over TCP 4790, not TLS and not claimed TLS-interoperable. Current protocol uses a pinned Ed25519 control identity, signed handshake messages, X25519, HKDF-SHA256, directional AES-256-GCM records, bounded framing and sequence numbers. Independent cryptographic review remains mandatory before production use.

## Required operations
- **health:** readiness and supported protocol version; does not imply directory freshness.
- **enroll:** router_id, request_id, nonce, timestamp, bootstrap/router credentials, Ed25519 CSR, RSA-3072 encryption public key and proof of possession. Validate credentials, registry, freshness, persistent nonce/request uniqueness, CSR signature, RSA PoP and policy. Private keys never leave router. Return issued X.509 certificate and initial RDR/reference.
- **lookup:** authenticated request router_id plus fresh random client_nonce (>=128 bits). Return signed RDR, exact nonce echo and issued_at/valid_until. Valid <=30 seconds. Verify pinned directory Ed25519 key, NLS-DIR-v1, nonce, certificate chain, serial, status, endpoints, keys and freshness. Unknown/revoked/disabled/expired/stale/mismatched results fail closed.
- **directory-sync:** signed batch of RDRs, revoked serials, policy, issued_at and valid_until. Sign with directory Ed25519 key using NLS-DIR-v1 plus canonical CBOR. Default expiry 10 minutes; stale-grace=0. Offline mode is opt-in, verifies signed bundle and is marked degraded freshness.
- **sync/heartbeat:** preserve current synchronization but make signed bundle authoritative. Heartbeat cannot extend old signatures or suppress revocation; stale trust fails closed.
- **status:** authenticated router identity, certificate serial, status and record_seq; never private keys, tokens, session keys or unrelated private metadata.
- **revoke-router:** authorized authenticated principal submits router_id, reason code, request_id, nonce and timestamp. Mark REVOKED, revoke serial, increment record_seq, invalidate old RDR/bundle versions and publish signed revocation state. Idempotent; audit reason codes only.
- **close:** close authenticated channel and clear per-connection state.

## Router Directory Record
Fields: router_id, ed25519_public_key, rsa_encryption_public_key, wan_endpoints, gateway_ips, prefixes, certificate_serial, status (ACTIVE/REVOKED/DISABLED/EXPIRED), record_seq, issued_at, valid_until, signature. Signature preimage is exact ASCII NLS-DIR-v1 followed by canonical CBOR of unsigned RDR. Lookup nonce binding is signed. X.509 issuer root and directory signer are distinct pins.

## Failure, limits, routing
Use stable machine-readable errors without secrets. Bound frame size, record count, pending requests and expensive crypto; enforce timeouts and CA policy. No CA response creates a route: CA may authorize a prefix, but only operator route configuration creates routes.
Current handlers are src/nls_nexos_core/api.py:handle_control_request and src/nls_nexos_core/control.py:NLSControlServer. Prompt 1 documents target only; it does not implement lookup, directory-sync, RSA PoP or revoke-router.
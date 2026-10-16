# NLS Router-CA security model

## Assets
CA certificate/private signing key, pinned Ed25519 directory/control identity, router Ed25519/RSA private keys, enrollment credentials, registry/database, certificate serials, signed RDRs/bundles, revocation, policy, session keys, audit records and route policy.

## Trust anchors and key separation
X.509 CA root validates router certificates. A separate Ed25519 control/directory key is pinned out of band and signs RDRs/bundles with NLS-DIR-v1 plus canonical CBOR. Router certificate binds CN=router_id to Ed25519 identity. RDR binds identity and RSA-3072 encryption key to endpoints, gateways, prefixes, serial, status, sequence and validity. Never implicitly substitute the certificate issuer key for the directory key.

## Enrollment
Routers generate private keys locally. CA validates CSR signature, credentials, registry authorization, timestamp/nonce freshness, persistent uniqueness and proof of possession for the submitted RSA public key. No private or symmetric session key is transmitted. Record serial, identity, RSA key, authorized endpoints/gateways/prefixes, status and record_seq.

## Signed records and freshness
Lookup(router_id, client_nonce) returns signed RDR plus nonce echo and is valid <=30 seconds. Bundle contains signed RDRs, revoked serials, policy, issued_at and valid_until; default expiry 10 minutes. stale-grace defaults to zero. Offline mode is explicit, verifies imported signed bundle, visibly marks degraded freshness and fails closed at expiry. Unsigned Router-CA YAML is not a trust source. Status values ACTIVE/REVOKED/DISABLED/EXPIRED. Revocation increments record_seq and is enforced at handshake and session refresh.

## Control channel and qualification
Current control channel is custom, not TLS. It uses signed handshakes, pinned identity, X25519, HKDF-SHA256, directional AES-256-GCM records and sequence validation. This is not proof of soundness. Independent protocol review, formal analysis, hostile-network tests and deployment hardening are required before critical use.

## Routing isolation and audit
CA metadata may authorize a peer/prefix but never create routes. Only operator-configured nls route PREFIX via ROUTER-ID entries install TUN routes. Destination validates decrypted inner source against source RDR prefixes by default. Use stable reason codes; never log credentials, keys, decrypted packets, tokens or canaries. Use parameterized SQL and transactions. Bound frames, pending requests, connections and expensive crypto. Rate-limit by observed source, never claimed identity.

## Prompt 2 implementation status and remaining gaps
The current branch implements RSA-3072 enrollment proof-of-possession, optional administrator-pinned RSA fingerprint, signed canonical-CBOR RDRs and directory bundles, nonce-bound lookup, directory-sync, heartbeat sequence/revocation state, per-router rate limiting, router revocation, and offline bundle export/import. These claims passed the Prompt 2 CA/client CI gate on Ubuntu 22.04 and 24.04 in run 38861075718; the run evidence and remaining warnings are recorded in docs/TRACEABILITY.md. Directory sync returns a full snapshot rather than deltas. Router daemon live-revocation teardown is intentionally deferred to prompts 3–4. See docs/TRACEABILITY.md and docs/DEVIATIONS.md.
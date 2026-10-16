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

## Router-CA control identity provisioning and rotation (Prompt 5a)

The Router-CA control identity is a dedicated Ed25519 key, separate from the X.509 CA signing key. The private key remains on the CA host, is readable only by the configured CA service account, and must be mode `0600`. Routers pin the raw Ed25519 public key out of band in `router_ca.server_public_key`; the administrator must verify its SHA-256 fingerprint through an independent channel before enabling live CA trust. An unsigned Router-CA YAML file, a key learned during the first connection, or an unauthenticated fallback must never establish trust.

The required authenticated rotation design is a transition statement signed by the currently pinned key. It must bind the old key identifier, new public key, monotonically increasing key epoch, activation time, expiry, and intended CA identity. Routers verify the transition with the old key, persist the new epoch outside the directory cache, and accept the new key only after activation. Rollback to an older epoch is rejected; there is no silent fallback.

**Status: NOT VERIFIED.** The end-to-end authenticated control-identity rotation message, durable key epoch, overlap procedure, rollback behavior, and Ubuntu 22.04/24.04 rotation tests have not passed the Prompt 5a gate. Carry this item into Prompt 5b.

## Clock skew and freshness policy

- A live lookup response is bound to the request nonce and valid for no more than 30 seconds.
- A signed directory bundle expires after 10 minutes by default; stale grace is zero. Expired or untrusted cache state must fail closed.
- X.509 `notBefore`/`notAfter`, RDR `issued_at`/`valid_until`, and bundle `expires_at` are independent validity checks.
- The control protocol's configured timestamp-skew allowance defaults to 120 seconds. Rekey time thresholds use a monotonic clock (one hour by default); packet-count rekey is independent of wall-clock adjustments.
- Operators must maintain NTP synchronization. Do not work around skew failures by increasing stale grace.

**Status: NOT VERIFIED.** Boundary tests for positive/negative skew, certificate validity edges, 30-second lookup expiry, bundle freshness loss, and time-based rekey remain outstanding for Prompt 5b.

# Open questions and safe interpretations

1. Directory signature: exact ASCII NLS-DIR-v1 followed by canonical CBOR of unsigned RDR/bundle; signed lookup wrapper echoes and binds nonce.
2. RDR schema: freeze CBOR types, status enum, endpoint canonicalization, prefix normalization and serial representation; reject unknown critical fields.
3. RSA proof of possession: use a domain-separated challenge bound to router_id, request_id, nonce and public-key hash, signed by submitted RSA private key and authenticated control channel.
4. Trust pins: X.509 root and Ed25519 directory signer are separate out-of-band pins.
5. Freshness: lookup <=30 s, bundle <=10 min, stale-grace 0; offline mode explicit and visibly degraded.
6. revoke-router: restrict to authenticated administrative principal or explicit CA policy; enrolled routers cannot revoke others by default.
7. Route ownership: CA records authorize only; no CA API/sync path mutates kernel routes.
8. Control protocol parity: constants, canonical JSON, signature preimage, framing and exceptions must be parity-tested against router copy.
9. Stable errors: define shared error-code table; never log secrets or unbounded attacker-controlled text.

## 2026-10-25 — vIP derivation and deployment reachability

The shared specification requires a deterministic SHA-512-derived vIP with signed `vip_nonce`, `time_bucket`, and policy version. The reviewed NetOS `feat/nls-v1` runtime still allocates a random /128 from a local pool. The spec also notes that a digest-derived /128 may not be routable on production WANs and forbids rewriting digest bits.

**Safe interpretation:** implement the exact derivation; retain lab-only route behavior behind explicit lab configuration; do not claim production routed-WAN bootstrap reachability until a compatible forwarding design is reviewed.

## 2026-10-25 — M4 loss and connection admission

The responder activates after sending M4 but has no proof that the initiator received it. Separately, the Core TCP listener starts a thread for each accepted connection even though lookup operations have their own rate and concurrency caps.

**Safe interpretation:** specify and test bounded M4 retransmission/recovery and add a global connection admission/idle-connection limit. Do not treat successful `sendto` or successful TCP accept as authenticated session completion.

## 2026-10-25 — Exact RDR schema and NLD2 rollout

The reviewed NetOS branch's RDR validator does not explicitly reject all unknown fields, and its active SourceToken payload remains counter-first rather than NLD2.

**Safe interpretation:** reject unknown RDR fields; deploy NLD2 as a coordinated versioned wire-format change with no automatic fallback. Passing NLSC control-protocol compatibility tests does not prove NLH2/NLD2 compatibility.

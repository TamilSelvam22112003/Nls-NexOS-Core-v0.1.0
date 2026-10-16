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
# Deviations — Prompt 2

- The `directory-sync` response currently returns a full signed directory snapshot for every `since_seq`, rather than incremental deltas. This is wire-compatible with the required signed bundle semantics and reduces state ambiguity; delta optimization is deferred.
- Lookup and directory records use the same `NLS-DIR-v1` canonical-CBOR envelope, with the lookup nonce included in the signed RDR payload as well as echoed by the response.
- CLI changes in this prompt: `register-router` accepts repeatable operator-only `--wan-endpoint`, `--gateway-ip`, and `--prefix` flags plus `--rsa-public-key-sha256`; `revoke-router` and `export-directory` were added. Existing token-file behavior and prior registration flags remain supported.
- The custom NLS Control v1 transport remains experimental and is not TLS. Independent cryptographic review is still required.
- Router data-plane session teardown is not changed in Prompt 2; the exposed revocation/freshness accessors are intended for prompts 3–4.


## 2026-10-24 — SourceToken specification reconciliation

- The Core copy of `docs/nls/MASTER_SPEC.md` described AES-256 single-block encryption for SourceToken derivation, while the NetOS master specification and active `nls/source_token.py` implementation define HKDF-SHA-256 followed by HMAC-SHA-256 over a domain-separated message and the sender's packed IPv6 `originalIP`.
- The minimal safe resolution is to synchronize the Core specification to the already-implemented NetOS construction. This is a specification correction only; it does not change runtime behavior or introduce a new cryptographic primitive.
- SourceToken is a pseudonymous routing identifier, not reversible encryption. Inner-packet confidentiality is provided by the separately specified AES-256-GCM payload protection.
- This reconciliation establishes implementation/spec consistency, not independent cryptographic approval. Any future derivation change must be explicitly versioned and tested across both peers; silent algorithm substitution is prohibited.

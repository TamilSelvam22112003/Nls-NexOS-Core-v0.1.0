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


## 2026-10-24 — Metadata mode specification gate (implementation pending)

- The master specification now defines versioned NLD2 data records and explicit `source-only` and `source-destination` policies. The stronger mode conceals both inner endpoint addresses; the source-only mode intentionally exposes the inner destination in authenticated clear metadata.
- The current runtime still uses the prior counter-first SourceToken payload and has no `metadata_mode` configuration. Therefore, these new requirements are NOT IMPLEMENTED in this commit and this branch is not yet a runnable release for NLD2. Runtime changes must follow in a separate implementation gate with regression tests and exact-head CI.
- The NLD2 framing change is intentionally versioned and forbids automatic fallback. Both routers must be upgraded together before enabling it.


## 2026-10-25 — Target-branch conformance gaps (not approved deviations)

- The reviewed NetOS `feat/nls-v1` branch allocates random temporary vIPs instead of the amended SHA-512 derivation with signed `vip_nonce`, `time_bucket`, and policy version. This is a nonconformance gap, not an accepted alternative.
- The reviewed NetOS `feat/nls-v1` branch still emits the legacy counter-first SourceToken payload; the master spec requires NLD2 framing and explicit metadata modes without fallback. A newer implementation exists on a separate branch but is not the reviewed target branch.
- The NetOS RDR v2 validator does not explicitly reject all unknown payload fields.
- The responder's post-M4 activation lacks an explicit proof that the initiator received M4; packet-loss recovery remains unverified.
- Core lookup rate/concurrency caps are implemented, but the TCP listener's thread-per-connection model lacks an evident global connection cap.

These are recorded as unresolved implementation gaps. No protocol deviation is approved by this list; each item must be resolved against the shared master spec or handled through an explicitly versioned design decision.

# Deviations — Prompt 2

- The `directory-sync` response currently returns a full signed directory snapshot for every `since_seq`, rather than incremental deltas. This is wire-compatible with the required signed bundle semantics and reduces state ambiguity; delta optimization is deferred.
- Lookup and directory records use the same `NLS-DIR-v1` canonical-CBOR envelope, with the lookup nonce included in the signed RDR payload as well as echoed by the response.
- The custom NLS Control v1 transport remains experimental and is not TLS. Independent cryptographic review is still required.
- Router data-plane session teardown is not changed in Prompt 2; the exposed revocation/freshness accessors are intended for prompts 3–4.

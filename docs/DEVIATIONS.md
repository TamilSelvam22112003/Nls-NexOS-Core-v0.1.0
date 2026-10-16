# Deviations — Prompt 2

- The `directory-sync` response currently returns a full signed directory snapshot for every `since_seq`, rather than incremental deltas. This is wire-compatible with the required signed bundle semantics and reduces state ambiguity; delta optimization is deferred.
- Lookup and directory records use the same `NLS-DIR-v1` canonical-CBOR envelope, with the lookup nonce included in the signed RDR payload as well as echoed by the response.
- CLI changes in this prompt: `register-router` accepts repeatable operator-only `--wan-endpoint`, `--gateway-ip`, and `--prefix` flags plus `--rsa-public-key-sha256`; `revoke-router` and `export-directory` were added. Existing token-file behavior and prior registration flags remain supported.
- The custom NLS Control v1 transport remains experimental and is not TLS. Independent cryptographic review is still required.
- Router data-plane session teardown is not changed in Prompt 2; the exposed revocation/freshness accessors are intended for prompts 3–4.

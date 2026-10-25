# NLS Core engineering audit — 2026-10-25

## Scope and evidence

This review covers the Core side of the approved `feat/nls-v1` integration and the cross-repository contracts it serves. It is not a cryptographic certification. The files and CI metadata were inspected through GitHub; no local checkout or local test execution was available.

- Core reviewed base head: `1bb3b02bbcbbaa8bc1115584ec923fc7b9daa136`.
- NetOS reviewed base head: `a4dbb8ba75e6893c90e825fa420ec70876efba53`.
- Shared master specification blob on both feature branches: `8346c63f1926c73b7945265f5b92539376b4e9c1`.
- Core CI run `40091955351`: completed successfully, including unit/security tests and cross-repository control integration on Ubuntu 22.04 and 24.04.
- NetOS CI run `40091947203`: completed successfully, including the ten-router IPv6 lab, six-node NLH2 lab, performance gates, package checks and control-protocol compatibility.
- Passing workflow results apply to the exact tested commits. They do not establish full conformance to every amendment in the master specification.

## Confirmed Core implementation

1. The Core service owns Router-CA enrollment, certificate issuance/revocation, SQLite router/certificate records, signed RDR/directory bundles and nonce-bound lookup.
2. Directory lookup requires an authenticated Router-CA-issued client certificate and checks the caller's current router/certificate status. Lookup actions are audited.
3. The Core lookup path applies per-router request rate limiting and per-router/global concurrent-lookup caps.
4. The TCP listener starts a thread for each accepted connection. Lookup caps do not bound all unauthenticated or idle connections, so a separate connection-level resource limit should be assessed.
5. The duplicated `control_protocol.py` implementations use NLSC framing, signed Ed25519 hello messages, X25519/HKDF-SHA-256 key derivation, directional AES-256-GCM records and sequence checks. The cross-repository compatibility test passed in the reviewed CI run.
6. NLS Control v1 (TCP 4790), router handshake NLH2, and the UDP data plane are separate protocol surfaces. A successful control-channel session does not prove an NLH2 data session is trusted.

## Cross-repository acceptance gaps

| ID | Finding | Evidence | Status |
|---|---|---|---|
| C1 | The approved master spec on the two `feat/nls-v1` branches matches by blob SHA, but the NetOS `main` branch has a different newer `docs/nls/MASTER_SPEC.md`. | NetOS main commit `05fb64ae0fa8fa2e6490ac1c5fd6afa66b8c0bda`; feature-branch spec blob `8346c63...` | Confirmed branch/spec divergence; do not merge silently |
| C2 | The reviewed NetOS `feat/nls-v1` implementation still emits the legacy counter-first SourceToken payload, while the shared master spec requires NLD2 framing and explicit `source-only` / `source-destination` modes. A separate metadata-mode implementation branch contains NLD2 code, but it is not the reviewed target branch. | NetOS `nls/source_token.py` at `feat/nls-v1`; shared master spec sections B.3–B.5; separate `feat/nls-metadata-modes-impl-20261024` branch | Confirmed target-branch mismatch |
| C3 | The current amended vIP formula requires SHA-512-derived vIP candidates and signed `vip_nonce`, `time_bucket` and policy-version fields. The reviewed NetOS branch allocates a random temporary /128 and does not yet implement that amended contract. | NetOS `nls/vip.py`, `nls/v2_runtime.py`; shared master spec “vIP derivation” | Confirmed target-branch mismatch |
| C4 | The NLS control protocol is custom experimental cryptography. Passing CI does not establish protocol soundness; independent cryptographic review and hostile-network interoperability testing remain outstanding. | Core `docs/SECURITY_MODEL.md`, `docs/API_SPECIFICATION.md` | Confirmed documented limitation |
| C5 | The end-to-end system still lacks verified evidence of actual OSPF/OSPFv3 LSA propagation and BGP/RIP interoperability. | Shared master spec routing boundary; NetOS routing/LSDB implementation | Not verified |
| C6 | M4 loss can leave the responder activated after sending M4 while the initiator has not accepted it. The protocol needs a tested retransmission/recovery rule or an explicit post-M4 confirmation design. | NetOS `nls/v2_runtime.py:HandshakeV2._handle_m3/_handle_m4` | Confirmed lifecycle risk; test pending |
| C7 | Connection-level resource exhaustion is possible in principle because the listener starts a thread per accepted connection without a visible global connection cap. Lookup rate and concurrency controls are present, but do not alone bound idle handshakes/connections. | `src/nls_nexos_core/control.py:NLSControlServer.serve_forever`, lookup caps in `_dispatch` | Hardening gap; exploitability not tested |

## Required handling of the V1–V11 review

The detailed V1–V11 hypothesis matrix is maintained in NetOS `Documentation/nls/IMPLEMENTATION_AUDIT_2026-10-25.md`. The Core-specific verification boundary is:

- **Router-CA identity and directory:** signed RDRs, pinned directory signer, nonce-bound lookup, caller ACTIVE checks, freshness and revocation fields are implemented in the reviewed branch.
- **Lookup abuse controls:** per-router rate limits and per-router/global concurrent-lookup caps exist. Add a separate bound for total live control connections and verify it under load.
- **Control protocol parity:** passed in the reviewed CI run; this only covers NLSC framing/API compatibility, not NLH2 or NLD2 conformance.
- **Data plane and vIP:** the Core service does not implement the router's active data plane. It cannot be treated as evidence that NetOS uses the approved NLD2 payload or amended vIP formula.
- **Routing:** directory records authorize peer identity; they must not create kernel routes. Actual routing-daemon propagation remains a separate integration gate.

## Gate result

**Core control-plane baseline: PASSED for the recorded CI scope; whole-system conformance: PARTIALLY VERIFIED.** No Core product code was changed in this audit. The NetOS strict-xfail test and audit documentation are on the feature branch, and their latest CI outcome is not yet verified at this report's creation.

## Next actions

1. Confirm the new NetOS audit/test commit's CI result.
2. Keep the two `control_protocol.py` copies parity-tested.
3. Add global connection admission/idle-connection limits and test resource exhaustion safely.
4. Complete the target-branch NLD2 and amended-vIP implementation on NetOS, then run a cross-repository, exact-head lab.
5. Do not claim OSPF/BGP/RIP interoperability or production cryptographic assurance without the corresponding evidence.

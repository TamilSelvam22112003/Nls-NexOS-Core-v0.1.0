# NLS Phase 0 execution report — NexOS Core

**Reviewed branch:** `feat/nls-v1`  
**Reviewed head:** `75164528544661d783803ae531b396504152d220`  
**Review date:** 2026-10-20  
**Scope:** Cross-repository Stage 0 source-of-truth and Router-CA/control-plane review. This is not a runtime test report. No test command or VM/lab was executed in this session.

## Repository responsibility

NexOS Core provides the Router-CA service, registry/directory operations, and the NLS Control v1 transport. The router-side packet forwarding, vIP assignment, replay window, and TUN route installation belong to NetOS. Core should authorize peers and publish signed directory information; it should not mutate a router's kernel route table.

## Current source evidence

| Area | Assessment | Evidence | Runtime/test status |
|---|---|---|---|
| Control channel | **Implemented in source; experimental** | `src/nls_nexos_core/control_protocol.py` defines NLSC framing, signed Ed25519 handshake messages, ephemeral X25519, HKDF-SHA256, directional AES-256-GCM records, and sequence numbers. Its module documentation explicitly says this is not TLS and requires independent cryptographic review. | No Core tests executed in this session. |
| Router authorization | **Present; exact policy needs test evidence** | `src/nls_nexos_core/control_protocol.py:server_handshake` accepts an `authorize_client` callback; Core's control/CA modules are separate from the NetOS data plane. | No authorization-negative test executed in this session. |
| Signed Router Directory Records and freshness | **Specified in repository docs; runtime verification not re-run here** | `docs/nls/MASTER_SPEC.md`, `docs/OPEN_QUESTIONS.md`, and `docs/PHASE0_INVENTORY.md` describe signed directory records, lookup freshness, revocation state, and pinned trust. The existing inventory cites an older baseline and must be revalidated against the current head. | No signature, expiry, replay, or revocation test executed in this session. |
| Router-CA route mutation | **Out of Core's intended responsibility; verify no indirect side effect** | Core source tree is the CA/API/control/registry package; route installation appears in NetOS daemon integration, not in the reviewed Core control protocol. | No route-table observation was performed. |
| Shared control-protocol parity | **Open cross-repository gate** | NetOS `nls/control_protocol.py` and Core `src/nls_nexos_core/control_protocol.py` both implement NLS Control v1, but formatting and constants differ. A compatibility test must establish identical framing, canonicalization, signature preimages, errors, and record behavior. | Cross-repository parity test not executed in this session. |

## Required follow-up before implementation gate

1. Run Core unit/security tests and record exact commands, exit codes, and failure output.
2. Add or run cross-repository compatibility tests against the two current control-protocol implementations.
3. Revalidate signed RDR schema, caller ACTIVE-state enforcement, lookup nonce/request binding, revocation and expiry behavior at the current head.
4. Confirm Core lookup, directory sync, bundle import, and administration operations do not alter any router route state.
5. Record the exact CI run IDs and per-job conclusions; do not infer Core CI status from NetOS results.

## Gate result

**PARTIAL — source-of-truth and responsibility audit recorded; runtime gate not passed.**

- Files changed in this repository by this report: `docs/PHASE0_EXECUTION_REPORT.md`.
- Tests executed: none in this session; no test output is claimed.
- Remaining gaps: exact-head Core test execution, cross-repository control-protocol compatibility validation, and fresh CI evidence.
- Ready for prompt 2: **no** — Prompt 1's required test execution/evidence has not been established in this session.

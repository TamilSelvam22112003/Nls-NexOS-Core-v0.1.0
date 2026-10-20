# Cross-repository architecture reconciliation

Date: 2026-10-20
Branch target: `feat/nls-v1`

## Protocol boundaries

The authoritative `docs/nls/MASTER_SPEC.md` contains a base NLH2 handshake specification and later amendments. Apply amendments only to the fields and behaviors they explicitly supersede; retain the remaining NLH2 authentication, transcript, key-schedule, freshness, replay, and failure requirements.

The implementation must keep three protocol surfaces distinct:

1. **NLS Control v1 (`NLSC`, TCP 4790):** router enrollment, authenticated control records, registry lookup/synchronization, policy and revocation state.
2. **Router handshake (`NLH2`):** sealed, signed, versioned router-to-router handshake messages and authenticated session establishment.
3. **NLS data plane:** the current master-spec SourceToken amendment supersedes legacy NLE2 outer-header/data-demultiplexing behavior where explicitly stated. Encrypted payload carries the original IP packet and message type; per-direction SourceTokens select the data session.

A control-channel session is not evidence of an established NLH2 data session. Likewise, an OSPF/BGP adjacency or a reachable endpoint does not establish NLS trust.

## Core responsibilities and cross-repository contracts

- Own Router-CA enrollment, certificate issuance/revocation, authoritative SQLite registry, signed RDRs, nonce-bound peer lookup, directory bundles, policy, and revocation synchronization.
- Require authenticated and authorized callers; enforce ACTIVE status, rate/concurrency limits, record sequence monotonicity, and audit records.
- Keep CA signing private keys on the CA service. Routers receive only pinned trust material and their own private identity keys.
- Preserve ordered `wan_endpoints` semantics: the first endpoint defines canonical `originalIP` under the current amendment. Reject absent, invalid, or inconsistent `originalIP` values.
- Ensure CA metadata can authorize a peer but cannot create kernel routes.
- Keep the duplicated `control_protocol.py` implementation compatible with NetOS and validate the copies with an explicit cross-repository compatibility test.

## Confirmed implementation boundary

Core `src/nls_nexos_core/control_protocol.py` declares `MAGIC=b"NLSC"` and canonical JSON. The README documents this as the separate experimental TCP control channel. It is not the router-to-router NLH2 handshake and must not be conflated with the data plane.

NetOS `nls/handshake.py` retains legacy `NLSH`/JSON helpers, but the active daemon imports the v2 NLH2 APIs from that module. The remaining active-path gaps are the amended M1 field/disclosure contract, deterministic vIP derivation and the SourceToken data plane (NetOS still uses the legacy NLE2 header). These must be migrated with regression tests; the existence of legacy helpers is not proof that the active handshake uses NLSH.

## Gate before implementation changes

Verify the Core registry schema, lookup response signature, caller authorization, status/freshness checks, revocation synchronization, and admin authorization in code. Then run unit/security tests and the cross-repository compatibility test. No test execution is claimed by this document.

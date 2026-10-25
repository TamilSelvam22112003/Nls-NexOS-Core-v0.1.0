# NLS Stage 4 — Threat Model and Security Validation Matrix

**Status:** Draft engineering artifact; not a security certification.
**Baseline:** Stage 3 specification branch `docs/stage3-spec-freeze`; implementation observations are from NetOS branch `feat/nls-v1` at the time this document was prepared. Re-run all checks against exact commit SHAs before release.
**Scope:** Router-CA directory and signed Router Directory Records (RDRs), NLH2 M1–M4, vIP derivation and binding, VIP Table, Trust Table, NLE2 data plane, route/prefix authorization, revocation, replay protection, persistence, resource exhaustion, and cross-repository compatibility.

## 1. Security objectives and assets

1. **Peer identity authenticity:** a router is accepted only when its identity, public keys, certificate, status, and signed directory record agree with authoritative Router-CA data.
2. **Confidentiality and integrity:** protected inner packets and handshake secrets remain confidential and authenticated; unauthenticated input must not change trusted state.
3. **Metadata minimization:** the outer handshake/data-plane representation does not expose the original client/server address where the normative protocol says it must be concealed. A vIP is not an authorization credential by itself.
4. **State consistency:** VIP Table and Trust Table transitions are bound to the same peer identity, certificate/key version, session and policy decision. A stale lookup or concurrent handshake cannot overwrite newer verified state.
5. **Authorization:** successful cryptographic authentication does not itself authorize arbitrary source addresses, destination prefixes, gateways, routes, or forwarding.
6. **Freshness and revocation:** expired, disabled, revoked, stale, rolled-back, or unusable directory records fail closed; the revocation-to-session-invalidation bound must be explicit and testable.
7. **Availability within defined limits:** malformed or unauthenticated traffic cannot cause unbounded memory, CPU, directory lookups, pending handshakes, logging, or response amplification.
8. **Interoperability and reproducibility:** NetOS and NexOS Core implement the same normative wire formats and policy semantics, with deterministic vectors and negative tests.

## 2. Trust boundaries

- **B1 — Untrusted network ingress:** arbitrary UDP datagrams, forged source addresses, packet reordering, duplication, delay, truncation, and floods.
- **B2 — Router-CA control plane:** enrollment/admin APIs, signed directory records, status/revocation feeds, persistence and cache freshness.
- **B3 — Handshake parser to state machine:** decoded fields are untrusted until schema, signature, timestamp, directory, policy and transcript checks succeed.
- **B4 — VIP Table to Trust Table:** candidate address allocation/reservation must not be mistaken for peer authentication or an established session.
- **B5 — Control plane to data plane:** a trusted session must not implicitly grant forwarding outside the authorized inner address/prefix/gateway set.
- **B6 — Local host and persistence:** privileged configuration, key files, route changes, restart recovery and clock integrity.
- **B7 — Cross-repository release boundary:** independently versioned NetOS and NexOS Core implementations, schemas, defaults and CI gates.

## 3. Threat register

Severity is an initial engineering priority, not a measured exploitability score. “Observed gap” means a source/spec discrepancy or verification gap was identified; it does not mean a working exploit has been demonstrated.

| ID | Threat / attack path | Impact | Required control / test oracle | Current evidence / status |
|---|---|---|---|---|
| TM-01 | **M1 schema divergence:** peers send different field sets or semantics for the same protocol version | Handshake failure, downgrade pressure, inconsistent security checks | Strict single canonical M1 schema; golden byte vectors; reject missing, extra, duplicate and wrongly typed fields on both implementations | **Observed spec/code mismatch.** Stage 3 requires expanded hybrid M1 fields; NetOS `nls/handshake.py` currently declares the older M1 field set. Block release pending resolution and tests. |
| TM-02 | **vIP derivation substitution:** allocate a local pool address instead of deriving/recomputing the specified vIP | Peer disagreement, address binding failure, potential identity/metadata policy bypass | Deterministic derivation vectors; both peers independently derive from identical canonical inputs; mismatch must fail closed; no fallback allocation | **Observed spec/code mismatch.** Runtime contains `self.vip.allocate()`; Stage 3 specifies derivation. Confirm exact call path and migrate only after spec approval. |
| TM-03 | **RDR forgery or signer substitution** | Impersonation, wrong keys/certificate trusted | Verify directory signature and signer pin/authority; canonical encoding and domain separation; tamper every signed field and require rejection | Schema/envelope checks are present in inspected NetOS code; full end-to-end adversarial test results **unverified**. |
| TM-04 | **Unknown-field / legacy RDR acceptance** | Parser differentials, security-field smuggling, downgrade | Exact required field set, explicitly allowed optional fields only; reject unknown fields and missing `rdr_version`; test all message boundaries in both repos | NetOS handshake schema has exact RDR payload field-set checks. Cross-boundary consistency and Core parity **unverified**. |
| TM-05 | **Identity/key substitution between M1, RDR, certificate and registry** | Attacker binds a valid signature to another endpoint or key | Require router ID, Ed25519 key, RSA key, certificate serial, endpoint and authoritative RDR to agree; test one-field-at-a-time swaps | Runtime contains key/RDR comparison and signature validation paths; complete mismatch matrix **unverified**. |
| TM-06 | **vIP collision, replay, time-bucket abuse or forged outer source** | Session misbinding, stale identity accepted, reachability failure | Specify byte encoding and candidate selection precisely; test nonce length/uniqueness, bucket boundary ±1, replayed nonce, collision exhaustion and outer-source equality | Stage 3 defines the intended behavior; interoperability vectors and adversarial results **not run**. |
| TM-07 | **Handshake replay / transcript substitution** | Reused session, key confirmation bypass, stale M1 accepted | Bind M1–M4 transcript, session ID, role, nonces, selected algorithms and peer identity; replay each message before/after completion and across sessions | Replay window and transcript helpers exist in NetOS; full state-machine fuzz/replay results **unverified**. |
| TM-08 | **VIP Table race or stale write** | Expired/revoked identity reintroduced; session points at wrong peer | Atomic compare-and-swap on identity/version/session; state transitions explicit; stale completion cannot overwrite newer record; concurrent handshake/revocation tests | Lifecycle invariants are normative; concurrent and crash-interleaving tests **unverified**. |
| TM-09 | **Trust Table over-trust** | Pending/unverified peer gains forwarding authority | Trust requires verified VIP plus matching current authoritative evidence; no trust from address allocation or handshake partial state; negative transition tests | Architecture requires separation; end-to-end lifecycle verification **unverified**. |
| TM-10 | **Revocation race / stale cache / rollback** | Revoked router keeps sessions or re-enters via stale RDR | Define maximum revocation propagation and session teardown time; monotonic record sequence; stale/rollback feed rejection; invalidate VIP, Trust, keys, routes and sessions | Runtime checks revocation paths; enforceable maximum bound remains an **open release decision**. |
| TM-11 | **Unauthorized inner source/destination or route injection** | Spoofing, lateral movement, traffic redirection | Enforce per-peer authorized inner prefixes/gateways on ingress and egress; reject unassigned source, out-of-prefix destination, unauthorized control-plane route; test IPv4/IPv6 negative cases | Critical security test gap from prior review; pass evidence **not available**. |
| TM-12 | **NLE2 ciphertext modification / nonce reuse / rekey race** | Data forgery, confidentiality loss, session desynchronization | AES-GCM tag failures drop without state mutation; unique directional nonce per key; rekey before packet/time limit; simultaneous rekey and counter-boundary tests | NLE2 and replay/rekey mechanisms exist; independent adversarial validation **unverified**. |
| TM-13 | **Replay-window poisoning / concurrent duplicate processing** | Legitimate packets dropped or replay accepted | Authenticate before marking sequence; atomically update replay window; duplicate and out-of-window packets dropped; concurrency stress test | ReplayWindow is used; exact concurrent behavior and mark-after-auth tests **unverified**. |
| TM-14 | **Resource exhaustion / amplification** | Handshake service or router unavailable | Global token bucket plus per-interface and per-source-/64 limits; bounded pending state and lookups; response no larger than allowed amplification budget; test floods and cleanup | Runtime has pending-limit and amplification checks; aggregate rate limits and flood behavior **not proven by test results**. |
| TM-15 | **Malformed packet parser differential** | Crash, memory/CPU spike, inconsistent acceptance | Property/fuzz tests for truncated headers, lengths, CBOR/JSON types, nested map/array bounds, oversized datagrams and invalid IP payloads | Parser has explicit size/type bounds; fuzz coverage and crash-free results **unverified**. |
| TM-16 | **Certificate expiry, endpoint drift or clock manipulation** | Stale or misdirected peer accepted | Validate validity windows, endpoint canonicalization and allowed skew; handle clock rollback safely; test expired/not-yet-valid certificates and endpoint changes | RDR validation and timestamp paths exist; clock rollback and drift tests **unverified**. |
| TM-17 | **Crash/restart persistence inconsistency** | Reused nonce/counter, stale trust or routes after restart | Persist anti-replay/key state as required; fail closed on corruption or rollback; reconcile VIP/Trust/session/route state on startup; power-loss fault tests | Persistence/recovery invariants lack current-head test evidence. |
| TM-18 | **Cross-repository protocol drift** | NetOS/Core incompatible registry or control messages | Shared fixtures, schema contract tests, both-repo CI against identical vectors, explicit protocol version compatibility matrix | Prior review noted a control-message CLOSE compatibility gap; current-head cross-repo matrix **unverified**. |
| TM-19 | **Traffic analysis / metadata leakage** | Observers infer endpoints, topology, timing or identity | Document exactly which fields remain visible; capture packets at each hop; assert no original endpoint/certificate leakage in outer headers/logs; state residual timing/size leakage | Metadata minimization is a design goal; packet-capture proof **not run**. |
| TM-20 | **CA or router private-key compromise / unsafe local admin** | System-wide impersonation or unauthorized policy changes | Key permissions, rotation/revocation, audited admin operations, least privilege, backup/recovery and incident procedure; verify audit log integrity | Control-plane controls exist in part; full operational hardening assessment **not completed**. |

## 4. Required security validation suites

These are release gates, not claims that tests have already passed.

### A. Protocol conformance
- Same deterministic M1–M4, RDR and vIP vectors consumed by both repositories.
- Exact field-set/type/length tests for every message and nested object.
- Unknown fields, duplicate keys, legacy version, malformed encoding and unsupported policy version must fail closed.
- Cross-implementation initiator/responder matrix: NetOS↔NetOS, Core registry↔NetOS, and any supported Core peer role.

### B. Identity, trust and lifecycle
- Mutate each identity-bearing field independently: router ID, Ed25519 key, RSA key, certificate, serial, originalIP, WAN endpoint, record sequence, status and validity interval.
- Exercise every VIP and Trust state transition, including lookup timeout, lookup rate limit, revocation during each handshake flight, peer key rotation, simultaneous handshakes, stale completion and restart.
- Assert no pending/unverified state can install a trusted route or authorize forwarding.

### C. Data plane and authorization
- Valid packet round trip for IPv4 and IPv6, both directions and multiple sessions.
- Bit-flip ciphertext, tag, header/AAD, session ID, sequence number and inner addresses; require drop without replay/state mutation.
- Replay duplicates, reorder, window edges, sequence exhaustion, rekey threshold and simultaneous rekey.
- Attempt unauthorized inner source, destination, gateway and prefix; require drop and no route/neighbor side effect.
- Capture outer traffic and verify the documented metadata-leakage assertions.

### D. Abuse, availability and recovery
- Fuzz parsers and malformed datagrams with memory/CPU/pending-state bounds.
- Flood global, per-interface and per-source-/64 limits; verify fairness and recovery after rate-limit expiry.
- Simulate Router-CA unavailable, stale response, rollback, revocation feed delay, corrupt persistence, process kill and host reboot.
- Test PMTU/fragmentation, IPv6 minimum MTU, NAT/firewall/bootstrap return path, and real WAN reachability separately from isolated lab success.

### E. Evidence quality
Every test report must record repository, branch, exact commit SHA, OS/kernel, Python/runtime versions, command, test fixture/vector version, exit status, and raw logs. A green historical CI run or an unpinned local run is not evidence for a newer commit.

## 5. Prioritized remediation order

1. **P0 — Resolve normative M1 and vIP derivation mismatch** before protocol implementation is treated as spec-conformant.
2. **P0 — Prove authorization boundaries** for inner prefixes, routes, VIP/Trust promotion and forwarding.
3. **P0 — Set a concrete revocation-to-invalidation bound** and test cache/session/route teardown against it.
4. **P1 — Build shared cross-repository vectors** and exact RDR/M1 schema negative tests.
5. **P1 — Prove replay/rekey/concurrent state safety** and crash recovery.
6. **P1 — Exercise rate limits, amplification and parser fuzzing** with bounded resource assertions.
7. **P2 — Validate metadata leakage, PMTU/NAT/WAN behavior and reproducible performance** on pinned current heads.

## 6. Open decisions — do not invent defaults

The following need an explicit spec-owner decision before the threat model can be marked approved:
- Maximum revocation publication, cache-observation, session invalidation and route withdrawal latency; specify each bound separately.
- Exact canonical byte encoding and field order for vIP derivation, including IP address representation, certificate/key representation, nonce placement, time-bucket encoding, domain separation and policy version.
- Whether live Router-CA unavailability always fails closed for new handshakes and what bounded behavior is permitted for existing sessions.
- Exact authorized inner-prefix and gateway policy source and its update/rollback semantics.
- Which supported roles are implemented in each repository and the compatibility contract for control messages, including CLOSE.
- Explicit acceptance criteria for metadata leakage and minimum acceptable throughput/latency under a pinned test environment.

## 7. Exit criteria for Stage 4

Stage 4 is **not complete** until:
- Each threat has an owner, severity, mitigation, and reproducible test ID.
- All P0 decisions are resolved or explicitly block release.
- The M1/vIP specification and implementation are aligned through reviewed vectors and negative tests.
- The same security contract is validated across both repositories at exact commit SHAs.
- Evidence distinguishes PASS, FAIL, BLOCKED and UNVERIFIED; no gap is labeled PASS merely because the code path exists.

**Current decision: BLOCKED for release certification.** This is a documentation-based risk assessment. It is not a penetration-test report, does not establish exploitability, and does not claim that any test suite has been executed.

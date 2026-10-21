# ADR: Hop-by-Hop NLS Data Plane

- Status: Proposed architecture decision, pending review and implementation gates
- Decision date: 2026-10-21
- Scope: NLS router data plane across NetOS and NexOS Core
- Change class: Documentation only; no packet-processing code is changed by this ADR

## Decision

NLS will use **hop-by-hop protection** for transit traffic. Each adjacent router pair establishes an authenticated session. A sending router protects each packet with the session key for the next hop. The receiving router authenticates and decrypts that hop's packet, validates its metadata and replay state, chooses the next hop from the routing plane, updates the hop-level source/destination metadata, and protects the packet again under the session for the next adjacent router.

This supersedes the previous assumption that transit routers forward one end-to-end encrypted inner IP packet without decrypting it. The two models must not be mixed in one implementation or described as equivalent.

## Security and visibility consequences

1. A transit router is a trusted security endpoint for its incoming and outgoing hop sessions. Fields decrypted at that router are visible to that router.
2. Hop-by-hop protection **does not** hide the original source IP from every transit router if the original source IP is included in the per-hop plaintext. Do not claim that it does.
3. If end-to-end concealment of the originating client identity is also required, the protocol must carry a separate end-to-end encrypted origin-identity field inside the hop-protected payload. The hop-level source identity must identify the immediate sending router; it must not overwrite or impersonate the origin identity.
4. The routable outer destination (next-hop endpoint) remains visible to the underlay. Outer source-address behavior and whether the next-hop virtual identity is exposed must be specified separately.
5. Each hop must use independently derived directional keys and a unique AEAD nonce per key. Authenticate the complete NLS header as AEAD associated data. Reject invalid tags, wrong peer/session bindings, stale or duplicate sequence numbers, expired sessions, and unsupported versions before forwarding.
6. A router must never forward a packet that failed authentication or replay validation. Fail closed on missing, revoked, expired, or mismatched peer identity. Emit redacted audit events; do not log keys, tokens, decrypted payloads, or source-identity secrets.
7. Re-encryption at every hop adds cryptographic work and means compromise of a transit router can expose that hop's plaintext. Security claims and threat models must state this explicitly.

## Required per-hop processing

For a packet arriving at router R_i from R_(i-1):

1. Resolve the ingress peer and active session from the receiving interface/session identifier. Do not trust an unauthenticated packet field as the peer identity.
2. Enforce packet-size limits and validate the fixed header before allocating large buffers.
3. Authenticate/decrypt with the ingress direction's AEAD key, with the exact NLS header authenticated as associated data.
4. Enforce session binding, monotonic sequence/replay-window rules, lifetime, and current trust/revocation state.
5. Validate the decrypted packet and routing policy. Do not accept the packet's claimed next hop as authoritative when it conflicts with the local routing table or policy.
6. Select R_(i+1) through the existing routing plane (including FRRouting-managed OSPF/BGP routes where configured); preserve unrelated routes and routing-daemon configuration.
7. Set hop-level source identity to R_i and next-hop destination/session identity to R_(i+1). Preserve any origin identity as a separate field; never silently replace it.
8. Encrypt/authenticate with R_i→R_(i+1)'s directional session key, fresh nonce, and authenticated header; then transmit to the next hop.
9. If no valid next-hop session exists, queue only within a bounded policy or drop and report a redacted reason. Never send plaintext as a fallback.

Return traffic follows the same steps with independent reverse-direction keys and replay state.

## Key establishment and Router-CA

- Router-CA enrollment and signed directory lookup provide router identity and peer material; a directory response alone is not a data-plane session.
- The peer identity, certificate status, advertised endpoint, and signing key must be bound to the handshake transcript.
- NLH2 M1–M4 must be verified message-by-message, including signature, transcript binding, freshness, downgrade handling, and failure cleanup.
- Derive separate directional hop keys from the authenticated key agreement using HKDF-SHA-256 with protocol/session context. Do not use RSA public-key encryption to generate a fresh symmetric key independently for each data packet.
- Revocation, certificate expiry, session expiry, peer endpoint changes, and rekey must invalidate or replace affected hop sessions without disturbing unrelated routes.

## vIP role and lifecycle

The normative SHA-derived vIP input encoding, hash/truncation, address-policy version, nonce/time-bucket checks, and peer validation are specified by the hybrid NLH2 amendment in `docs/nls/MASTER_SPEC.md`. That specification—not this ADR—remains the wire-level source of truth. Implementation and deterministic validation are still pending.

- vIP is a temporary bootstrap address for the authenticated NLH2 M1–M4 exchange only. It is not a carrier for client/server payload and must not be used as the post-handshake data-plane address.
- “Original data of hop-A” means the peer's authoritative router identity and original endpoint details needed for trust validation; it does not mean application payload.
- After those details are authenticated and M4 is verified, routers switch to the authenticated real endpoint/session addressing and retire the vIP. Failed or timed-out handshakes clean up temporary state.
- A vIP has finite validity, is bound to the handshake/session context, and must not be reused to revive an expired session. Stale, replayed, retired, or revoked mappings are rejected.
- Interface-IP changes require authenticated peer revalidation and a controlled endpoint/session update or new handshake. An IP address alone never proves router identity.
- Retiring a vIP must not silently break an otherwise valid session; if the established session expires or its endpoint binding changes, traffic pauses/drops until a valid replacement session is established. Never fall back to plaintext.
- Tests must cover post-M4 vIP absence, success/failure/timeout cleanup, stale/replay rejection, interface-IP changes, and valid session replacement.

The existing random temporary-address allocator is not evidence that the SHA-derived vIP design is implemented. No implementation or test pass is claimed here.

## Acceptance gates before implementation is approved

- [ ] Update the authoritative MASTER_SPEC in both repositories to this model and cross-reference the same ADR.
- [ ] Specify the packet wire format, hop metadata, origin-identity handling, AEAD associated data, nonce/sequence rules, MTU overhead, fragmentation behavior, and failure codes.
- [ ] Specify and test SHA-derived vIP deterministically, including collision, expiry, stale mapping, and spoofing cases.
- [ ] Add negative tests for invalid tag, replay, wrong peer, certificate mismatch/revocation, expired session, malformed header, missing next-hop session, and attempted plaintext fallback.
- [ ] Demonstrate bidirectional traffic over at least four routers with packet captures proving hop ciphertext changes at every hop and plaintext is never emitted on transit links.
- [ ] Explicitly test the visibility boundary: transit routers can see hop-decrypted fields; any origin identity claimed to be concealed must remain end-to-end encrypted.
- [ ] Verify OSPF/BGP adjacency, convergence, route preservation, MTU/MSS, and recovery after session loss.
- [ ] Obtain fresh Ubuntu 22.04 and 24.04 CI runs on exact branch heads and retain logs/artifacts.
- [ ] Do not merge implementation changes until the Phase 0 gate and required reviews are satisfied.

## Non-goals and claims

This decision does not claim that NLS is better than TLS, IPsec, or another protocol. It selects a packet-processing architecture only. Security, privacy, performance, and interoperability claims require measured evidence.

## Repository coordination

This ADR must remain substantively identical in:
- NetOS: `docs/nls/HOP_BY_HOP_DATA_PLANE_DECISION.md`
- NexOS Core: `docs/nls/HOP_BY_HOP_DATA_PLANE_DECISION.md`

The two repositories must agree on packet format, handshake/session semantics, identity visibility, vIP semantics, and failure behavior before implementation proceeds.

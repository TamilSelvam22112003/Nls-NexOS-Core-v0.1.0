ROLE
You are a principal network-security engineer. Over 5 gated prompts you will complete NLS (Network Layer Security) inside two existing repositories. This is PROMPT 1 of 5. Nothing is complete until all 5 gates pass.

REPOSITORIES (work on branch feat/nls-v1 in each; never touch main; no force-push; commit in small steps)
- Router (NetOS): github.com/TamilSelvam22112003/NlsxNetOS-v0.1.0. Python packages at repo root (nls/, security/, tools/, services/, net/, kernel/), tests in tests/, docs in Documentation/, CI in .github/workflows/.
- CA (NexOS Core): github.com/TamilSelvam22112003/Nls-NexOS-Core-v0.1.0. Package in src/nls_nexos_core/, SQLite registry, NLS Control v1 on TCP 4790, docs in docs/.
Both repos copy control_protocol.py (nls/control_protocol.py and src/nls_nexos_core/control_protocol.py); keep them compatible and add a cross-repo compatibility test.

GROUND RULES (apply to all 5 prompts)
G1 Evidence only. Never claim "100%", "fully secure" or "complete" without evidence. Never describe an unrun test as passing. Paste the final summary line of every test command and every failure in full.
G2 Never guess silently. Ambiguity goes to OPEN_QUESTIONS.md with the safest reading behind a config flag. Every departure from this spec goes to DEVIATIONS.md with a reason.
G3 No placeholders, TODOs, stubbed crypto or invented primitives. Use only the `cryptography` library (and `cbor2`, pinned, for CBOR). Constant-time comparisons, secure randomness, no secrets in logs.
G4 Preserve existing behavior unless this spec changes it: IOS-like CLI (`sudo nlsxnetos`), vtysh/FRR untouched, GUI safety, installer/uninstall, NLS disabled by default, existing tests still passing (adapt tests only where this spec deliberately changes behavior, and say so).
G5 Every prompt ends with: gate result, files changed, real test output, remaining gaps, and "ready for prompt N+1: yes/no". Then STOP.

STEP A: VERIFY FINDINGS (skip any already verified earlier in this thread; say so)
For each item below mark CONFIRMED, DISPUTED, or PARTIAL with file:function evidence. For items marked "test", write a failing or demonstrating test and run it.
V1 CA revocation list is written (nls/ca_client.py:_persist_bundle) but never read by the data plane.
V2 The handshake "certificate" (nls/handshake.py:new_init) is a self-signed dict matched against local YAML; the CA is not consulted during NLS connection setup.
V3 Session send_key/recv_key are derived but never used for data packets.
V4 The vIP is only a string; never assigned to an interface or used as outer source.
V5 Handshake is cleartext signed JSON.
V6 _send_init requires the CA entry endpoint to equal the listen endpoint (no NAT); nls_role: wan is required.
V7 (test) One forged high-sequence packet poisons the ReplayWindow.
V8 (test) A packet built from only the destination RSA public key plus cleartext session_id and router_identity is accepted by open_ip_packet.
V9 (benchmark) Per-packet RSA-3072 OAEP unwrap cost and resulting single-core throughput bound.
V10 (test) _handle_init blocks a peer for 60 s on any failure, so spoofed garbage INIT can lock out a real router.
V11 CA metadata creates routes (auto_router_ca to install_tun_routes). This must stop.

MASTER SPEC (the single source of truth for all 5 prompts)
Players: Router S (source), Router D (destination), Router-CA. Routers are ordinary hosts between S and D; the client LAN is behind S, the server LAN behind D.

Keys and records
- Each router has an Ed25519 identity key (in its CA-issued X.509 certificate, CN = router_id) and an RSA-3072 encryption key.
- Router Directory Record (RDR), signed by the Router-CA control identity key (Ed25519, pinned by routers out of band; sign with domain-separation string "NLS-DIR-v1"): router_id, ed25519_public_key, rsa_encryption_public_key, wan_endpoints, gateway_ips, prefixes (the prefixes behind that router), certificate_serial, status (ACTIVE/REVOKED/DISABLED/EXPIRED), record_seq, issued_at, valid_until.
- Lookup(router_id, client_nonce) returns a signed RDR plus the nonce, valid for at most 30 s. Directory bundles (batch of RDRs, revoked serials, policy) are signed and expire (default 10 min). Fail closed when freshness is lost (stale-grace default 0).
- Policy from the CA: allowed suites, minimum versions, replay window (default 128), timeouts.

Suite (v1, only one): X25519 key agreement, HKDF-SHA256, AES-256-GCM, Ed25519 signatures, RSA-OAEP-SHA256 (3072-bit) key wrapping.
SEAL(recipient_rsa_pub, plaintext, aad): random 256-bit key K, RSA-OAEP wraps K, AES-256-GCM(K, 96-bit random nonce, plaintext, aad). Signature is made inside the plaintext (sign-then-seal); AAD binds magic, version, type and session_id.
Encoding: deterministic CBOR (canonical=True). Handshake datagram: magic "NLH2" | version(1) | type(1) | session_id(16) | length(2) | SEAL envelope.

Stages (strict order; any failure drops silently on the wire, logs a reason code, tears down state)
S1 Router authentication: certificate chain to the pinned CA root, matching RDR, status ACTIVE and not expired.
S2 Bootstrap with vIP (mandatory):
  - S derives a fresh per-handshake `vip` as cryptographic context only; it MUST NOT assign that address to an interface or use it as an outer locator. The selected v1 profile uses the authenticated primary WAN locators for all M1–M4 outer endpoints.
  - M1 (S to D, outer source = S's authenticated primary WAN locator, outer destination = D's authenticated primary WAN endpoint): SEAL(D.rsa_pub from S's CA directory, {session_id, S.router_id, S.ed25519_pub, S.rsa_pub, nonce_s, timestamp, vip, sig_S}), padded so M1 is at least as large as the maximum M2 (anti-amplification). D does an early local screen of M1's claimed keys against its cached directory (fail closed if unknown/revoked/mismatched). This is not a replacement for S4.
  - M2 (D to S's authenticated primary WAN locator): SEAL(S.rsa_pub, {session_id, D.router_id, D.certificate, D.RDR, gateway_ips, sa_proposals, dh_pub_D (X25519), nonce_d, ike_meta, H1 = hash(M1 plaintext), sig_D}).
S3 Source cross-check: S live-looks-up D (fresh signed lookup), compares every M2 detail (certificate serial, keys, WAN endpoint, gateway IPs, SA proposals within CA policy, no downgrade). Any mismatch means drop and abort. All match means M3.
  - M3 (S to D, outer source = S's authenticated primary WAN locator): SEAL(D.rsa_pub FROM THE CA RECORD, never from M2, {session_id, S.certificate, S.RDR, dh_pub_S, chosen_sa, S.wan_endpoint, H2 = hash(M1..M2), sig_S}).
S4 Destination cross-check: D live-looks-up S, compares M3 details and the M1 keys against the CA record. Mismatch means source untrusted, abort and log. Match means D derives keys and sends M4.
  - M4 (D to S's authenticated primary WAN locator): SEAL(S.rsa_pub FROM THE CA RECORD, {session_id, "trust": true, H3 = hash(M1..M3), confirm = HMAC-SHA256(k_confirm, H3), sig_D}).
S5 Session activation: after S verifies M4, both routers continue using the authenticated WAN locators for the handshake and the approved post-M4 SourceToken profile for data. The derived `vip` is never installed as an interface address or route and is not a routable endpoint; no `VIP_AFTER_SWITCH` outer-address transition is needed for it.
Key schedule: shared = X25519(dh_S, dh_D), reject all-zero. salt = SHA256(H3 || nonce_s || nonce_d). HKDF-SHA256 with labels including both router_ids: c2s key, s2c key, c2s iv-prefix, s2c iv-prefix, k_confirm.
Data plane: header = magic "NLE2"(4) | version(1)=2 | flags(1)=0 | reserved(2)=0 | session_id(16) | seq(8) = 32 bytes, used as AEAD AAD. AES-256-GCM, nonce = iv-prefix(4) || seq(8), separate key per direction, no per-packet RSA. The original IP packet (including source IP) is the plaintext; the header carries no inner addresses. Replay window (default 128) advances only after authentication succeeds. Rekey (new handshake, make-before-break) at 2^32 packets or 1 hour. Overhead: outer IPv6 40 + UDP 8 + 32 + 16 tag = 96 bytes (compute TUN MTU from it).
Forwarding: D decrypts and forwards the inner packet via kernel routing. D drops the inner packet unless the inner source is inside S's RDR prefixes (`enforce_inner_source_prefix`, default true).
Routing: routes into the TUN come only from operator-configured `nls route <prefix> via <router-id>`. CA data may authorize, never create routes.
DoS: handshake state is minimal until M3 validates. Rate-limit by outer source address, never by claimed identity. A failed or garbage M1 must not block a legitimate peer. Cap pending handshakes. Handshake timeout 5 s.
Failure semantics: drop silently on the wire; structured JSON log with a stable reason code (NLS_<AREA>_<REASON>); no secrets in logs (test with canary values).
Trust modes: `ca` (default; live lookups) and `offline` (verifies a CA-signed directory bundle imported by the operator; no live lookups; marked as degraded freshness). The unsigned Router-CA YAML is removed from the trust path.

STEP B: DOCUMENTATION (docs and tests only; no product code in this prompt)
1. Router repo: Documentation/nls/protocol.md, handshake.md, packet-format.md, key-management.md, replay-protection.md, virtual-ip.md, trust-model.md updated to this spec, with byte-level layouts, state machines for S, D and CA, key schedule, and the error-code table. Plus Documentation/security/threat-model.md (MITM, replay, impersonation, downgrade, rogue CA response, vIP abuse, DoS, amplification) mapping V1-V11 to threats.
2. CA repo: docs/API_SPECIFICATION.md gets the new messages (lookup, directory-sync, enrollment extension carrying the RSA public key with proof of possession, revoke-router) and docs/SECURITY_MODEL.md the signing and freshness rules.
3. DEVIATIONS.md, OPEN_QUESTIONS.md and TRACEABILITY.md in each repo. The matrix lists R1-R14 and S1-S5 against planned file/function, planned test, and status "not started".

STEP C: LAB SCAFFOLD
Reuse the style of tests/integration/test_four_node_nls.py. Build a reusable pytest fixture that creates a network-namespace lab: client, routerA, wan, routerB, server, ca (v6 addressing, veth pairs, forwarding on the WAN node). Add the full required test list as strict xfail tests, each with a docstring naming its requirement: valid handshake and end-to-end traffic; wrong certificate; revoked router; expired certificate; CA mismatch in S3; CA mismatch in S4; forged CA response; tampered ciphertext; replayed packet; out-of-window packet; replay-window poisoning (V7); data forgery (V8); vIP reuse after expiry; no vIP on the wire after the switch; SA downgrade; out-of-order handshake messages; spoofed garbage M1 cannot block a legitimate peer (V10); amplification bound; CA unreachable fails closed; rekey; routes not created from CA metadata (V11); logs contain no secrets; pcap proves inner IP packet and original source IP never appear in plaintext.

GATE FOR PROMPT 1: verification table complete; docs written; lab fixture runs (existing tests still green); all new tests collected as strict xfail. Then STOP; do not start prompt 2.

## Hybrid NLH2 amendment: CA-verified, time-bucketed vIP

This amendment supersedes conflicting legacy statements about RDR fields, vIP derivation, M1 contents, and M1–M4 outer headers. NLH2 framing, sealing, signatures, transcript hashes, X25519/HKDF key schedule, AEAD data plane, fresh CA cross-checks, replay protections, authenticated endpoint validation, and failure semantics remain the security base. Any legacy vIP-based endpoint-switch example is superseded by the Stage 7 locator rules.

### RDR primary WAN address

Add `originalIP` to every Router Directory Record (RDR). `wan_endpoints` is an ordered list and its order is significant: `wan_endpoints[0]` defines `originalIP`; updates MUST preserve the supplied order, and the RDR signature MUST cover the endpoint list in that order. Changing the first endpoint changes `originalIP`. The first endpoint MUST use bracketed IPv6 endpoint syntax `[IPv6]:PORT`; its port MUST be an integer from 1 through 65535. IPv6 zone identifiers (any `%...` suffix) are forbidden. Parse the address component with IPv6 canonicalization and set `originalIP` to that canonical IPv6 address, excluding brackets and port. Reject unspecified, loopback, multicast, link-local, and IPv4-mapped IPv6 addresses; ULA addresses are allowed. Additional endpoints retain the existing supported IP:PORT formats (bracketed IPv6 `[IPv6]:PORT` or IPv4 `IPv4:PORT`); hostnames are not supported. Registration and update MUST reject an invalid first endpoint or an `originalIP` inconsistent with it. An RDR with an absent, invalid, or inconsistent `originalIP` is invalid and MUST NOT be used for a handshake. The full certificate is the CA-issued X.509 certificate in DER encoding; public keys used in the vIP input are DER SubjectPublicKeyInfo encodings.

### vIP derivation

The source router S computes a per-handshake vIP before sending M1. M1 MUST contain a fresh cryptographically random 32-byte `vip_nonce` and a `time_bucket` equal to floor(Unix-time-seconds / 30). These fields are covered by the M1 signature and sealing. The time bucket is an unsigned 64-bit big-endian integer.

#### Candidate validation and nonce redraw

S MUST derive a candidate vIP using the exact SHA-512 input encoding specified below. If the candidate is not valid under the address policy version selected for the handshake, S MUST discard it, generate a new cryptographically random 32-byte `vip_nonce`, and recompute the candidate with the same time bucket and all other inputs unchanged. S MUST repeat until the candidate passes policy validation. Every redraw MUST use a fresh nonce; a nonce used for a rejected candidate MUST NOT be reused.

The derivation formula and field encoding MUST remain unchanged. An implementation MUST NOT mask, prefix, or otherwise rewrite digest bits to make a candidate pass address policy.

D MUST independently validate the received/recomputed candidate under the same policy version and MUST reject a candidate that fails policy, even if its hash calculation otherwise matches.

Construct the vIP input as the following ordered sequence of fields:

1. ASCII domain-separation label `NLS-vIP-v1`
2. D.originalIP (16 packed IPv6 bytes)
3. D certificate (complete DER certificate bytes)
4. D Ed25519 public key (DER SubjectPublicKeyInfo bytes)
5. S.originalIP (16 packed IPv6 bytes)
6. S certificate (complete DER certificate bytes)
7. S Ed25519 public key (DER SubjectPublicKeyInfo bytes)
8. `vip_nonce` (32 bytes)
9. `time_bucket` (8-byte unsigned big-endian integer)

Encode EVERY field as `uint32_be(length) || field_bytes`, including the fixed-length fields and the domain label. Let `digest = SHA-512(encoded_fields)`. The candidate vIP is the IPv6 address represented by the first 16 bytes of `digest` (network byte order). Implementations MUST NOT use JSON, delimiter-concatenated text, platform-native integer encoding, or non-canonical certificate/key encodings for this calculation.

D MUST recompute the candidate vIP using its own authoritative certificate/key and originalIP, plus S's certificate/key/originalIP obtained from a fresh, authenticated Router-CA lookup. D MUST compare the recomputed address with the M1 `vip` field and reject a mismatch; outer source validation is a separate check against S's authoritative `originalIP`. D MUST accept a time bucket only if it is the current bucket or one adjacent bucket (absolute bucket difference <= 1), and MUST also enforce the independent M1 timestamp freshness, nonce replay protection, and handshake timeout. A time-bucket match does not replace the signature, transcript, certificate, status, or proof-of-possession checks.

Because this requires S's full certificate before D sends M2, D performs an authenticated CA lookup for S after decrypting M1 and before replying. Before any RSA decryption of M1, D MUST enforce a global pending-handshake cap; if the cap is reached, D MUST reject or drop the datagram without decrypting it or allocating pending state. D MUST also apply a global token bucket, per-ingress-interface rate limits, and per-outer-source-/64 rate limits before RSA decryption. The outer source is the observed WAN locator and MUST be validated against authenticated endpoint state; resource limits still MUST be applied independently and MUST NOT be replaced by claimed-identity limits.

After decryption and bounded schema parsing, the claimed router ID MAY be used only as a secondary rate-limit key; it MUST NOT replace the global, ingress-interface, or source-/64 controls. Before starting the CA lookup, D MUST enforce strict datagram-size and NLH2 framing limits, validate message type, lengths, required fields, field types, and schema constraints, and reject malformed input. Where a cached RDR for the claimed source router exists, D MUST verify the M1 signature against that cached identity and compare claimed identity keys to the cached record. A known mismatch, revoked/disabled status, or invalid cached record MUST be rejected before lookup. An absent cache entry does not establish trust; it may proceed only through the bounded, fail-closed path. D MUST cap concurrent pending CA lookups as well as pending handshakes.

An optional stateless retry cookie MAY be enabled as an additional load-shedding measure. It MUST be validated before allocating expensive handshake state or initiating a CA lookup, and MUST NOT replace the mandatory authentication and CA checks.

D still performs the mandatory fresh S lookup during S4/M3 processing; the early lookup is not a replacement for S4. If Router-CA is unreachable, the lookup is stale, or S's record is not ACTIVE, D fails closed and sends no successful M2 response.

### M1 request and M1-M4 outer IP headers

M1 MUST retain all existing NLH2 security fields and MUST additionally contain `request_for_peer_details: true`, the intended destination router ID, `vip_nonce`, `time_bucket`, and `vip_policy_version`. `vip_policy_version` is an unsigned integer identifying the versioned IPv6 address-classification policy; version 1 is defined below. The nonce, time bucket, policy version, and request fields MUST be covered by the M1 signature and sealing. D MUST reject an unknown or unsupported policy version before the pre-M2 CA lookup. The explicit request asks D to return its CA-registered identity details in M2. It does not authorize D to trust S; S remains subject to D's S4 cross-check.

The outer IP header and UDP endpoint rules for the bootstrap exchange are:

- `wan_endpoints[0]` is parsed as `[IPv6]:PORT`; its IPv6 address component is `originalIP` and its port is the router's bootstrap/listener port. The endpoint's port is not part of `originalIP` or the vIP hash input.
- M1 (S to D): send to `(D.originalIP, port parsed from D.wan_endpoints[0])`; outer source = S's authenticated `originalIP`.
- M2 (D to S): outer source = D's authenticated `originalIP`; outer destination = S's authenticated `originalIP`. Send to the source router's primary endpoint port from S.wan_endpoints[0].
- M3 (S to D): send to `(D.originalIP, port parsed from D.wan_endpoints[0])`; outer source = S's authenticated `originalIP`.
- M4 (D to S): outer source = D's authenticated `originalIP`; outer destination = S's authenticated `originalIP`. Send to the source router's primary endpoint port from S.wan_endpoints[0].

M2 MUST carry D's certificate, public key, originalIP, and signed RDR, while retaining the existing DH key, SA proposal, nonce, transcript-hash, and signature fields required by NLH2. M3 MUST carry S's certificate, public key, originalIP, and signed RDR, while retaining the existing DH key, selected SA, transcript-hash, and signature fields. M4 remains the authenticated acknowledgement with transcript confirmation. Do not remove or weaken existing NLH2 fields to implement these additions.

### vIP lifecycle and deployment constraint

The derived `vip` is handshake-scoped cryptographic context only. It MUST NOT be assigned to an interface, used as an outer source/destination, or installed in the FIB. M1–M4 use authenticated WAN locators as defined by Stage 7. Failed handshakes MUST clean up pending cryptographic and trust state without removing unrelated routes or addresses.

#### Versioned vIP address policy

`vip_policy_version = 1` requires the candidate IPv6 address to lie within IPv6 Global Unicast space `2000::/3` and not fall within any excluded range in this policy. The following commonly recognized exclusions are **informative only**; the pinned literal table in “Policy-v1 pinned registry snapshot” is normative and defines the complete policy-v1 exclusion set.

#### Policy-v1 pinned registry snapshot

Policy v1 approves **no** IANA special-purpose prefix for vIP use. Therefore, every IPv6 Special-Purpose Address Registry entry whose prefix intersects `2000::/3` is excluded, including entries whose registry metadata says globally reachable; globally reachable status alone is not approval for this protocol. The table below is the literal policy-v1 exclusion table derived from the IANA IPv6 Special-Purpose Address Space registry.

- Registry: https://www.iana.org/assignments/iana-ipv6-special-registry
- Registry's recorded **Last Updated** date: `2025-10-09`
- Snapshot captured for this specification: `2026-10-18`
- Table serialization for hashing: the CIDR prefixes below, one per line in the exact order shown, ASCII lowercase, LF line endings, including one final LF, with no whitespace or comments.
- SHA-256 of that exact serialized table: `6639dadc8a64373a682874fb8e83e16a7e6898463b91c74da09c756527ab57ad`

| Literal exclusion prefix | Registry designation |
|---|---|
| `2001::/23` | IETF Protocol Assignments |
| `2001::/32` | TEREDO |
| `2001:1::1/128` | Port Control Protocol Anycast |
| `2001:1::2/128` | Traversal Using Relays around NAT Anycast |
| `2001:1::3/128` | DNS-SD Service Registration Protocol Anycast |
| `2001:2::/48` | Benchmarking |
| `2001:3::/32` | AMT |
| `2001:4:112::/48` | AS112-v6 |
| `2001:10::/28` | Deprecated (previously ORCHID) |
| `2001:20::/28` | ORCHIDv2 |
| `2001:30::/28` | Drone Remote ID Protocol Entity Tags (DETs) Prefix |
| `2001:db8::/32` | Documentation |
| `2002::/16` | 6to4 |
| `2620:4f:8000::/48` | Direct Delegation AS112 Service |
| `3fff::/20` | Documentation |

Implementations MUST embed this exact literal table and MUST NOT read, download, or otherwise consult the host's IANA registry data at runtime. S and D MUST use the same pinned table and hash. A future table change requires a new `vip_policy_version`, a new table hash, and explicit protocol-specification change; implementations MUST reject unknown versions. The `2000::/3` inclusion check remains mandatory in addition to this exclusion table.

Add boundary tests for the start, end, and adjacent addresses of `2000::/3` and every table prefix. Tests MUST cover accepted addresses immediately outside excluded ranges where those addresses remain inside `2000::/3`, rejection of addresses in every exclusion (including nested/overlapping entries), and rejection of unknown `vip_policy_version` values. The version is part of M1's signed and sealed fields.

#### Lab-only temporary route and explicit configuration switch

The legacy configuration key `vip.lab_temporary_route.enabled` is deprecated and MUST remain false. If it is true, invalid, or absent, implementations MUST NOT install a derived-vIP route; production-mode configuration MUST reject attempts to enable it. The selected Stage 7 v1 profile forbids temporary derived-vIP routes even in lab mode. This key MUST NOT be enabled by package installation, discovery, CA metadata, or handshake messages.

Under the selected Stage 7 v1 profile, even in lab mode, implementations MUST NOT install a route for the derived `vip` as a bootstrap workaround. A lab topology that requires derived-vIP routing is a different profile and MUST be separately specified and explicitly selected; it MUST NOT be represented as conformant to the routable-locator profile.

If installed, D MUST remove this route on successful handshake completion, handshake failure, or handshake timeout. Cleanup MUST also run when the pending handshake is cancelled or its state is discarded. Removal MUST be scoped to the exact route installed for that handshake and MUST NOT delete or overwrite an operator-managed route. Route installation failure MUST fail the lab handshake closed and MUST NOT leave partially allocated vIP or handshake state. This /128-via-S.originalIP behavior is strictly for lab testing and MUST NOT be treated as the production routing solution.

OPEN QUESTION: The first 128 digest bits are an arbitrary IPv6 address and may not be routable to S on a multi-hop or Internet WAN. Do not silently mask or rewrite digest bits to fit `vip.pool`, because doing so changes the specified derivation. Lab tests MUST establish whether the lab-only temporary route provides the required bootstrap reachability in the controlled topology. Production use over routed WANs requires a separately documented routing/encapsulation strategy that preserves the exact derivation and return-path reachability. Spoofed global-unicast source addresses are expected to be dropped by ingress filtering (BCP 38 / uRPF) on production networks.

## Amendment: Minimal M1 disclosure and SourceToken data plane

**Precedence for the SourceToken data plane:** This amendment's wire format and requirements supersede conflicting legacy NLE2 data-header descriptions elsewhere in this specification. The legacy NLE2 header is not an additional header in the SourceToken data path. NLH2 handshake framing remains separate.

This amendment is normative and applies to the NLH2 handshake and its post-handshake data plane. It changes only the requirements explicitly listed below. It does not itself implement or validate the amended protocol.

### Scope and supersession

This amendment supersedes only conflicting statements in earlier parts of this specification about:
- the STEP A S2 M1 field list, and any interpretation that M1 carries S's certificate, originalIP, or signed RDR;
- the hybrid NLH2 amendment's M1 contents and field names;
- STEP A S5 endpoint-switch/data-plane wire format and the hybrid vIP lifecycle, but only for post-M4 data packet addressing and format.
- the SourceToken data-record framing and metadata-protection-mode requirements defined in B.3 and B.4.

Existing M2, M3 and M4 message contents remain unchanged except for the M3 disclosure timing stated below. The derived vIP is never a routable outer address under Stage 7; implementations MAY retain `VIP_AFTER_SWITCH` as a defensive diagnostic/drop reason for any unexpected packet using that address, but MUST NOT implement a vIP-based endpoint transition. The pinned policy-v1 table/hash, ordered `wan_endpoints`, `originalIP` requirements, replay/freshness rules, signatures, transcript checks, key schedule, fail-closed behavior and NLH2 framing remain the security base unless an amendment explicitly supersedes them.

### A. Minimal M1 disclosure

M1 is sealed to D's RSA encryption public key and signed by S. After opening M1, D verifies sig_S over the canonical encoding of every M1 field except sig_S itself. Padding is part of the signed canonical encoding.

M1 contains exactly the following protocol fields, along with the padding required by the existing anti-amplification rule:
- session_id;
- source_router_id;
- source_ed25519_pub, S's Ed25519 verification public key;
- source_rsa_pub, S's RSA encryption public key;
- request_for_peer_details, which MUST be the boolean true;
- destination_router_id;
- vip;
- vip_nonce, a fresh random 32-byte value;
- time_bucket, an unsigned 64-bit big-endian integer;
- vip_policy_version;
- nonce_s, the existing random handshake nonce;
- timestamp;
- padding;
- sig_S.

The field name source_router_id supersedes the earlier S.router_id name for this M1 field. Fields MUST have the specified types; unknown fields MUST be rejected. The existing M1 padding/anti-amplification requirement remains in force: M1 MUST be padded to at least the maximum permitted M2 size.

M1 MUST NOT contain S's certificate, S's originalIP, or S's signed Router Directory Record (RDR). D MUST authenticate an authoritative Router-CA lookup for S before producing M2. D MUST compare both public keys in M1 with the corresponding keys in S's authoritative Router-CA record and reject a mismatch. A cached record may be used only for the existing early screening/pre-checks; it MUST NOT replace the required authenticated authoritative lookup. Unknown, revoked, disabled, stale, or otherwise invalid records fail closed.

S MUST validate D's M2 against D's authoritative Router-CA record before sending M3. S reveals its certificate, originalIP and signed RDR in M3 only after that validation succeeds. The M3 contents themselves are unchanged. M2, M3 and M4 otherwise retain their already specified fields, signatures, transcript checks and key schedule.

The intent is to disclose only the keys and parameters required for D's early vIP checks in M1, and defer S's certificate, originalIP and signed RDR until after S has authenticated D.

### B. Post-M4 SourceToken data plane

After successful verification of M4, the derived `vip` remains non-routable cryptographic context and is not used as a data-plane address. Subsequent data packets use the separately specified directional SourceToken profile; the authenticated peer WAN locator remains the outer destination.

#### B.1 Outer packet addressing and UDP ports

For traffic A to B:
- outer IPv6 source is SourceToken(A-to-B);
- outer IPv6 destination is B's originalIP;
- UDP source port is the port in A's own advertised wan_endpoints[0];
- UDP destination port is the port in B's advertised wan_endpoints[0].

For traffic B to A, reverse A and B. The source port is always the sender's own advertised wan_endpoints[0] port, not the peer's port. A receiver MUST NOT use the observed UDP source port for demultiplexing, session selection, authorization, routing, or any other protocol decision. The UDP ports are not included in the AEAD associated data.

#### B.2 SourceToken construction and selection

SourceToken is a 16-byte pseudonymous routing identifier derived from the sender's packed 16-byte IPv6 originalIP. It is not reversible ciphertext: confidentiality of the actual inner IP header is provided by the AES-256-GCM data-payload encryption in B.3. For each direction and each attempt, derive a 32-byte key as:

- input key material: the existing session_secret (the NLH2 X25519 shared value);
- salt: the existing handshake salt, SHA-256(H3 || nonce_s || nonce_d);
- info: the direction-specific ASCII label NLS-SourceToken-v1/A-to-B or NLS-SourceToken-v1/B-to-A, concatenated with uint32_be(attempt);
- KDF: the existing HKDF-SHA256 construction.

Compute HMAC-SHA256 using the derived key over the domain-separated message `NLS-SourceToken-candidate-v1/` concatenated with the sender's packed 16-byte IPv6 originalIP. The candidate is the first 16 bytes of the HMAC digest. This is a keyed pseudorandom-function mapping, not encryption of a recoverable address. No IV, padding, or block-cipher mode is used. Both session endpoints MUST implement the same derivation; a token mismatch fails closed.

Attempts are uint32 big-endian values 0 through 255 inclusive. For each attempt, a candidate MUST be rejected and redrawn at the next attempt if it is invalid under the same selected, versioned address-policy mechanism used for vIP selection, equals this session's retired vIP, or equals either router's originalIP. If no candidate qualifies within attempts 0 through 255, the session MUST fail closed.

The receiver precomputes expected inbound SourceTokens and performs an exact-match lookup on the outer IPv6 source address. A collision is scoped to the receiving router's local active/pending token table. A collision MUST NOT overwrite an existing entry; a detected local table collision fails the session closed. The SourceToken is constant for each direction throughout a session and changes when the session is rekeyed. It does not vary per packet; per-packet SourceToken variation is out of scope.

#### B.3 Versioned data record, metadata modes, nonce and authentication

Every data-plane record uses the explicit NLD2 framing below. The receiver MUST reject unknown magic, versions, mode values, malformed lengths, and mode mismatches. There is no fallback to the earlier counter-first SourceToken payload or legacy NLE2 format.

Common header:
```
magic "NLD2" (4 bytes) || version=2 (1 byte) || mode (1 byte) ||
counter (uint64 big-endian) || mode-specific visible metadata
```

The header is followed by AES-256-GCM ciphertext and a 16-byte tag. The encrypted plaintext is `message_type (1 byte) || complete original IP packet`. Message type 0 means a tunneled IP packet. Nonzero values are reserved and MUST NOT be emitted; after successful authentication, an unknown/reserved type is silently dropped.

The configured `metadata_mode` is an explicit local policy with these exact values:
- `source-only` (wire mode 1): conceal the original source address, while intentionally exposing the original inner destination address in a clear, authenticated 17-byte field. The field is `IP version (1 byte: 4 or 6) || address slot (16 bytes)`. For IPv4, the address slot is 12 zero bytes followed by the 4-byte IPv4 destination; for IPv6 it is the full 16-byte destination. The receiver MUST authenticate the record, decrypt the complete inner packet, and reject it unless the clear destination exactly matches the decrypted packet's destination.
- `source-destination` (wire mode 2): expose no inner destination metadata. Both original source and original destination IP addresses remain inside the encrypted inner packet.

Configuration: `nls.metadata_mode` is required for the NLD2 data plane and accepts exactly `source-only` or `source-destination`. The default for new installations is `source-destination`; an invalid value MUST reject configuration. The setting is static local policy, not per-packet negotiation. Both endpoints of a session MUST use the same value. This NLD2 framing is a deliberate wire-format version change: peers using the prior counter-first SourceToken payload are incompatible and MUST be upgraded together; implementations MUST NOT fall back automatically to the prior format.

Both modes encrypt the complete inner IP packet with AES-256-GCM. Mode 1 intentionally leaks the inner destination IP and must not be described as destination-confidential. Mode 2 hides the inner endpoint source and destination from observers on the underlay, but not the outer source token, destination-router WAN address, UDP ports, packet sizes, timing, or traffic patterns. The outer destination is the authorized destination router's `originalIP`; intermediate underlay routers do not need the inner destination to forward the protected record.

The receiver MUST require the record's mode byte to equal its configured `metadata_mode`; a mismatch fails closed. The selected mode is policy, not opportunistically negotiated per packet. Both peers MUST be configured consistently. The mode byte and all visible metadata are authenticated as associated data, so an attacker cannot downgrade or rewrite the mode without AEAD failure.

The 12-byte AES-256-GCM nonce is the four-byte directional IV prefix concatenated with the uint64 big-endian counter. Associated data is exactly:
`outer IPv6 source (16 bytes) || outer IPv6 destination (16 bytes) || complete clear NLD2 header`.
UDP source and destination ports are not included in the associated data.

The sender's counter starts at zero and increases strictly for each record in that direction. It MUST NOT wrap; the existing hard rekey limit remains 2^32 records. The receiver uses the configured replay window (default 128), permits authenticated reordering within the window, rejects duplicates and records too old for the window, and updates replay state only after successful AEAD authentication. Authentication failure MUST NOT advance replay state.

The existing NLH2 rekey policy remains: rekey at 2^32 packets in either direction or one hour, whichever occurs first, using make-before-break. Rekey establishes new directional keys, nonce prefixes and SourceTokens. If rekey cannot complete before the hard limit, the session fails closed.

#### B.4 Datagram demultiplexing

Demultiplexing MUST follow this order:
1. An exact outer-source match in the receiver's active/pending SourceToken table selects the NLS data path. The receiver parses only the fixed NLD2 header needed for bounds checking and mode enforcement, then authenticates the complete clear header and ciphertext before acting on the counter, visible destination, or encrypted message type.
2. If there is no exact SourceToken match, the datagram may enter the NLH2 handshake path only when it passes the existing NLH2 framing and pre-checks.
3. All other datagrams are dropped silently. There MUST be no fallback to the retired cleartext handshake, counter-first SourceToken payloads, or legacy NLE2 data formats.

The receiver MUST NOT use the observed UDP source port in this decision. SourceToken matching precedes handshake fallback. A packet using the derived vIP as an outer address is invalid under Stage 7 and MUST be dropped without protocol response; a local diagnostic MAY record `VIP_AFTER_SWITCH`. This is defensive rejection only, not a routable-vIP transition.

#### B.5 Legacy NLE2 header and control-carrier audit

The current NLE2 header is 32 bytes: magic NLE2 (4 bytes), version 2 (1 byte), flags/reserved (3 zero bytes), session_id (16 bytes), and sequence (8 bytes). The implementation requires all three flags/reserved bytes to be zero. No keepalive, close, rekey, or control-message type is defined in those bytes.

The effects of replacing the legacy header are:
- NLE2 magic/version no longer appear in the data packet. Data dispatch is selected by exact SourceToken lookup; the handshake continues to use NLH2 framing.
- The required-zero flags/reserved bytes carry no defined behavior, so no defined NLE2 flag behavior is removed.
- The old header session_id is removed from the outer data header; exact SourceToken lookup provides data-session selection.
- The old header sequence is replaced by the uint64 counter in the new payload and continues to drive nonce generation and replay protection.
- No NLE2 keepalive message is defined. Existing local session-idle handling is not an on-wire keepalive.
- NLE2 defines no close message type. Local session teardown remains local. The separate experimental NLSC control protocol has its own frame types, including CLOSE, and is not an NLE2 header field.
- Rekey is triggered by local daemon age/packet thresholds and carried by a new NLH2 handshake, not by NLE2 flags/reserved bytes.
- NLE2 defines no data-header control types. The new encrypted message-type byte reserves room for future explicitly specified control messages but does not import NLSC frame types or semantics.

#### B.6 Security and operational limitations

Metadata guarantees depend on the configured mode. `source-only` hides the original inner source but deliberately exposes the original inner destination in the authenticated NLD2 header. `source-destination` encrypts both original inner endpoint addresses. In both modes, the actual destination router `originalIP` remains visible as the outer IPv6 destination, and a per-direction SourceToken is stable within a session and can correlate packets from that session. Neither mode provides endpoint-identity anonymity or traffic-flow anonymity.

The sender must be able to emit UDP packets with the SourceToken as the outer IPv6 source. Implementations may require a temporary /128 address, raw sockets, or carefully scoped packet-manipulation rules; these must be removed at session termination. The implementation approach and cleanup tests are deferred to the applicable implementation workstream.

ICMPv6 Packet Too Big messages may not be delivered reliably to the token source address, so PMTU discovery can be unreliable. Implementations MUST use a conservative tunnel MTU and clamp TCP MSS as needed. The interaction between large M1 handshake messages, IPv6 fragmentation and tunnel MTU remains an explicit lab-validation risk. SourceToken source addresses may also be dropped by BCP 38/uRPF ingress filtering; use is limited to a controlled lab until the deployment and source-address policy is documented.

### C. Required tests for this amendment

These are specification requirements, not a claim that tests have been implemented:
- M1 without certificate, originalIP or signed RDR is accepted; M1 containing any of these fields is rejected.
- M1 public-key mismatch against the authoritative Router-CA record is rejected.
- M1 signature covers all canonical fields except sig_S, including padding.
- SourceToken derivation is deterministic for a given session/direction/attempt and is direction-separated.
- Candidates equal to the retired vIP or either router's originalIP are redrawn; address-policy rejection is honored; exhaustion of attempts 0 through 255 fails closed.
- Receiving-router local active/pending token collisions do not overwrite an entry and fail the session closed.
- Exact SourceToken match selects the data path; unmatched packets use only the existing NLH2 pre-check path or are silently dropped.
- Mode 1 exposes only the specified inner destination metadata; its authenticated value must match the decrypted inner destination for IPv4 and IPv6.
- Mode 2 contains no visible inner destination field; packet captures show both inner endpoint addresses only inside ciphertext.
- Unknown NLD2 versions, unknown mode values, mode/config mismatch, malformed visible-destination encodings, and mode downgrade/tampering are rejected without advancing replay state.
- Both peers configured for the same mode complete bidirectional forwarding; mismatched mode configuration fails closed without legacy-format fallback.
- Changing only the observed UDP source port does not change protocol decisions; outbound source port is the sender's advertised wan_endpoints[0] port.
- Type 0 successfully transports an inner IP packet. Unassigned message types cause no control action and are silently dropped after authentication.
- Tampering with outer source, outer destination or counter causes AEAD authentication failure.
- Replay and out-of-window counters are rejected; replay state is unchanged after failed authentication.
- Rekey changes SourceTokens and directional keys/prefixes; counter wrap is prohibited.
- The retired vIP is not reused as a SourceToken; no vIP data traffic is accepted after VIP_AFTER_SWITCH.
- Captures confirm that inner IP addresses and message type values are encrypted, while documenting that outer destinations and per-session packet lengths remain visible.

### D. Remaining open questions

1. Should specific encrypted data-plane message types be assigned for keepalive, close or other control operations now, or should no such types be emitted until a separate control-message specification is approved?
2. Should the separate experimental NLSC control protocol (including its CLOSE frame type) remain independent, or should selected NLSC operations eventually be mapped to explicitly defined encrypted data-plane message types?
3. The exact PMTU/ICMPv6 error strategy for the SourceToken source address and the handling of oversized or fragmented M1 messages still require lab validation.

## Goals and non-goals of the SourceToken data plane (version 1)

### Goals

- **G1 — Source-address confidentiality:** In data-plane packets, the outer IPv6 source field MUST NOT contain a router's real address. It contains a SourceToken that only the two session endpoints can relate to the sender.
- **G2 — Destination-only forwarding:** Intermediate routers forward using the outer destination address alone and need no knowledge of the SourceToken.
- **G3 — Inner-packet confidentiality:** Inner IP addresses and the original packet payload are inside the AEAD ciphertext.

### Non-goals for this version

- **N1 — Communication-pattern hiding:** Each router's real address appears as the outer destination in one direction.
- **N2 — Destination-router address hiding:** The destination router's address is not hidden.
- **N3 — Within-session unlinkability:** The SourceToken is constant per direction for a session and can correlate packets in that session.
- **N4 — UDP metadata hiding:** UDP ports, packet sizes, and timing remain observable.
- **N5 — Sender-side observer protection:** This version does not protect against an observer at or adjacent to the sender, including link-layer observers, the first hop, or the upstream provider.
- **N6 — Reply-destination hiding:** The reply's outer destination is the sender's real address so that the reply can be routed to it.

### Observer model (informative)

An observer that sees only A-to-B packets learns B's address, an opaque SourceToken, UDP ports, packet sizes, and timing. The observer does not learn A's address from the packet fields.

An observer that sees both directions learns both routers' addresses.

### Terminology rule

Specification text, test names, and external descriptions MUST use "source-address confidentiality" for this version. They MUST NOT claim endpoint-identity anonymity or traffic-flow anonymity.

### Future work (informative; not requirements)

- Hide the reply destination using a routable-but-opaque return address, such as a per-session pseudo-address delegated to the sender's network, or a relay.
- Vary the SourceToken per packet.
- Define and validate MTU and ICMPv6 handling for the token source.

## Segment 8 — Authenticated vIP registry and routing-plane LSDB synchronization

### Purpose

The NLS session registry is the authoritative local table mapping each active NLS router identity and `originalIP` to its session-scoped cryptographic `vip` context and directional SourceToken binding. The `vip` is not allocated as a kernel address: no interface address, FIB route, or routing advertisement is created for it. Registry state records authenticated identity, session lifecycle, and reachability metadata; SourceToken source selection is handled by the specified per-socket binding mechanism.

The implementation MUST keep these state stores separate:

- **Address lease table:** local kernel /128 allocation, ownership, expiry, and cleanup after crash.
- **NLS vIP binding table:** router_id, originalIP, vIP (handshake-only until M4), directional SourceTokens, session_id, record_seq, authentication state, lifecycle state, expiry, and binding version.
- **Routing LSDB view:** only authenticated current bindings that have been accepted by the routing-plane synchronizer. A local registry row MUST NOT by itself install a kernel route or be flooded as an OSPF LSA.

### Binding lifecycle and authorization

1. **PENDING:** a candidate vIP may be reserved for one bounded handshake; it is not reachable, not eligible for LSDB origination, and MUST NOT be exported as an established binding.
2. **ESTABLISHED:** only after full NLH2 M1–M4 validation, fresh authoritative Router-CA lookups, both RDR checks, transcript/signature validation, and key confirmation succeed, atomically publish the session's directional SourceToken rows and the verified peer originalIP. No record may be learned solely from an unauthenticated advertisement.
3. **OVERLAP:** when rekey succeeds, retain the old session binding for the configured make-before-break overlap interval, while the new ESTABLISHED record wins forwarding resolution. A stale withdrawal for the old session MUST NOT delete the new session's row.
4. **WITHDRAWN/EXPIRED:** session teardown, revocation, failed trust refresh, expiry, or token-lease cleanup withdraws that exact session's records. Any routing-plane LSA or equivalent advertisement MUST be withdrawn or aged out, and a later session MUST receive a strictly newer per-router record sequence.
5. **REJECTED:** invalid schema, identity mismatch, sequence rollback, collision, expiry, untrusted channel, or unauthorized route origin MUST fail closed without changing an existing good binding.

### Canonical vIP record

Use a versioned, exact-field schema. The local registry record contains:

`record_version`, `record_type=nls_vip_binding`, `router_id`, `original_ip`,
`vip`, `source_token`, `send_token`, `session_id`, `record_seq`,
`state`, `expires_at`, and the authenticated router public-key identity.
The routing export MUST omit private key material, symmetric keys, nonces, handshake envelopes, and user packet contents. Implementations MUST reject unknown fields at import boundaries. The routing channel's authenticated peer identity MUST match `router_id`; the record body alone MUST NOT establish that identity. Records MUST have a bounded lifetime and monotonically increasing `record_seq` per router/binding authority. A stale record or stale withdrawal MUST NOT replace or remove a newer session.

### LSDB synchronization and originalIP update

After the authenticated vIP registry commits an ESTABLISHED binding, the routing-plane adapter may originate an NLS-specific LSDB object carrying the router identity, originalIP, record sequence, lifecycle state, expiry/age, and session-specific opaque token identifier required by the approved routing design. It MUST NOT put a peer's unverified originalIP into the LSDB.

On an authenticated, accepted change of the peer's authoritative RDR where `wan_endpoints[0]` changes the peer's originalIP, the daemon MUST NOT mutate the originalIP field of an existing session in place. It MUST revalidate the updated Router-CA record, establish or re-establish the NLH2 session using the new originalIP, publish a new session-scoped binding, and withdraw the old binding only when the old session is safely retired. Old and new bindings may coexist only in the explicitly bounded OVERLAP interval. The routing plane then updates its own LSDB from the accepted new binding; it does not learn the new originalIP from the data-plane packet or from an unauthenticated OSPF extension.

### OSPF compatibility boundary

This specification does not authorize injecting private NLS JSON or arbitrary custom payloads into standard OSPFv2/OSPFv3 LSAs. The existing FRRouting/OSPF LSDB may only be modified through an explicitly implemented, versioned and validated routing-plane adapter using a supported FRRouting interface or a separately specified OSPF extension. Until that adapter and interoperability tests exist, `nls/lsdb.py` is the NLS authenticated registry/LSDB view, not evidence that an originalIP is propagated through real OSPF LSAs to every NLS router. Keep the kernel FIB and operator-owned routes unchanged unless a distinct route-installation policy authorizes a specific route.

### Required verification gates

- Unit tests for exact schema, IPv6 canonicalization, identity mismatch, collisions, monotonic sequence, expired and stale update rejection, session-scoped withdrawals, and restart recovery.
- Lifecycle tests proving PENDING is never exported; M4 success publishes ESTABLISHED; failed M4/trust refresh/revocation withdraws; rekey publishes the new binding before retiring the old one.
- A multi-router test proving an authenticated originalIP change updates every participating router's LSDB view, with signed/authorized update and withdrawal records.
- OSPF/FRRouting tests demonstrating actual LSA origination, flooding, update, and withdrawal on the WAN-facing topology. Tests must verify both the protocol LSDB and kernel route table and must distinguish a synchronized metadata binding from an installed FIB route.
- WAN capture must show only the defined outer addressing and SourceToken payload, with inner original source/destination absent from plaintext; cProfile and throughput evidence must be attached to the exact tested commit.
- Required tests must pass on Ubuntu 22.04 and 24.04 before this feature is marked complete. If OSPF LSA integration is not implemented, the gate remains BLOCKED, not PASS.

**Status:** The current code has local vIP/SourceToken binding and LSDB export/import primitives. Dedicated authenticated end-to-end vIP/LSDB synchronization and actual OSPF LSA propagation remain unverified until separately implemented and tested.



## Stage 3 — Normative specification consolidation and freeze gate

### Status and purpose

This section consolidates the requirements already introduced by the hybrid NLH2, minimal-M1-disclosure, SourceToken data-plane, and authenticated vIP-registry amendments. It does not assert implementation conformance. The specification is not considered implementation-certified merely because this section exists; conformance requires the vectors, tests, and release evidence listed below.

### Normative precedence

If sections conflict, apply this precedence:

1. The minimal M1 disclosure and SourceToken data-plane amendment governs the exact M1 field set, disclosure timing, and post-M4 data packets. It does not override the Stage 7 outer-locator rules below.
2. Stage 7's normative bootstrap-locator decision governs the outer IP headers for M1-M4 and the routing treatment of `vip`. The derived `vip` MUST NOT be an outer source/destination, interface address, or kernel FIB route. After M4, a directional SourceToken may be used as the protected data-plane outer source, while the authenticated peer `originalIP` is the outer destination.
3. The hybrid NLH2 amendment governs `originalIP`, RDR primary-endpoint interpretation, vIP derivation, nonce redraw, address policy, and cryptographic context, except where Stage 7 explicitly controls the outer locator.
4. Segment 8 governs authenticated vIP registry records, session-scoped bindings, lifecycle, and routing-plane synchronization.
5. The remaining base NLH2 specification governs handshake framing, signatures, transcript validation, key schedule, replay protection, trust requirements, and failure semantics, except where a later amendment explicitly supersedes it.
6. Historical or superseded examples MUST NOT override these requirements.

### Canonical terminology

The following terms are distinct and MUST NOT be treated as synonyms:

- `originalIP`: the canonical IPv6 address extracted from the first endpoint in the authoritative RDR.
- `vip`: the per-handshake value derived using the approved SHA-512 input encoding and address-policy version. It remains signed/sealed cryptographic handshake context only, MUST NOT be used as a network locator, and is retired after successful M4 verification.
- `source_token`: a session-scoped outer source token used by the approved post-M4 SourceToken data plane.
- `original_ip`: a local registry/database spelling for the authoritative originalIP value; it is not a separate wire identity.

Wire-field spelling, field type, canonical encoding, and field presence are protocol requirements. An implementation MUST NOT silently translate an unknown or legacy wire schema into the current schema.

### Canonical RDR and identity contract

The signed RDR is an authoritative router identity record. Its canonical schema MUST define an exact required field set and field types. The signature MUST cover the canonical RDR encoding, including the ordered `wan_endpoints` list and `originalIP`. `wan_endpoints[0]` MUST be parsed as the specified bracketed IPv6 endpoint; `originalIP` MUST equal its canonical IPv6 address component, excluding the port.

Strict RDR boundaries MUST reject missing required fields, unknown fields where the schema is exact, incorrect types, malformed encodings, absent/invalid/inconsistent `originalIP`, invalid signatures, invalid validity intervals, unacceptable sequence rollback, and statuses other than ACTIVE where an active peer is required. CA registration/update MUST enforce primary-endpoint and `originalIP` consistency. An unsigned local record MUST NOT alter authoritative identity, key, or endpoint data.

The full CA-issued X.509 certificate MUST be obtained through the defined authenticated certificate/registry mechanism; it MUST NOT be replaced by an unsigned identity claim. Internal database names may differ from wire names only through explicit, deterministic, tested conversion.

### Canonical M1 contract

M1 MUST use exactly the field set defined in the minimal-M1-disclosure amendment: `session_id`, `source_router_id`, `source_ed25519_pub`, `source_rsa_pub`, `request_for_peer_details`, `destination_router_id`, `vip`, `vip_nonce`, `time_bucket`, `vip_policy_version`, `nonce_s`, `timestamp`, `padding`, and `sig_S`. `request_for_peer_details` MUST be boolean true. Unknown fields and legacy M1 schemas MUST be rejected. M1 MUST NOT disclose S's certificate, `originalIP`, or signed RDR.

The signature MUST cover the canonical encoding of every M1 field except `sig_S`, including padding. M1 MUST be sealed to D's authoritative RSA encryption key. The outer source address MUST equal S's authoritative `originalIP`, as specified by the Stage 7 bootstrap-locator decision, not the derived `vip`. The destination router identity MUST match the intended peer.

D MUST perform the mandatory authenticated Router-CA lookup for S before producing a successful M2. A cache may be used for early rejection but MUST NOT replace the authoritative lookup. Both public keys in M1 MUST match S's authoritative record. Unknown, revoked, disabled, stale, or otherwise invalid records MUST fail closed.

### vIP derivation invariants

The vIP calculation MUST use the exact field order, uint32 length-prefix encoding, DER encodings, nonce size, time-bucket encoding, SHA-512 operation, and address-policy version specified in the hybrid NLH2 amendment. Implementations MUST NOT mask, rewrite, prefix, or otherwise alter the digest to make a candidate fit the address policy.

When a candidate fails policy, S MUST draw a new 32-byte cryptographically random `vip_nonce` and recompute with the same time bucket and all other inputs unchanged. The specified attempt limit is 256 candidates, indexed 0 through 255. Exhaustion MUST fail closed. D MUST independently recompute the candidate from authoritative identity data and S's fresh authenticated Router-CA record, validate the time bucket and address policy, and compare the result with the M1 `vip` field. D MUST validate the outer source separately against S's authenticated authoritative `originalIP` under the Stage 7 bootstrap-locator rules.

### Handshake and trust invariants

Implementations MUST model M1–M4 as an explicit state machine. A syntactically valid message MUST NOT by itself establish trust or authorize forwarding. The logical progression is: idle; bounded M1 validation; authoritative peer lookup validation; M2 validation; M3 disclosure and cross-check validation; M4 transcript/key confirmation; established session; closed/invalidated session. This list does not authorize reordering the prescribed wire flow.

Implementations MUST reject out-of-order messages, invalid transcript hashes, identity/key substitution, unsupported policy versions, stale CA responses, invalid key confirmation, and duplicate or invalid state transitions. Failure MUST NOT leave a partially trusted session. Pending handshakes, CA lookups, and expensive cryptographic work MUST be bounded. Required global, ingress-interface, and outer-source-/64 rate controls are independent and MUST NOT be replaced by claimed-identity rate limits.

### VIP Table and Trust Table invariants

The VIP Table and Trust Table are separate authorization boundaries; neither table alone proves trust. A pending candidate MUST NOT be forwardable or exported as an established binding. A trusted session requires the complete prescribed handshake, authoritative fresh CA validation, transcript/key confirmation, and policy checks. Failed or mismatched verification MUST NOT overwrite an existing valid binding.

Promotion to forwarding-authorized state MUST atomically publish the authenticated session binding. Bindings MUST be scoped to a session and authoritative record sequence. A stale update MUST NOT replace a newer record, and an old-session withdrawal MUST NOT delete a newer session's binding. Teardown, expiry, failed trust refresh, or revocation MUST remove forwarding eligibility and withdraw only the exact affected session binding. Cleanup MUST NOT delete unrelated operator-managed routes.

### Revocation, freshness, and rekey

The live-CA trust mode MUST fail closed when a required authoritative lookup is unavailable, invalid, or stale. Any explicitly configured offline-bundle mode MUST be identified operationally as having degraded freshness; it MUST NOT silently become the fallback for a failed live lookup.

The release specification MUST assign a concrete maximum interval between accepted revocation and forwarding/session invalidation. The implementation MUST test revocation authentication, freshness, propagation, established-session invalidation, behavior during feed/CA failure, persistence, and restart recovery. An unbounded or unmeasured revocation interval is not a passing security result.

Rekey MUST establish new directional keys, nonce prefixes, replay state, and SourceTokens. Old/new session overlap is permitted only for the configured make-before-break interval. New state MUST become usable before old state is retired, and stale old-session events MUST NOT remove the new session. Rekey MUST occur at the existing hard limit of 2^32 records in either direction or one hour, whichever occurs first. Counters MUST NOT wrap; nonce reuse under the same directional key MUST NOT occur. Failure to rekey before the hard limit MUST close the session.

### Mandatory compatibility vectors

Before implementation conformance can be accepted, the project MUST publish versioned deterministic test vectors covering:

1. RDR canonical encoding, signature verification, endpoint parsing, and `originalIP` canonicalization.
2. vIP field serialization, every uint32 length prefix, SHA-512 digest, and candidate address for fixed test fixtures.
3. Candidate policy rejection, nonce redraw, and attempt-limit exhaustion.
4. M1 canonical encoding, signature input, and exact field-set validation.
5. M1/M2/M3 transcript values and M4 key confirmation.
6. X25519/HKDF labels, directional keys, IV prefixes, and confirmation key using fixed test-only inputs.
7. SourceToken derivation and direction separation.
8. Data-record AAD, nonce construction, ciphertext authentication, replay-window behavior, and metadata modes.

Each vector MUST record its version, exact inputs, expected output bytes, and verification method. Test-only credentials MUST be clearly marked. Expected outputs MUST be independently checked by at least two independent implementations or independently implemented test paths; self-generated-and-self-verified output alone is insufficient.

### Mandatory negative and lifecycle tests

The conformance suite MUST prove rejection of unknown, missing, duplicated, incorrectly typed, or non-canonical fields at strict boundaries; invalid/stale/revoked/disabled/mismatched/sequence-rollback RDRs and CA responses; M1 signature or padding tampering; key/destination/vIP mismatch; unsupported policy versions; prohibited candidates and redraw exhaustion; out-of-order or replayed handshake messages; invalid M4 confirmation; forwarding before establishment; forged/replayed data packets; authentication failure; duplicate or out-of-window counters; counter wrap; unauthorized inner source prefixes or route creation; stale-session withdrawal of a newer binding; revocation and expiry; restart inconsistency; incomplete cleanup; and cross-repository protocol-schema mismatches.

Tests MUST assert that rejected input does not advance replay state, replace a valid binding, create an unauthorized route, disclose secrets in logs, or leave a session established.

### Cross-repository and release gate

NetOS and NexOS Core MUST use compatible versioned control-protocol schemas, field types, message constants, authentication rules, and error behavior. The release gate MUST run cryptographic-vector tests, schema tests, cross-repository compatibility tests, VIP/Trust lifecycle tests, handshake/revocation tests, data-plane integrity/replay/metadata/authorization tests, crash/restart tests, network-namespace end-to-end tests on every supported Ubuntu version, and measured MTU, packet-loss, throughput, and rekey tests on the exact tested commit.

Historical CI success or performance measurements MUST NOT be represented as evidence for a newer commit unless that commit was actually tested. A release report MUST identify tested commit SHAs, environment, commands, complete test summaries, failures, deviations, and remaining limitations. An unexecuted mandatory test is UNVERIFIED; a failing mandatory test is FAIL; neither may be reported as PASS.

### Explicit deployment gate: vIP reachability

The SHA-512 vIP derivation and address-policy rules are protocol requirements. A candidate MUST NOT be rewritten to make it routable. Address-policy acceptance alone does not prove that a derived vIP is reachable over a real WAN, that the return path works, or that upstream anti-spoofing filters permit it.

Before production deployment is approved, a separate deployment design MUST specify and validate the bootstrap return path, source-address validation behavior, interface/socket requirements, route cleanup, NAT/firewall behavior, fragmentation/PMTU handling, and ingress-filtering interaction. Lab-only temporary routes MUST remain explicitly lab-only and MUST NOT be installed automatically. Until this design is validated on the intended network, production deployment of the selected routable-locator profile remains BLOCKED/UNVERIFIED even if cryptographic unit tests pass. This deployment gate covers WAN endpoint reachability, NAT/firewall behavior, source validation, asymmetric routing, PMTU/fragmentation, restart recovery, and revocation behavior.

### Freeze decision record

The freeze review MUST record PASS, FAIL, BLOCKED, or UNVERIFIED for: canonical schemas and precedence; RDR signature/freshness/primary-endpoint validation; vIP encoding/policy/redraw/recomputation; M1 minimal disclosure and signature coverage; M1–M4 state transitions; VIP/Trust atomic lifecycle; revocation propagation and invalidation bound; rekey/nonce/counter/replay invariants; SourceToken and metadata modes; routing authorization and session-scoped withdrawals; cross-repository compatibility; and end-to-end/deployment evidence.

The specification is not implementation-certified merely because this section has been added. The freeze decision MUST link to actual vector results, test logs, and reviewed commit SHAs.


## Stage 7 — Normative bootstrap reachability decision (supersedes conflicting earlier text)

### Decision and rationale

For the v1 multi-hop and general WAN profile, NLS MUST use the authenticated routers' routable WAN locators for the outer IPv6 header during NLH2 bootstrap. The derived `vip` remains a handshake-scoped cryptographic identifier and MUST NOT be used as an outer source/destination address or installed in the kernel FIB. This section supersedes earlier examples requiring the outer source to equal `vip`, including the conflicting base examples above. The vIP derivation algorithm, field encoding, policy checks, nonce redraw, independent recomputation, and M1 disclosure rules remain unchanged.

Reason: a derived arbitrary IPv6 /128 is not inherently routable. Distributing it as a host route through participating routers would require pre-handshake route authorization, expose address-claiming behavior, risk hijacking arbitrary global /128s in the kernel FIB, and still would not work through non-participating Internet transit networks. A destination-local route is insufficient for a multi-hop path. NLS MUST NOT attempt to solve this by changing the vIP digest or by silently injecting custom OSPF LSAs.

### Outer locator rules

1. S obtains its canonical `originalIP` and primary WAN endpoint from a fresh, authenticated Router-CA RDR. D does the same for its own endpoint. The canonical address and UDP port are taken from the same signed, ordered `wan_endpoints[0]` entry; the list order is significant.
2. For every NLH2 handshake message, the outer IPv6 source address and UDP source port MUST be the sender's authenticated primary WAN locator and port; the outer IPv6 destination address and UDP destination port MUST be the recipient's authenticated primary WAN locator and port. Implementations MUST NOT mix an address from one endpoint entry with a port from another.
3. M1 travels S to D; M2 travels D to S; M3 travels S to D; M4 travels D to S. Therefore M1/M3 outer source is S's authenticated `originalIP` and destination is D's; M2/M4 outer source is D's authenticated `originalIP` and destination is S's. Each source and destination UDP port follows the corresponding sender/recipient's primary endpoint entry. The M1 `vip` field remains inside the sealed, signed M1 payload and MUST NOT replace either outer locator.
4. Each receiver MUST validate the observed outer source address and UDP source port against the expected authoritative peer endpoint, and validate the destination locator/port against its own expected primary endpoint and configured socket/listener policy. The deployment's documented NAT/source-validation policy may affect the observed path, but MUST NOT silently weaken peer authentication. Endpoint changes require fresh CA validation and a new handshake; an unauthenticated packet MUST NOT update the locator.
5. No router may route M1–M4 by looking up `vip` in the kernel FIB. The `vip` is never a routing address: it MUST NOT be assigned to an interface, advertised in the routing protocol, or installed as a route. It may be held only as handshake/session cryptographic context through token derivation and cross-checking. The pending bootstrap registry row MUST be removed after successful M4 activation; no active routing binding for `vip` may remain.
6. This profile does not claim source-address confidentiality for the handshake outer header: an observer may see the routers' WAN locators during NLH2. The post-M4 SourceToken data-plane profile remains responsible for its separately specified source-address-confidentiality properties. Documentation and claims MUST state this distinction.
7. Implementations MUST NOT install a `vip/128` route or address as part of bootstrap. Existing operator routes and ordinary IPv6 traffic MUST remain unchanged.

### SourceToken socket binding and routing-plane invariance

After M4, a directional SourceToken may be used as the outer IPv6 source for the protected data plane, while the authenticated peer `originalIP` remains the outer destination. On Linux routers whose WAN interface participates in OSPF/OSPFv3, the implementation MUST bind the token as a per-socket source address (the tested Linux profile uses `IPV6_FREEBIND`, UAPI option 78, together with egress-interface binding). It MUST NOT add a directional SourceToken `/128` to that routing interface. Assigning the token to the interface can create a connected host route and cause FRR to advertise session-specific addresses into the ordinary routing domain.

The implementation MUST NOT enable namespace-wide non-local binding as a workaround. Session setup and teardown MUST leave WAN interface addresses, operator routes, OSPF neighbors, advertised prefixes, and the OSPF-installed FIB unchanged. A real FRR-backed regression MUST compare normalized LSDB, advertised-prefix, neighbor, and `proto ospf` route snapshots after CA synchronization, M1–M4/session establishment and data forwarding, rekey, vIP-verification TTL expiry, and trust revocation/session teardown; it MUST also include a positive control proving the test detects an intentional routing change. If the deployment's source-validation/uRPF policy rejects a SourceToken source, the deployment remains blocked pending a separately specified and tested network policy; the protocol MUST NOT silently fall back to advertising tokens.

This rule supersedes the earlier general implementation suggestion to assign temporary SourceToken `/128` addresses on an interface. It does not alter the SourceToken derivation, payload AEAD, or authenticated outer destination.

### Security and deployment boundary

The route-control/LSDB synchronizer MAY distribute authenticated session-binding metadata only under the separate Segment 8 rules. It MUST NOT install routes for arbitrary derived vIPs and MUST NOT treat a Router-CA identity record as route-installation authorization. No custom data may be injected into standard OSPF LSAs unless a separately approved, interoperable extension is specified.

A deployment that requires the derived vIP itself to appear as the outer source is outside this v1 profile and remains BLOCKED until it has a separately specified, routable delegated-prefix or relay design with source-validation, authorization, and end-to-end tests. Lab-only temporary vIP routes MUST remain disabled and MUST NOT be used to claim production conformance.

### Required tests

- M1–M4 complete over a multi-hop IPv6 topology using real WAN locators; no route to the derived vIP is present or installed.
- The responder's M2 reaches S through ordinary routing, and both sides validate authoritative endpoint consistency.
- Tampered, stale, revoked, or mismatched endpoint records fail closed without changing routes or trusted bindings.
- A test asserts that bootstrap creates no interface address, FIB route, or OSPF advertisement for the derived vIP.
- Four-node, six-node, and ten-router labs pass in both directions on Ubuntu 22.04 and 24.04.
- WAN capture documents the visible handshake locators and verifies that post-M4 data-plane behavior matches the separately approved SourceToken profile.
- NAT, asymmetric routing, PMTU, firewall/source-validation, endpoint-change, restart, and revocation behavior are explicitly tested for each supported deployment profile.

**Status:** Normative design decision; do not infer production readiness from this amendment alone. The real FRR smoke gate and full six-node NLS lifecycle OSPFv3 invariance checks passed on Ubuntu 22.04 and 24.04 on NetOS head `09a603d5677c1a7fbabdac34f4213d91209c326c`. The added production-TTL vIP-verification expiry case also passed on both OS versions on head `43341e164f760d9ee1a0be48cedf28c7f6dbf418`: two rows expired and became un-retrievable while the OSPF neighbor, normalized LSDB, advertised-prefix, and OSPF-FIB snapshots stayed unchanged. Full exact-head CI run [`40299384039`](https://github.com/TamilSelvam22112003/NlsxNetOS-v0.1.0/actions/runs/40299384039) remains in progress for throughput/profile/evidence gates. Deployment tests for NAT/uRPF/source-validation, asymmetric routing, PMTU/fragmentation, firewall rules, restart and endpoint-change recovery remain separate BLOCKED/UNVERIFIED gates.

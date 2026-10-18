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
  - S picks a fresh random /128 vIP and assigns it to its WAN interface (`ip -6 addr add ... nodad`), TTL 10 s. Lab default: ULA fd00::/8 (fd + 40 random bits + subnet + random 64-bit IID). Pool configurable (`vip.pool`); for Internet-routed WANs use a random /128 inside the router's own routable prefix.
  - M1 (S to D, outer source = vIP, outer destination = D's WAN endpoint): SEAL(D.rsa_pub from S's CA directory, {session_id, S.router_id, S.ed25519_pub, S.rsa_pub, nonce_s, timestamp, vip, sig_S}), padded so M1 is at least as large as the maximum M2 (anti-amplification). D does an early local screen of M1's claimed keys against its cached directory (fail closed if unknown/revoked/mismatched). This is not a replacement for S4.
  - M2 (D to vIP): SEAL(S.rsa_pub, {session_id, D.router_id, D.certificate, D.RDR, gateway_ips, sa_proposals, dh_pub_D (X25519), nonce_d, ike_meta, H1 = hash(M1 plaintext), sig_D}).
S3 Source cross-check: S live-looks-up D (fresh signed lookup), compares every M2 detail (certificate serial, keys, WAN endpoint, gateway IPs, SA proposals within CA policy, no downgrade). Any mismatch means drop and abort. All match means M3.
  - M3 (S to D, still from vIP): SEAL(D.rsa_pub FROM THE CA RECORD, never from M2, {session_id, S.certificate, S.RDR, dh_pub_S, chosen_sa, S.wan_endpoint, H2 = hash(M1..M2), sig_S}).
S4 Destination cross-check: D live-looks-up S, compares M3 details and the M1 keys against the CA record. Mismatch means source untrusted, abort and log. Match means D derives keys and sends M4.
  - M4 (D to vIP): SEAL(S.rsa_pub FROM THE CA RECORD, {session_id, "trust": true, H3 = hash(M1..M3), confirm = HMAC-SHA256(k_confirm, H3), sig_D}).
S5 Endpoint switch: after S verifies M4, both routers use real WAN endpoints. D binds the session to the S.wan_endpoint validated against the CA record. S removes the vIP immediately; any later packet with outer source equal to the vIP is dropped (reason VIP_AFTER_SWITCH).
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

This amendment supersedes only conflicting statements above about the RDR fields, vIP derivation, M1 contents, and the outer IP header fields for M1-M4. The existing NLH2 message framing, sealed messages, signatures, transcript hashes, X25519/HKDF key schedule, AEAD data plane, fresh CA cross-checks, replay protections, endpoint-switch rules, and failure semantics remain the security base.

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

D MUST recompute the candidate vIP using its own authoritative certificate/key and originalIP, plus S's certificate/key/originalIP obtained from a fresh, authenticated Router-CA lookup. D MUST compare the recomputed address with the M1 outer source address and reject a mismatch. D MUST accept a time bucket only if it is the current bucket or one adjacent bucket (absolute bucket difference <= 1), and MUST also enforce the independent M1 timestamp freshness, nonce replay protection, and handshake timeout. A time-bucket match does not replace the signature, transcript, certificate, status, or proof-of-possession checks.

Because this requires S's full certificate before D sends M2, D performs an authenticated CA lookup for S after decrypting M1 and before replying. Before any RSA decryption of M1, D MUST enforce a global pending-handshake cap; if the cap is reached, D MUST reject or drop the datagram without decrypting it or allocating pending state. D MUST also apply a global token bucket, per-ingress-interface rate limits, and per-outer-source-/64 rate limits before RSA decryption. The outer source is a per-handshake vIP and is not a stable router identity, so these limits MUST be applied as independent resource controls and MUST NOT be replaced by claimed-identity limits.

After decryption and bounded schema parsing, the claimed router ID MAY be used only as a secondary rate-limit key; it MUST NOT replace the global, ingress-interface, or source-/64 controls. Before starting the CA lookup, D MUST enforce strict datagram-size and NLH2 framing limits, validate message type, lengths, required fields, field types, and schema constraints, and reject malformed input. Where a cached RDR for the claimed source router exists, D MUST verify the M1 signature against that cached identity and compare claimed identity keys to the cached record. A known mismatch, revoked/disabled status, or invalid cached record MUST be rejected before lookup. An absent cache entry does not establish trust; it may proceed only through the bounded, fail-closed path. D MUST cap concurrent pending CA lookups as well as pending handshakes.

An optional stateless retry cookie MAY be enabled as an additional load-shedding measure. It MUST be validated before allocating expensive handshake state or initiating a CA lookup, and MUST NOT replace the mandatory authentication and CA checks.

D still performs the mandatory fresh S lookup during S4/M3 processing; the early lookup is not a replacement for S4. If Router-CA is unreachable, the lookup is stale, or S's record is not ACTIVE, D fails closed and sends no successful M2 response.

### M1 request and M1-M4 outer IP headers

M1 MUST retain all existing NLH2 security fields and MUST additionally contain `request_for_peer_details: true`, the intended destination router ID, `vip_nonce`, `time_bucket`, and `vip_policy_version`. `vip_policy_version` is an unsigned integer identifying the versioned IPv6 address-classification policy; version 1 is defined below. The nonce, time bucket, policy version, and request fields MUST be covered by the M1 signature and sealing. D MUST reject an unknown or unsupported policy version before the pre-M2 CA lookup. The explicit request asks D to return its CA-registered identity details in M2. It does not authorize D to trust S; S remains subject to D's S4 cross-check.

The outer IP header and UDP endpoint rules for the bootstrap exchange are:

- `wan_endpoints[0]` is parsed as `[IPv6]:PORT`; its IPv6 address component is `originalIP` and its port is the router's bootstrap/listener port. The endpoint's port is not part of `originalIP` or the vIP hash input.
- M1 (S to D): send to `(D.originalIP, port parsed from D.wan_endpoints[0])`; outer source = derived vIP.
- M2 (D to S): outer source = D.originalIP; outer destination = derived vIP. Send to the source router's advertised bootstrap port from S.wan_endpoints[0].
- M3 (S to D): send to `(D.originalIP, port parsed from D.wan_endpoints[0])`; outer source = derived vIP.
- M4 (D to S): outer source = D.originalIP; outer destination = derived vIP. Send to the source router's advertised bootstrap port from S.wan_endpoints[0].

M2 MUST carry D's certificate, public key, originalIP, and signed RDR, while retaining the existing DH key, SA proposal, nonce, transcript-hash, and signature fields required by NLH2. M3 MUST carry S's certificate, public key, originalIP, and signed RDR, while retaining the existing DH key, selected SA, transcript-hash, and signature fields. M4 remains the authenticated acknowledgement with transcript confirmation. Do not remove or weaken existing NLH2 fields to implement these additions.

### vIP lifecycle and deployment constraint

The derived vIP is temporary and is valid only for this handshake. It MUST be assigned/recognized as the outer source address for M1 and M3 and accepted as the outer destination for M2 and M4. On successful M4 verification, apply the existing endpoint-switch behavior: move the established session to the CA-validated real WAN endpoints and immediately retire the vIP; later packets using the vIP are rejected with `VIP_AFTER_SWITCH`. Failed handshakes must clean up temporary address and state.

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

The lab-only temporary route is controlled by the configuration key `vip.lab_temporary_route.enabled`, a Boolean whose default MUST be `false`. If the key is absent, invalid, or false, D MUST NOT install this route. Enabling it MUST require an explicit operator configuration in a controlled lab deployment; production configurations MUST leave it disabled, and a production-mode configuration MUST reject an attempt to enable it. This switch MUST NOT be enabled automatically by package installation, discovery, CA metadata, or handshake messages.

When and only when `vip.lab_temporary_route.enabled = true` in lab mode, after D has successfully verified M1, recomputed the vIP, validated its address class and policy version, verified the applicable signature and cached-record checks, and completed the required fresh authenticated CA lookup, D MAY install a temporary IPv6 /128 route for the derived vIP via S.originalIP when needed for the controlled lab topology. This route is temporary handshake state, MUST NOT be installed from unverified M1 fields, and MUST NOT be created from CA directory metadata alone.

If installed, D MUST remove this route on successful handshake completion, handshake failure, or handshake timeout. Cleanup MUST also run when the pending handshake is cancelled or its state is discarded. Removal MUST be scoped to the exact route installed for that handshake and MUST NOT delete or overwrite an operator-managed route. Route installation failure MUST fail the lab handshake closed and MUST NOT leave partially allocated vIP or handshake state. This /128-via-S.originalIP behavior is strictly for lab testing and MUST NOT be treated as the production routing solution.

OPEN QUESTION: The first 128 digest bits are an arbitrary IPv6 address and may not be routable to S on a multi-hop or Internet WAN. Do not silently mask or rewrite digest bits to fit `vip.pool`, because doing so changes the specified derivation. Lab tests MUST establish whether the lab-only temporary route provides the required bootstrap reachability in the controlled topology. Production use over routed WANs requires a separately documented routing/encapsulation strategy that preserves the exact derivation and return-path reachability. Spoofed global-unicast source addresses are expected to be dropped by ingress filtering (BCP 38 / uRPF) on production networks.

## Amendment: Minimal M1 disclosure and SourceToken data plane

This amendment is normative and applies to the NLH2 handshake and its post-handshake data plane. It changes only the requirements explicitly listed below. It does not itself implement or validate the amended protocol.

### Scope and supersession

This amendment supersedes only conflicting statements in earlier parts of this specification about:
- the STEP A S2 M1 field list, and any interpretation that M1 carries S's certificate, originalIP, or signed RDR;
- the hybrid NLH2 amendment's M1 contents and field names;
- STEP A S5 endpoint-switch/data-plane wire format and the hybrid vIP lifecycle, but only for post-M4 data packet addressing and format.

Existing M2, M3 and M4 message contents remain unchanged except for the M3 disclosure timing stated below. The vIP retirement rule and VIP_AFTER_SWITCH rejection semantics remain in force. The pinned policy-v1 table/hash, ordered wan_endpoints, originalIP requirements, replay/freshness rules, signatures, transcript checks, key schedule, fail-closed behavior and the existing NLH2 handshake framing remain the security base unless this amendment explicitly says otherwise.

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

After successful verification of M4, the vIP is retired for data-plane use as already specified by VIP_AFTER_SWITCH. The following outer addressing and packet format apply to all subsequent data packets.

#### B.1 Outer packet addressing and UDP ports

For traffic A to B:
- outer IPv6 source is SourceToken(A-to-B);
- outer IPv6 destination is B's originalIP;
- UDP source port is the port in A's own advertised wan_endpoints[0];
- UDP destination port is the port in B's advertised wan_endpoints[0].

For traffic B to A, reverse A and B. The source port is always the sender's own advertised wan_endpoints[0] port, not the peer's port. A receiver MUST NOT use the observed UDP source port for demultiplexing, session selection, authorization, routing, or any other protocol decision. The UDP ports are not included in the AEAD associated data.

#### B.2 SourceToken construction and selection

SourceToken is a 16-byte value produced by one AES-256 block-cipher operation on the sender's packed 16-byte IPv6 originalIP. For each direction and each attempt, derive a 32-byte key as:

- input key material: the existing session_secret (the NLH2 X25519 shared value);
- salt: the existing handshake salt, SHA-256(H3 || nonce_s || nonce_d);
- info: the direction-specific ASCII label NLS-SourceToken-v1/A-to-B or NLS-SourceToken-v1/B-to-A, concatenated with uint32_be(attempt);
- KDF: the existing HKDF-SHA256 construction.

Encrypt exactly one 16-byte block under the derived AES-256 key. This operation uses no IV, padding, chaining mode, or multi-block format.

Attempts are uint32 big-endian values 0 through 255 inclusive. For each attempt, a candidate MUST be rejected and redrawn at the next attempt if it is invalid under the same selected, versioned address-policy mechanism used for vIP selection, equals this session's retired vIP, or equals either router's originalIP. If no candidate qualifies within attempts 0 through 255, the session MUST fail closed.

The receiver precomputes expected inbound SourceTokens and performs an exact-match lookup on the outer IPv6 source address. A collision is scoped to the receiving router's local active/pending token table. A collision MUST NOT overwrite an existing entry; a detected local table collision fails the session closed. The token is constant for a direction during one session and changes when the session is rekeyed. Per-packet SourceToken variation is out of scope.

#### B.3 Data payload, nonce and authentication

The UDP payload is:

  counter (uint64 big-endian) || AEAD ciphertext || 16-byte AEAD tag

The AEAD plaintext is:

  message_type (1 byte) || message_body

Message type 0 means a tunneled IP packet; the message body MUST be the complete original client/server IP packet. The inner packet's source and destination IP addresses are carried only inside the ciphertext. All nonzero message-type values remain unassigned/reserved until their control semantics are explicitly specified. A sender MUST NOT emit an unassigned type. A receiver MUST authenticate the record before acting on the message type, and MUST silently drop an unknown or reserved type after successful authentication. The type byte is encrypted, not exposed as an unencrypted wire field; its presence increases the ciphertext/plaintext content length by one byte.

The existing NLH2 directional AEAD keys and four-byte directional IV prefixes are used. The 12-byte AES-256-GCM nonce is the four-byte directional IV prefix concatenated with the uint64 big-endian counter. The 40-byte associated data is exactly: 16-byte outer IPv6 source || 16-byte outer IPv6 destination || 8-byte counter. UDP source and destination ports are not included in the associated data.

The sender's counter starts at zero and increases strictly for each data-plane record in that direction. It MUST NOT wrap. The receiver uses the existing default 128-record replay window, permits authenticated reordering within that window, rejects duplicates and records too old for the window, and updates replay state only after successful AEAD authentication. Authentication failure MUST NOT advance replay state.

The existing NLH2 rekey policy remains: rekey at 2^32 packets in either direction or one hour, whichever occurs first, using make-before-break. Rekey establishes new directional keys, nonce prefixes and SourceTokens. A counter MUST NOT wrap; if rekey cannot complete before the hard limit, the session fails closed.

#### B.4 Datagram demultiplexing

Demultiplexing MUST follow this order:
1. An exact outer-source match in the receiver's active/pending SourceToken table selects the NLS data path. The receiver then performs AEAD, counter, replay-window and message-type checks.
2. If there is no exact SourceToken match, the datagram may enter the NLH2 handshake path only when it passes the existing NLH2 framing and pre-checks.
3. All other datagrams are dropped silently. There MUST be no fallback to the retired cleartext handshake or legacy data formats.

The receiver MUST NOT use the observed UDP source port in this decision. SourceToken matching precedes handshake fallback. Existing vIP retirement and VIP_AFTER_SWITCH rejection semantics remain; retired-vIP traffic receives no protocol response, though a local diagnostic may record the defined VIP_AFTER_SWITCH reason.

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

This SourceToken mechanism is not endpoint anonymity. In each direction, the actual destination router originalIP remains visible as the outer IPv6 destination. A per-direction SourceToken is stable within the session and can correlate packets from that session.

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

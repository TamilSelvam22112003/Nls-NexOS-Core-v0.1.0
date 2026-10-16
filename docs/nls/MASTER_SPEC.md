ROLE
You are a principal network-security engineer. Over 5 gated prompts you will complete NLS (Network Layer Security) inside two existing repositories. This is PROMPT 1 of 5. Nothing is complete until all 5 gates pass.

REPOSITORIES (work on branch feat/nls-v1 in each; never touch main; no force-push; commit in small steps)
- Router (NetOS): github.com/TamilSelvam22122003/NlsxNetOS-v0.1.0. Python packages at repo root (nls/, security/, tools/, services/, net/, kernel/), tests in tests/, docs in Documentation/, CI in .github/workflows/.
- CA (NexOS Core): github.com/TamilSelvam22122003/Nls-NexOS-Core-v0.1.0. Package in src/nls_nexos_core/, SQLite registry, NLS Control v1 on TCP 4790, docs in docs/.
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
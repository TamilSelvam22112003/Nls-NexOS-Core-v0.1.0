# NLS v1 — Phase 0 Requirement Inventory and Gap Report

**Review baseline:** router tree f6a3486a1aa4c4562191b2e37d8f382e0e6f3fe9; CA tree bdfbda6a9d6c293307851eeb70e858bc55ae3295.  
**Review method:** source-level inspection of NLS handshake, daemon, encapsulation, replay, CA client/control protocol, Router-CA registry/API, relevant configuration, deployment units, CI and protocol/integration tests. This is not a runtime test report.  
**Status meanings:** Implemented = source evidence matches the normative requirement; Partial = some related mechanism exists but material normative behavior is absent or differs; Missing = no matching implementation found in reviewed source.

## Requirement matrix

| Requirement | Status | Source evidence and function | Existing test evidence / gap |
|---|---|---|---|
| R1 — Router-ID, Router-CA certificate and pinned-root authorization | **Partial** | Router: nls/handshake.py:verify, responder_key; nls/daemon.py:_peer_trusted, _peer_for_obj; security/trust/router_ca/store.py. The NLS handshake signs JSON with Ed25519 and checks a local Router-CA store entry, but the handshake certificate is a JSON claim, not a Router-CA-issued X.509 certificate validated against a pinned root at the NLS handshake boundary. Peer entries without router_ca_id are trusted by _peer_trusted. | tests/unit/test_nls_handshake.py, tests/unit/test_security_hardening.py; no complete certificate-chain/revocation/expiry handshake matrix identified. |
| R2 — Random 128-bit temporary vIP as actual outer IPv6 source, fresh per session, 10 s TTL | **Missing** | Router: nls/handshake.py:new_init generates a textual vIP field; nls/daemon.py:_bind, _send_init use the configured socket source and never assign/bind the generated vIP. No 10 s vIP lifecycle exists. Current string generation is not a SHA-derived 128-bit address algorithm. | tests/unit/test_nls_handshake.py checks handshake values, not OS address assignment, source address on wire, TTL cleanup, or reuse. |
| R3 — M1 sends source public keys encrypted to destination Router-CA public key | **Missing** | Router: nls/handshake.py:new_init, encode_message; nls/daemon.py:_send_init. INIT is length-prefixed JSON and Ed25519-signed; identity/ephemeral public key fields are visible and are not hybrid-encrypted to the destination RSA key. | Handshake tests cover signatures/key derivation, not encrypted M1 or packet capture. |
| R4 — M2 encrypted to source key and includes destination certificate, gateway IPs, SA proposals, DH value, nonce, IKE metadata | **Missing** | Router: nls/handshake.py:responder_key. RESPONSE contains a signed X25519 public value, timestamp, vIP/original-IP fields and INIT digest; it is not encrypted and lacks the specified certificate/gateway/proposal/nonce/IKE fields. | Existing handshake tests do not assert M2 schema, confidentiality, or SA proposal handling. |
| R5 — After authentication/key establishment switch to real WAN endpoints, remove vIP, drop all later vIP traffic | **Missing** | Router: nls/daemon.py:_handle_init, _handle_response, _bind; nls/lsdb.py. The daemon stores vIP mappings in an LSDB with session timeout but does not add/remove the address on an interface, switch socket source, or drop traffic from a retired vIP. | No observed test proving switch timing, address removal, or post-expiry packet rejection. |
| R6 — Source cross-checks M2 against signed CA record; abort on mismatch/revocation/expiry; send encrypted M3 | **Missing** | Router: nls/daemon.py:_handle_response, nls/handshake.py:initiator_key, nls/ca_client.py:_persist_bundle. Response validation checks peer Ed25519 signature, session/transcript-related fields and endpoint; it does not retrieve/verify a signed per-router CA record, check certificate revocation/expiry for M2, or send M3. | No S3 mismatch/revocation/expiry tests identified. |
| R7 — Destination validates M3 against CA and sends authenticated M4 | **Missing** | Router: nls/daemon.py:_handle_init, _handle_response; handshake supports only INIT/RESPONSE constants. No M3/M4 state machine or transcript-bound acknowledgement exists. | No S4 mismatch or M4 tests identified. |
| R8 — Directional data keys derived from X25519 shared secret, both nonces, both Router-IDs and transcript hash | **Partial** | Router: nls/handshake.py:derive_session, responder_key, initiator_key. X25519 + HKDF-SHA256 produces directional values, but derivation uses a salt based on session ID and identity public-key bytes, not both nonces, Router-IDs and M1–M3 transcript hash. Data plane does not use these derived values. | Handshake tests check successful derivation and invalid signatures/timestamps; no KDF input/transcript binding tests for the specified formula. |
| R9 — Original IP packet/source IP encrypted in tunnel mode | **Partial** | Router: nls/encapsulation.py:seal_ip_packet, open_ip_packet; nls/daemon.py:_send_payload, _handle_data; nls/tun.py. Inner IP bytes are AES-256-GCM encrypted, but each packet currently uses a fresh random AES key wrapped with the destination RSA public key (nls/rsa.py:wrap_key), rather than the D1 directional session keys. | tests/unit/test_nls_encapsulation.py, tests/integration/test_four_node_nls.py exercise encapsulation/traffic, but no pcap proof of no inner packet/source plaintext was identified. |
| R10 — Tampered packets dropped | **Partial** | Router: nls/encapsulation.py:open_ip_packet authenticates ciphertext using AES-GCM; nls/daemon.py:_handle_data catches failures and drops. However, because a receiver's RSA public key permits anyone to wrap a self-chosen AES key, per-packet RSA wrapping alone does not prove sender identity. | Encapsulation tests cover round-trip/invalid input; required adversarial ciphertext/tamper test coverage is incomplete in the reviewed test suite. |
| R11 — Destination verifies/decrypts and forwards inner packet | **Partial** | Router: nls/daemon.py:_handle_data decrypts and writes to TUN; nls/daemon.py:run and nls/routing.py:install_tun_routes implement runtime/route path. Actual forwarding depends on TUN, kernel routing and configured peer prefixes. | tests/integration/test_four_node_nls.py attempts client/server forwarding; source-level evidence alone does not establish that it currently passes. |
| R12 — Sequence numbers plus 128-packet sliding window; never accept a packet twice | **Partial** | Router: nls/replay.py:ReplayWindow; nls/daemon.py:_handle_data. Replay-window logic exists, but default NLSConfig.replay_window is 64, not 128. | Required replay, out-of-window and out-of-order data tests were not identified as a complete set. |
| R13 — Wire-silent failures, structured local reason codes, no secret logging | **Partial** | Router: nls/daemon.py:_handle_init, _handle_response, _handle_data, _block; CA: src/nls_nexos_core/control.py:NLSControlServer._handle_client. Invalid NLS packets generally are not answered, but logs use free-form exception text rather than stable structured reason codes. No complete redaction audit or failure-injection matrix is present. | tests/unit/test_security_hardening.py covers selected hardening properties only. |
| R14 — CA issues/revokes certs and authenticated lookup(Router-ID) returning signed router record | **Partial** | CA: src/nls_nexos_core/ca.py:CertificateAuthority.enroll; src/nls_nexos_core/database.py:Registry.revoke_certificate, get_certificate; src/nls_nexos_core/api.py:handle_control_request; src/nls_nexos_core/control.py:NLSControlServer._authorize_client_certificate. Issuance, registry status, revocation and an authenticated AES-GCM control channel exist. No lookup(Router-ID) response with the required public keys, WAN/gateway IPs, serial/status and CA signature exists in the reviewed API. | Existing CA tests cover enrollment/authorization/control records, not lookup signing, router endpoint/key record validation or revocation heartbeat propagation end-to-end. |

## Cross-cutting observations

1. Router NLS handshake is currently NLSH + JSON, not the D6 versioned length-prefixed CBOR format. Router-CA control is a separate NLSC JSON record protocol; it is not the NLS data-handshake wire format.
2. The router's local Router-CA YAML store (security/trust/router_ca/store.py) is not itself evidence that each peer's presented certificate is currently valid, unexpired and unrevoked. The CA control API currently syncs policy and a revocation list, not a signed per-router lookup record.
3. nls/encapsulation.py uses RSA-OAEP-SHA256-wrapped per-packet AES keys. The X25519/HKDF values produced by the handshake are stored in sessions but are not passed into seal_ip_packet/open_ip_packet.
4. nls/daemon.py:_send_init uses the socket's configured bind/source behavior; no code adds a temporary vIP with ip -6 addr, pins the socket to it, transitions to the real WAN endpoint, or removes the address.
5. The Router-CA certificate issued by CertificateAuthority.enroll binds an Ed25519 identity key and uses an RSA CA signing key. Router encryption public keys/WAN and gateway metadata are not represented as a complete signed lookup object in the current control API.
6. The existing network-namespace integration test is useful baseline evidence but is not the requested six-node client/routerA/WAN/routerB/server/CA test and does not implement the full S1–S6 handshake. No runtime test results are claimed by this inventory.

## Phase 0 gate

**Result: INVENTORY WRITTEN; IMPLEMENTATION GATE NOT YET PASSED.** The core protocol/control/data-plane sources and relevant tests have been inspected at source level. The implementation has substantial gaps against R1–R14, so the next phase must not assume existing behavior matches the normative protocol. Before Phase 1, retain the current CLI, leave vtysh untouched, preserve GUI safety and default-disabled NLS, and do not create routes from CA metadata alone. No test command was executed as part of this source-only inventory.


## Supplemental Phase 0 verification (2026-10-16)

### Source-file coverage

Fetched and indexed every tracked file matching the repositories' executable/configuration/test extensions at the reviewed main-tree SHAs: 133 files in NlsxNetOS and 24 files in Nls-NexOS-Core. This included Python modules, shell scripts, systemd units, YAML/TOML/JSON configuration, CI workflows and tests. Function/class declarations and security-sensitive operations were indexed across these files; core NLS handshake, daemon, encapsulation, replay, route, CLI, installer, AppArmor, Router-CA API/control, enrollment and database paths were also read directly. Non-code documentation was not treated as implementation evidence.

### Baseline automated tests (GitHub-hosted Ubuntu runners)

These runs were triggered from documentation-only feature branches. No implementation file changed. Test output below is from the repository CI logs; the pytest result lines are reproduced verbatim.

**NlsxNetOS, Ubuntu 22.04 — unit + security**
```text
2026-10-16T04:45:27.4544900Z ......................................................                   [100%]
2026-10-16T04:45:27.4545267Z 54 passed in 4.04s
```

**NlsxNetOS, Ubuntu 24.04 — unit + security**
```text
2026-10-16T04:45:32.3249153Z ......................................................                   [100%]
2026-10-16T04:45:32.3250601Z 54 passed in 6.95s
```

**NlsxNetOS, Ubuntu 24.04 — four-node forwarding integration**
```text
2026-10-16T04:45:36.0501697Z .                                                                        [100%]
2026-10-16T04:45:36.0502306Z 1 passed in 16.79s
```

**NlsxNetOS, Ubuntu 24.04 — ten-router IPv6 chain integration**
```text
2026-10-16T04:45:29.2847436Z .                                                                        [100%]
2026-10-16T04:45:29.2847769Z 1 passed in 7.73s
```

**Nls-NexOS-Core, Ubuntu 24.04 — unit + security**
```text
2026-10-16T04:45:25.2328104Z ..............                                                           [100%]
2026-10-16T04:45:25.2328946Z 14 passed in 0.80s
```

**Cross-repository control integration, Ubuntu 22.04**
```text
2026-10-16T04:45:26.1105610Z .                                                                        [100%]
2026-10-16T04:45:26.1151611Z 1 passed, 8 warnings in 1.50s
```

**Cross-repository control integration, Ubuntu 24.04**
```text
2026-10-16T04:45:25.6656406Z .                                                                        [100%]
2026-10-16T04:45:25.6683976Z 1 passed, 8 warnings in 1.51s
```

All jobs in router CI run 38852215428 and CA CI run 38852227009 completed successfully. Router CI also passed package build/install/reinstall/purge/reinstall, fresh-install checks on Ubuntu 22.04 and 24.04, source-integrity check, dependency audit and ShellCheck. CA CI's unit job passed compilation and tests. The cross-repository integration emits eight Python/cryptography datetime deprecation warnings; those warnings are not test failures. These existing suites do not cover the required new M1–M4/vIP/session-AEAD attack matrix.

### Compatibility and behavior preservation evidence

- **No source behavior changed in this gate branch:** the only changes in the gate commits are this inventory document. CLI, runtime, systemd, AppArmor, package and route source files are unchanged relative to main. CI run links: [NlsxNetOS run 38852215428](https://github.com/TamilSelvam22112003/NlsxNetOS-v0.1.0/actions/runs/38852215428), [Nls-NexOS-Core run 38852227009](https://github.com/TamilSelvam22112003/Nls-NexOS-Core-v0.1.0/actions/runs/38852227009).
- **CLI:** tools/router_cli/commands.py:main, interactive_cli retain the `nlsxnetos` subcommands and IOS-like interactive modes. No CLI source was modified.
- **vtysh/FRR:** scripts/build/deb.sh rejects package contents containing /etc/frr, /usr/lib/frr, /usr/bin/vtysh or FRR daemons; .github/workflows/ci.yml repeats that package-ownership assertion and runs `vtysh -c "show version"`. net/validation.py:frr_validate deliberately reports vtysh unavailable inside AppArmor confinement rather than invoking it there; tests/unit/test_frr_validation.py:test_confined_frr_validation_fails_closed_without_vtysh and test_unconfined_frr_validation_executes_vtysh cover this distinction. This is evidence that packaging does not own/replace vtysh and CI can invoke it, not a claim that every administrator workflow was manually exercised.
- **GUI safety:** scripts/install/install.sh does not remove desktop packages; it installs ubuntu-desktop-minimal and Firefox only for explicit `--with-gui`. scripts/install/uninstall.sh purges only nlsxnetos and states FRR is left installed. scripts/build/deb.sh removes only generated packaging/deb staging subdirectories and dist, not the host desktop. This behavior was not modified.
- **NLS default/registration:** config/nls/nls.yaml sets enabled=false and tun.enabled=false; nls/config.py:NLSConfig defaults are false; nls/daemon.py:run refuses to run when disabled, without active Router-CA entries, or without TUN enabled. nls/activation.py:activate checks for active entries and an enabled WAN interface. Caveat: activate checks that some Router-CA entry is NLS-ready, not explicitly that the local identity matches that entry; nls/daemon.py:_send_init later enforces that identity match before sending INIT.
- **Route-management caveat (important):** nls/config.py:load with auto_router_ca=true imports active Router-CA entries as PeerConfig objects and assigns each entry's prefix to allowed_prefixes; nls/daemon.py:run calls nls/routing.py:install_tun_routes on all configured peers; install_tun_routes creates a TUN route for any missing allowed prefix. Therefore, in the current main branch, a Router-CA entry can indirectly cause route installation through auto_router_ca. The requested invariant “no route creation from CA metadata alone” is **not currently satisfied**. This gate made no route-source changes, so it did not introduce the behavior, but I cannot confirm that invariant as currently true.
- **No test failures occurred in the CI runs above.** No manual VM tests were performed by this review.

### Explicit public-key forgery assessment (R10)

**Yes, the current data-plane construction permits cryptographic packet forgery using the destination router's RSA public key, subject to session admission checks.** In nls/encapsulation.py:seal_ip_packet, the sender generates a fresh attacker-selectable AES key with secrets.token_bytes(32), wraps it using nls/rsa.py:wrap_key (RSA-OAEP-SHA256 to the destination public key), then authenticates/encrypts the packet with AESGCM(data_key). A receiver decrypts the wrapped key with its private key and accepts a valid AES-GCM tag in open_ip_packet; no sender Ed25519 signature or session-derived directional data key authenticates the DATA packet. An attacker can therefore construct a valid AEAD ciphertext for a chosen inner packet and wrap the key to the destination's public key.

**Acceptance is not unconditional from the public key alone:** nls/daemon.py:NLSDaemon._handle_data also requires an existing session ID, the packet's source endpoint to match session.endpoint, expected router identity and an acceptable sequence in ReplayWindow. An attacker who does not know or cannot satisfy those session/source constraints may be rejected. Those checks do not fix the cryptographic design flaw if an attacker can observe/reuse session metadata and deliver from an accepted endpoint or spoof it. This is why D1's sender-authenticated, HKDF-derived directional AEAD is required.

### Updated Phase 0 gate result

**NOT PASSED. Do not start Phase 1 yet.** The existing CI suites pass, and the gate branch did not change implementation code. However, the current implementation materially fails R2–R7 and R8–R10 as described above, and the current `auto_router_ca` path contradicts the requested “no route creation from CA metadata alone” invariant. Phase 0 has documented these gaps and existing test results; this report is not an approval to proceed to Phase 1.

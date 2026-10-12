# Boot Enrollment Flow

## 1. Layer-3 reachability

Configure the router management path to the Router-CA management IPv6 address. Verify route and bidirectional reachability using `ip -6 route get`, `ping -6`, or `tracepath6`. These checks prove only network reachability. The service identity is verified cryptographically during the NLS handshake using a provisioned Router-CA Ed25519 public-key fingerprint.

## 2. PKI enrollment

The router generates its own signing key locally and creates a CSR. It submits its router ID, CSR, fresh request ID/nonce/timestamp, and an authorized bootstrap credential through a protected NLS control channel. The Router-CA checks the registered router, CSR signature, key binding, freshness, replay record, and authorization policy before issuing a constrained identity certificate. Private keys are never transmitted. The current code contains certificate-signing primitives but does not yet wire enrollment over NLS.

## 3. Mutual NLS control channel

The proposed control protocol uses a signed CHLO/SHLO exchange, pinned Ed25519 identities, ephemeral X25519 key agreement, HKDF-SHA-256 transcript-bound derivation, and AES-256-GCM protected records with direction-specific sequence numbers. The protocol code exists as a library prototype; TCP networking, persistent service endpoints, and client daemon integration remain incomplete.

## 4. Policy, revocation, and session parameters

After NLS control authentication, the Router-CA should authorize requests for versioned policy and signed revocation data. The routers derive NLS data-plane keys locally from ephemeral key agreement. Do not transmit raw AES keys. Current policy/revocation endpoints are not implemented.

## Verification checklist

- `ip -6 route get <ca-ipv6>` succeeds; ping/traceroute as permitted by network policy.
- Router-CA public-key fingerprint matches pre-provisioned configuration.
- Enrollment denied for unknown router IDs, invalid CSR signatures, stale/replayed requests, and unauthorized credentials.
- Router certificate validates against CA root and matches expected router identity.
- NLS handshake fails on unpinned server keys, invalid signatures, stale timestamps, and duplicate/replayed session IDs.
- `ss -ntp` shows an NLS control TCP socket only after the production stream adapter is implemented; `ss -unp` shows current UDP NLS data-plane socket.
- CI and a two-VM Ubuntu integration test both pass before claiming support.
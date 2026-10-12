# NLS Router-CA Architecture

## Responsibilities

- **Nls-NexOS-Core** runs Router-CA control services, router registration, enrollment authorization, X.509 certificate issuance, revocation state, policy versions and audit records.
- **NlsxNetOS** runs on edge routers and owns local identity keys, CSR generation, the NLS control client, the NLS data plane, and policy/revocation cache.
- Router-CA is not a user-packet forwarding hop.

## Four-phase connection sequence

1. **Reachability:** establish ordinary IPv6 management reachability to the configured Router-CA endpoint. Route/ping/traceroute diagnostics confirm network reachability only; the pinned NLS control handshake authenticates the service.
2. **Enrollment:** router creates an Ed25519 private key and CSR locally. The first NLS control handshake is pinned to the Router-CA Ed25519 control public key provisioned out-of-band. A fresh encrypted enrollment request contains the CSR, request ID, nonce, timestamp, global bootstrap credential, and router-specific credential. Router-CA validates both tokens, router registry state, CSR signature, key binding, time window and replay state before certificate issuance.
3. **Mutual NLS control:** router reconnects and presents its Router-CA-signed identity certificate in the signed NLS hello. Router-CA validates the certificate against its signing root, validity, Ed25519 key binding, router identity, active registry record and certificate status. The router independently verifies the Router-CA’s pinned control identity.
4. **Policy/revocation synchronization:** a persistent TCP channel uses encrypted heartbeat and sync messages. Router-CA sends a versioned policy profile and certificate revocation state. NLS session keys are derived by the peers with ephemeral X25519/HKDF; the server does not distribute raw symmetric keys.

## Control wire protocol

NLS Control Record Protocol v1 uses a framed TCP stream:
- 4-byte `NLSC` magic, protocol version, record kind and a bounded length
- Ed25519-signed client/server hello messages with timestamp, fresh nonce and transcript binding
- ephemeral X25519 shared secret; HKDF-SHA-256 key schedule bound to the complete signed handshake transcript
- separate client-to-server and server-to-client AES-256-GCM keys
- deterministic directional nonce prefix plus a strict 64-bit monotonically increasing sequence number per direction
- encrypted, schema-checked JSON control requests and responses

The router data plane remains NLS UDP (default port 4789); Router-CA control defaults to TCP port 4790. The two protocols have different framing and purposes.

## Address privacy

Ordinary IP forwarding requires a routable outer destination address, so the outer IP destination remains visible to transit routers. NLS encapsulation must place sensitive original endpoint metadata and the inner packet inside authenticated encryption. Do not encrypt only the outer IP destination field and expect normal routers to forward it.

## Keys and trust

- The CA signing private key signs router identity certificates and is separate from the Ed25519 NLS control identity key.
- Routers must pin the Router-CA control identity key and install the CA root certificate through a trusted out-of-band procedure before enrollment.
- Router and CA private keys never cross the network.
- IP/MAC metadata is not proof of identity. Token authorization plus CSR key-possession proof is used for first enrollment; subsequent control sessions require an active CA-issued identity certificate.
- The NLS control protocol is experimental custom cryptography and must receive independent review before production use.

## Remaining work

Independent cryptographic review; formally versioned wire specification; certificate renewal/rotation automation; production CRL/OCSP; TPM/HSM support; rate limiting and administrator APIs; and a multi-host IPv6 deployment test beyond the CI loopback integration test.

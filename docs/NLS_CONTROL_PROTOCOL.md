# NLS Control Protocol (Experimental v1)

## Purpose

This protocol is the proposed NLS-native alternative to TLS for the Router-CA management control channel. It is separate from NlsxNetOS's current UDP data-plane handshake. The code under `src/nls_nexos_core/nls_control.py` implements cryptographic building blocks and in-memory tests only; it does not yet run a network service, enrollment API, or persistent session agent.

## Identity and trust prerequisites

Before the handshake, each side must have a trusted Ed25519 signing public key for the peer. The client pins the Router-CA signing public key; the CA resolves the client ID and public key against an administrator-approved registry. A self-supplied key is never a trust anchor. Initial provisioning must use an out-of-band verified Router-CA key fingerprint and an enrollment token or equivalent credential.

## Handshake

1. **CHLO:** client sends protocol version, client and expected server IDs, the pinned server-key fingerprint, client Ed25519 public key, an ephemeral X25519 public key, 128-bit session ID, 256-bit random nonce, timestamp, and Ed25519 signature over canonical JSON.
2. **CA verification:** reject malformed fields, wrong protocol/server ID, wrong pinned-key fingerprint, invalid signature, stale timestamp, repeated session ID/nonce, or client identity not authorized by the Router-CA registry. The caller must implement persistent replay tracking and rate limiting.
3. **SHLO:** server returns its pinned public key, ephemeral X25519 public key, session ID, both nonces, timestamp and the hash of CHLO; the entire response is signed by the Router-CA Ed25519 key.
4. **Key derivation:** both sides compute X25519 shared secret and derive 64 bytes with HKDF-SHA-256 using a transcript/session/nonce-bound salt. Separate client-to-server and server-to-client keys are derived from the two halves.
5. **Protected records:** each record contains NLS framing, session ID, direction, strictly increasing sequence number, length, and AES-256-GCM ciphertext/tag. Header/session/direction/sequence are associated authenticated data. Nonce is the 32-bit direction label plus 64-bit sequence number. Rekey before sequence exhaustion and never reuse a key/nonce pair.

## Transport and application protocol

The framing is stream-oriented and requires an exact-read/exact-write loop over TCP or an explicitly specified NLS tunnel. A transport adapter must reject oversized frames, partial frames, invalid message types, timeouts, and unauthenticated sessions. Do not place the CA on the public Internet until that adapter and rate-limited service are complete.

Post-enrollment operations should include `HEALTH`, `ENROLL`, `POLICY_GET`, `REVOCATION_GET`, `SESSION_PARAMS`, and `KEY_ROTATE`. The Core-side authorization layer must reject every unknown operation and enforce each router's policy. Symmetric data-plane keys must not be sent directly; exchange ephemeral key-agreement parameters and derive traffic keys at both ends.

## Why not encrypt the ordinary destination IP field

Ordinary IP routers need the outer destination address to forward packets, so ordinary IPv6 source/destination fields remain visible. Private original source/destination metadata belongs inside NLS authenticated-encrypted inner packet contents. For the control channel, IP reachability is a separate prerequisite from protocol authentication.

## Security status

**Experimental; not security-reviewed; not production-ready.** A custom security protocol needs external cryptographic review, threat modelling, protocol state-machine tests, fuzzing, downgrade/replay/cross-session tests, and interoperability testing. The implementation currently lacks persistent anti-replay state, retry/timeout handling, rekey support, network socket lifecycle, and integration with the existing router daemon/CA registry.
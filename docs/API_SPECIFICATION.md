# NLS Control Record Protocol v1: Control Operations

This repository implements a **custom experimental NLS control protocol over TCP**. It is not TLS, not HTTP, and does not claim interoperability with TLS implementations. The default control port is 4790; NLS user-data transport remains separate (typically UDP 4789).

## Handshake and records

The protocol uses Ed25519-signed hello messages, a pre-provisioned Router-CA control public-key pin, fresh X25519 ephemeral key agreement, transcript-bound HKDF-SHA-256 derivation, directional AES-256-GCM records, bounded framing and strict monotonic sequence numbers. Each peer confirms the derived session transcript before sending application messages.

These measures are an experimental design, not a substitute for an independent cryptographic review. The wire protocol has not been formally verified or audited and must not be used for critical production/defence traffic before review.

## Messages

- `health`: service and protocol readiness.
- `enroll`: CSR, request ID, nonce, timestamp, global bootstrap credential, and router-specific credential, carried inside encrypted records.
- `sync`: requires a valid Router-CA-issued identity certificate and returns versioned policy/revocation state.
- `heartbeat`: requires a valid certificate and returns updated policy/revocation state on a persistent connection.
- `status`: requires a valid certificate and returns the authenticated router identity and certificate serial.
- `close`: closes the record channel.

## Identity and key handling

The router private key never leaves the router. Router-CA signs an identity certificate only after validating the CSR signature, registry authorization, credentials, freshness and anti-replay state. Subsequent control connections validate issuer, validity, certificate purpose, public-key binding, registry status and revocation state.

The peers derive NLS data-plane session keys locally through X25519/HKDF. The CA sends policy parameters, never raw symmetric keys. Ordinary outer IP destination fields needed for routing remain visible; protected original endpoints and packet payload belong inside an authenticated-encrypted NLS inner packet.

## Revocation and limitations

`nls-router-ca revoke-certificate SERIAL` marks an active certificate revoked. New control connections are refused and connected peers receive revocation state during heartbeats. Robust refresh/expiry policy, signed CRL/OCSP distribution, automated certificate renewal, TPM/HSM support, administration API and rate limiting remain future work.
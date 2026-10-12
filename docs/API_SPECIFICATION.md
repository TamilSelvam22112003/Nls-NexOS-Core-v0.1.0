# Router-CA NLS Control Protocol — Proposed v1

This is a wire-protocol target, not an implemented listener. Production Router-CA traffic must use NLS control messages integrated with the NLS protocol in NlsxNetOS; do not deploy the developer-only HTTP-shaped adapter as the network transport.

## Common control envelope

Each control message should be carried inside an authenticated-encrypted NLS session and include:
- protocol version and message type
- router identity and intended CA identity
- monotonically increasing request/sequence number
- cryptographically random nonce and timestamp/expiry
- request/correlation ID
- length-bounded message payload and authenticated transcript binding

Reject unknown protocol versions, invalid identities, expired timestamps, duplicate request IDs/nonces, malformed fields, unauthorized operations and invalid authentication tags. Control-message parsing must be strict and bounded.

## Proposed message types

- `NLS_CA_PROBE` / `NLS_CA_PROBE_RESPONSE`: authenticated service reachability and identity.
- `NLS_ENROLL_REQUEST`: router ID, signed CSR, request ID/nonce/timestamp, server bootstrap credential and router-specific enrollment credential.
- `NLS_ENROLL_RESPONSE`: CA-signed router certificate, CA chain, serial number and validity interval. Never include a private key.
- `NLS_POLICY_REQUEST` / `NLS_POLICY_RESPONSE`: versioned policy bound to the authenticated router identity.
- `NLS_REVOCATION_REQUEST` / `NLS_REVOCATION_RESPONSE`: authenticated current revocation state or signed CRL.
- `NLS_ERROR`: stable error code and correlation ID, no secret material.

The bootstrap credential and the per-router enrollment token are separate secrets. The router token must match the registry hash for that router; the bootstrap token must pass the server bootstrap gate. Credentials must be inside the authenticated-encrypted NLS envelope, not in plaintext or logs.

## Current implementation status

The Pydantic request/response models, registry checks, replay store and CA-signed certificate generation exist. The Core API module is a developer-only adapter, and the CLI deliberately refuses to start a plaintext listener. The NLS wire listener, NLS handshake integration, policy API, revocation service and router-side enrollment client are not implemented or end-to-end tested yet.

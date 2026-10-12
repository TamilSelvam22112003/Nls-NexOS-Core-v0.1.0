# Nls-NexOS Core

Router-CA trust and enrollment services for NLS-enabled Ubuntu routers.

This repository is the server/control-plane counterpart to [NlsxNetOS-v0.1.0](https://github.com/TamilSelvam22112003/NlsxNetOS-v0.1.0).

## Scope for v0.1.0

- Reachability checks for Router-CA management endpoint
- Router enrollment using a locally generated private key and CSR
- Explicit router authorization against a registry
- CA-signed router identity certificates
- Mutual TLS control channel
- Session/policy distribution interfaces
- CRL/revocation foundations and audit records
- Debian/Ubuntu packaging and systemd units

## Security design requirements

- Never transmit router private keys.
- Pin and validate the Router-CA trust anchor before sending credentials.
- Use TLS 1.3 mutual authentication for the control channel; do not invent custom public-key encryption for arbitrary IP fields.
- Outer IP addresses are part of the network header and are not encrypted by the transport. Data that must be confidential belongs in the encrypted application/NLS inner payload.
- Router MAC/IP values are inventory attributes, not proof of identity by themselves. Authorization is bound to possession of the enrolled private key and an approved enrollment credential.
- CA signing keys must be separated from the router registry database and protected with restrictive permissions or a hardware-backed key store.

## Status

This repository is initialized with architecture and protocol requirements. The enrollment API, certificate issuance, mTLS service, package integration, and VM/system integration tests must be implemented and validated before production use.

## Planned layout

See `docs/ARCHITECTURE.md`, `docs/BOOT_ENROLLMENT_FLOW.md`, and `docs/SECURITY_MODEL.md`.

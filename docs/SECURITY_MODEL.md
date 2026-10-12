# Security Model

## Protected assets

CA signing key, router private keys, bootstrap/enrollment credentials, registry/authorization policies, router identity certificates, revocation state, and NLS session key material.

## Required controls

- Pin the Router-CA trust anchor before first enrollment. Authenticate the CA identity using the NLS protocol, not an unauthenticated reachability result.
- Never transmit router private keys. Generate them locally and enforce restrictive filesystem permissions.
- Require both a server bootstrap credential and a distinct router-specific token bound to a registered router identity.
- Validate the CSR signature, expected key binding, router allow-list/status, and certificate purpose/identity.
- Apply freshness windows, unique request IDs, nonces and a persistent replay store.
- Treat MAC/IP as inventory information, not identity proof.
- Use parameterized SQL, request-size bounds, rate limiting, sanitized audit logs and access-controlled registry files.
- Keep the CA signing key separate from the database and protect it with offline/HSM custody where practical.
- Use NLS authenticated encryption and identity-bound key derivation for control messages. Derive data-plane symmetric keys locally, and never log or transmit them in plaintext.

## Out of scope and release blockers

The current Core scaffold has no NLS network listener or mutual NLS control handshake; policy/revocation services, certificate renewal/rotation, TPM attestation, HSM integration, HA and independent protocol/security review remain incomplete. Do not call this production-ready until those items are implemented and tested on clean Ubuntu VMs.

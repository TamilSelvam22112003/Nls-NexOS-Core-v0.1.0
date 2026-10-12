# Security Model

## Assets

CA signing key, NLS control identity key, router private keys, bootstrap and per-router tokens, router registry, issued certificates, policy/revocation state, and NLS data-plane session key material.

## Current controls

- Routers pin the Router-CA Ed25519 control public key out-of-band.
- Router certificate signing uses a separate CA signing key and pre-provisioned CA root certificate.
- Router private keys are generated/stored locally and never transmitted.
- First enrollment requires signed CSR proof, freshness/replay checks, a registered router, a global bootstrap credential and a router-specific credential inside an encrypted record.
- Subsequent NLS control sessions require an issued identity certificate with matching Ed25519 key, valid issuer/time/EKU, active registry entry, and non-revoked serial.
- Control records use ephemeral X25519, transcript-bound HKDF-SHA-256, directional AES-256-GCM, and strict record sequence validation.
- SQL statements are parameterized; enrollment request IDs/nonces are persistent and uniqueness-constrained; logs exclude credentials.

## Important qualification

The NLS Control Record Protocol is **custom experimental cryptography, not TLS**. Code and CI success do not establish cryptographic soundness. It has not received independent cryptographic review, formal verification, or hostile-network interoperability testing. Do not deploy to critical or untrusted production networks until the wire protocol is reviewed and signed off by qualified cryptographers.

## Remaining operational work

TPM attestation, HSM protection, HA, automated certificate renewal, robust rate limiting, administrator authentication/API, signed CRL/OCSP publishing, revocation refresh/expiry policy, and multi-host IPv6 testing.
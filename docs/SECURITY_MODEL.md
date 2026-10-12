# Security Model

## Protected assets

CA signing key, router private keys, enrollment credentials, registry and authorization policies, certificates/revocation state, and NLS session key material.

## Threats and required controls

- Unknown router enrollment: allow-list registration and enrollment authorization.
- Spoofed IP/MAC: treat them as attributes, not proof; validate public-key possession and enrollment credential.
- Replay: unique request IDs/nonces, freshness window, persistent replay store.
- Fake CA: pinned root trust, strict TLS certificate/identity checks, never disable verification.
- CSR key substitution: validate CSR signature and compare public-key fingerprint to registry when pre-registered.
- Expiry/revocation: short-lived certificates, status checks and authenticated revocation updates.
- Injection: parameterized SQL and input size/schema validation.
- Credential disclosure: never log token or private keys; root-only bootstrap secret file.
- Database tampering: restrictive ownership, audit events, backups and administrative access control.

## Not in initial prototype

TPM attestation, HSM key storage, HA, formal verification, Internet-scale issuance, and production CRL/OCSP. Do not claim production readiness until these and independent review are complete.

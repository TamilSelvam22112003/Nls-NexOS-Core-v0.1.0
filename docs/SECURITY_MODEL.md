# Security Model

Protect the CA signing key, router private keys, enrollment credentials, router inventory, certificates and NLS session material.

- Pin the CA root and verify its server certificate before transmitting credentials.
- Never transmit router private keys. Generate and store them locally with restrictive permissions.
- Use an allow-list, authorized bootstrap credential, signed CSR/key-possession proof, freshness checks and persistent replay records.
- Treat MAC and IP as inventory attributes, not identity proof by themselves.
- Validate certificates for issuer, validity, identity and purpose; support short-lived credentials and revocation.
- Use parameterized SQL, request-size bounds, rate limits, sanitized audit logs and access-controlled registry files.
- Keep CA signing key outside the router database; use offline/HSM protection for production where possible.

TPM attestation, HSM operation, HA, full CRL/OCSP service, production mTLS authorization and independent security review remain out of scope for the initial prototype.
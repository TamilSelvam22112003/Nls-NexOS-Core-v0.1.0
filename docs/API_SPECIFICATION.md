# API Specification v1

- `GET /health`: service readiness only; still validate TLS server identity.
- `POST /api/v1/enroll`: bootstrap endpoint over pinned TLS; requires router ID, signed CSR, request ID, nonce, timestamp and the high-entropy enrollment credential header. Returns the CA-signed router certificate, CA certificate, serial and validity timestamps. Never returns a private key.
- `GET /api/v1/policy`: planned; must require validated mTLS client identity mapped to an active router record.
- `GET /api/v1/revocation`: planned; must provide authenticated/signed revocation state.

Important: in this scaffold, the CLI intentionally refuses to start a plaintext server because HTTPS listener wiring and mTLS authorization are incomplete. Do not expose it on an untrusted network.
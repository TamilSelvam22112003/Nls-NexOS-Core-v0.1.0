# Nls-NexOS Core

Router-CA trust and enrollment control-plane prototype for NLS-enabled Ubuntu routers.

This repository is the server/control-plane counterpart to [NlsxNetOS-v0.1.0](https://github.com/TamilSelvam22112003/NlsxNetOS-v0.1.0).

## Important protocol terminology

**NLS is the intended router-to-router data-plane/control-plane protocol.** NlsxNetOS implements an experimental NLS handshake and UDP encapsulation. This Core scaffold is not yet integrated into that NLS handshake. Its HTTP-shaped enrollment API is only an API contract/prototype; TLS must not be silently described as NLS, and no production TLS control channel is implemented here.

The intended end-state is:
1. Verify routed management reachability between router and Router-CA.
2. Enroll the router identity with a local private key and CSR, pinned CA trust and a one-time/authorized enrollment credential.
3. Use an authenticated NLS control channel whose handshake explicitly binds both router identities and Router-CA authorization data.
4. Distribute versioned policy/revocation state and let NLS peers derive session keys locally through ephemeral X25519/HKDF.
5. Do not transmit raw data-plane session keys or router private keys.

## Current implementation status

Implemented scaffold:
- typed enrollment request/response models
- SQLite router registry, request replay table, certificate index and audit table
- CSR signature validation and CA-signed client-identity certificate generation
- configuration model and CI unit tests
- architecture/security/flow documentation

Not implemented or not integration-tested:
- NLS control listener and NLS handshake integration
- endpoint reachability agent and CSR/enrollment client in NlsxNetOS
- enforced mutual-authentication and authorization for policy APIs
- working policy distribution, CRL/OCSP lifecycle, and revocation checks
- Debian/Ubuntu package install for Core
- end-to-end Router ↔ Router-CA test in Ubuntu VMs

The current CLI deliberately refuses to start a plaintext service. Do not deploy this scaffold as a network-facing CA service or treat a passing unit-test workflow as evidence of production security.

## Test

```bash
python3 -m pip install -e ".[test]"
python3 -m compileall -q src tests
pytest -q
```

See:
- `docs/ARCHITECTURE.md`
- `docs/BOOT_ENROLLMENT_FLOW.md`
- `docs/SECURITY_MODEL.md`
- `docs/API_SPECIFICATION.md`

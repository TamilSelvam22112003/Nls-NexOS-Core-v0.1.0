# Nls-NexOS Core

Router-CA trust and enrollment control-plane prototype for NLS-enabled Ubuntu routers.

This repository is the intended server/control-plane counterpart to [NlsxNetOS-v0.1.0](https://github.com/TamilSelvam22112003/NlsxNetOS-v0.1.0).

## Protocol boundary: NLS, not TLS

NlsxNetOS contains an experimental NLS UDP handshake and encrypted data-plane encapsulation. This Core repository is **not yet integrated with that NLS wire protocol**. The FastAPI module is a developer/test scaffold; it is not the Router-CA network listener and must not be exposed as a production HTTP service.

The intended production workflow is:
1. Verify Layer-3 management reachability to the Router-CA endpoint.
2. Generate router private keys locally and submit a CSR inside an authenticated NLS enrollment message.
3. Require both a server bootstrap credential and router-specific enrollment authorization, bound to the fresh request, router identity and CSR key.
4. Establish a mutually authenticated NLS control session with identity binding, anti-replay, ephemeral key agreement and key derivation.
5. Deliver versioned policy and revocation state over that NLS session. Routers derive data-plane keys locally; the CA must not send raw symmetric session keys or receive router private keys.

Outer IP addresses required to route packets remain visible. Sensitive original endpoints and packet payload belong inside authenticated-encrypted NLS encapsulation.

## Scaffold implemented

- Typed enrollment request/response models.
- SQLite router registry, request replay records, certificate index and audit records.
- CSR signature checks and CA-signed router certificate creation.
- Separate bootstrap-token and router-token authorization checks.
- CLI for CA bootstrap and router registry registration.
- Unit/security tests and Ubuntu 24.04 GitHub Actions CI.

## Not implemented or not integration-tested

- An NLS control listener and compatible NLS control message framing.
- Router-side CSR generation/enrollment/import integrated with NlsxNetOS.
- Certificate validation and identity binding over a live NLS control session.
- Policy delivery, operational revocation/CRL/OCSP, certificate renewal and rotation.
- A packaged Core installation and end-to-end Router ↔ Router-CA enrollment across Ubuntu VMs.

The CLI intentionally refuses to start a plaintext listener. A passing Core CI verifies the local scaffold only; it does not prove network interoperability or production security. Do not deploy the scaffold as a network-facing CA.

## Test the current scaffold

```bash
python3 -m pip install -e ".[test]"
python3 -m compileall -q src tests
pytest -q
```

See `docs/ARCHITECTURE.md`, `docs/BOOT_ENROLLMENT_FLOW.md`, `docs/SECURITY_MODEL.md`, and `docs/API_SPECIFICATION.md`.

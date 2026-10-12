# Security Model

## Assets

CA signing key, NLS control identity key, router private keys, bootstrap and per-router tokens, router registry, issued certificates, policy and revocation state, and NLS data-plane session key material.

## Controls

- Routers pin the Router-CA Ed25519 control public key out-of-band. The server cannot replace this trust pin during a network handshake.
- Router certificate signing uses a separate CA signing key and a pre-provisioned CA root certificate.
- Router private keys are generated and stored locally; they never leave the device.
- First enrollment requires a signed CSR, freshness/replay controls, an approved router ID, a global bootstrap credential and a router-specific credential inside an authenticated encrypted record.
- Subsequent NLS control connections carry the issued certificate. Router-CA verifies signature, validity, Ed25519 key binding, identity, registry status and certificate revocation status.
- The control protocol uses ephemeral X25519, transcript-bound HKDF-SHA-256, independent directional AES-256-GCM keys, deterministic per-direction nonces, and strict sequence checks.
- Policy/revocation responses are carried in the encrypted record layer. Raw symmetric session keys are derived locally rather than sent from the CA.
- SQLite statements are parameterized. Enrollment request IDs and nonces are unique; audit records do not contain credentials or private keys.
- Bootstrap token files must be high-entropy and owner-only; restrict Router-CA port 4790 to the management network.

## Known limitations

NLS Control Record Protocol v1 is custom, experimental cryptography and has not received independent protocol review or formal verification. It does not currently include TPM attestation, HSM operation, automated certificate renewal, high availability, robust rate limiting, administrator authentication/API, production CRL/OCSP publishing, or tested multi-host internet exposure. Do not deploy to critical or untrusted production networks until the protocol is reviewed and these operational controls are implemented.

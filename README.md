# Nls-NexOS Core

Router-CA enrollment, certificate issuance, revocation, and NLS control-plane service for NlsxNetOS routers.

Companion router repository: [NlsxNetOS-v0.1.0](https://github.com/TamilSelvam22112003/NlsxNetOS-v0.1.0).

## Implemented in this revision

- TCP NLS Control Record Protocol v1 listener (default port **4790**)
- Signed Ed25519 client/server hello messages, fresh X25519 key agreement, transcript-bound HKDF-SHA-256, and directional AES-256-GCM records
- Sequence-checked encrypted records and handshake replay-nonce cache
- Pre-provisioned Router-CA control identity pinning before enrollment
- Router CSR validation, bootstrap-token plus router-specific enrollment-token authorization, and CA-signed router identity certificates
- Certificate verification against the pinned Router-CA root on subsequent NLS control connections
- SQLite router/certificate registry with an idempotent schema-version migration, per-router record sequence, and monotonic directory sequence
- RSA-3072 encryption-key enrollment binding with request-bound RSA-PSS proof-of-possession and optional administrator-pinned RSA fingerprint
- Canonical-CBOR, domain-separated signed Router Directory Records and signed offline directory bundles
- Authenticated, nonce-bound `lookup`, signed `directory-sync`, heartbeat directory sequence/revocation state, and per-router request rate limits
- Operator-owned WAN endpoints, gateway IPs and prefixes; `revoke-router` revokes the router and its active certificates; `export-directory` emits a signed bundle
- Encrypted sync and heartbeat messages carrying versioned NLS policy and revocation state
- Core unit tests and a cross-repository IPv6 loopback integration test against the NlsxNetOS client

## Four-step workflow

1. **L3 reachability:** configure routed IPv6 management reachability to the Router-CA. Use `ip -6 route get`, `ping -6`, and `tracepath6` as diagnostics.
2. **PKI enrollment:** generate an Ed25519 router key locally, create a CSR, establish NLS Control v1 using a pre-provisioned Router-CA control public-key pin, and submit the CSR with both bootstrap and router-specific credentials inside the encrypted channel. The private key never leaves the router.
3. **Mutual NLS control:** reconnect with the signed router identity certificate. Router-CA validates its chain, validity, public-key binding, registry record and revocation status. The router authenticates the Router-CA using its pinned Ed25519 control identity key.
4. **Policy and revocation synchronization:** keep the TCP channel open and exchange heartbeats. Router-CA returns versioned NLS cryptographic policy and revoked certificate serials; session keys are derived locally by X25519/HKDF and are never sent as raw symmetric keys.

NLS data-plane packets remain on the existing NLS UDP transport (default port 4789); the NLS control channel uses TCP port 4790. Outer IP destination addresses required by ordinary routing remain visible; sensitive original endpoints and user payload belong inside the encrypted NLS inner packet.

## Important security status

NLS Control Record Protocol v1 is a custom experimental protocol. It is implemented with signed handshakes, ephemeral key agreement, transcript binding, AEAD records and sequence checks, but it has **not** received independent cryptographic review, formal verification, or hostile-network interoperability testing. Do not deploy this custom protocol for production or critical/defence networks until an independent review and agreed protocol specification are complete. HSM/TPM attestation, HA, certificate renewal automation, and a production CRL/OCSP service also remain future work.

The control identity key and CA signing key are different keys. Distribute the CA root certificate, NLS control identity pin, and enrollment credentials to routers out-of-band. Do not trust keys received from the network before pinning.

## Install and test on Ubuntu

```bash
sudo apt-get update
sudo apt-get install -y python3-venv python3-pip
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e ".[test]"
python -m compileall -q src tests
pytest -q tests/unit tests/security
```

For a local service test, copy `config/router-ca.example.yaml`, change file paths to a writable test directory, set `server.host: "::1"`, then run `nls-router-ca --config /path/to/test.yaml init` and `nls-router-ca --config /path/to/test.yaml serve` in separate terminals. The GitHub Actions `cross-repo-control-integration` job tests actual router enrollment and subsequent certificate-authenticated policy synchronization on Ubuntu 22.04 and 24.04 runners.

See `docs/ARCHITECTURE.md`, `docs/BOOT_ENROLLMENT_FLOW.md`, `docs/SECURITY_MODEL.md`, and `docs/API_SPECIFICATION.md`.

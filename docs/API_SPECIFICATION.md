# NLS Router-CA API specification — Prompt 2 implementation

**Status:** Router-CA lookup, signed directory bundles, enrollment RSA proof-of-possession, operator metadata, router revocation, and offline export are implemented on `feat/nls-v1`. The overall NLS product remains experimental and is not independently reviewed. CI evidence is the gate; this document does not imply that an unrun test passed.

## Transport and signer

The control channel is the custom NLS Control Record Protocol v1 over TCP 4790. It is not TLS and is not claimed TLS-interoperable. Routers pin the control identity Ed25519 public key out of band. Directory signatures use the pinned control identity key and the exact preimage:

```
ASCII("NLS-DIR-v1") || cbor2.dumps(payload, canonical=True)
```

The JSON control envelope carries `payload`, base64 `signer_public_key`, base64 `signature`, `encoding="canonical-cbor"`, and `domain="NLS-DIR-v1"`. The signature is over canonical CBOR, not JSON serialization. Routers reject signer mismatch, signature failure, malformed payload, nonce mismatch, expiry, and sequence rollback.

## Enrollment

`enroll` requires protocol_version, router_id, CSR PEM, request_id, nonce, timestamp, RSA-3072 encryption public key PEM, and RSA-PSS proof-of-possession. The proof uses SHA-256 and PSS with MAX_LENGTH salt over the request-bound challenge:

```
NLS-ENROLL-RSA-v1|router_id|request_id|nonce|hex(SHA256(RSA SubjectPublicKeyInfo DER))
```

The router's Ed25519 key is bound to its X.509 client certificate; the RSA key is bound to its directory record. If the administrator pre-registers an RSA SHA-256 fingerprint, enrollment must match it. WAN endpoints, gateway IPs and prefixes are accepted only through the local administrator CLI, never from an enrollment request. Reused request IDs or nonces are rejected.

## Router directory record (RDR)

Every signed RDR payload contains:
- `rdr_version` (currently `2`)
- `router_id`
- `ed25519_public_key` (standard base64 of raw 32-byte Ed25519 key)
- `ed25519_public_key_spki_der_b64` (base64 DER SubjectPublicKeyInfo deterministically derived from the raw key)
- `certificate_der_b64` (base64 of the complete CA-issued X.509 certificate DER)
- `originalIP` (canonical IPv6 address component of `wan_endpoints[0]`, excluding brackets and port)
- `original_ip_usable` (Boolean; false means the record MUST NOT be used for a handshake)
- `rsa_encryption_public_key` (PEM)
- `wan_endpoints`, `gateway_ips`, and `prefixes` (operator-configured arrays; `wan_endpoints` order is significant and covered by the RDR signature)
- `certificate_serial`
- `status`: `ACTIVE`, `REVOKED`, `DISABLED`, `EXPIRED`, or `UNKNOWN`
- monotonically increasing `record_seq`, `issued_at`, and `valid_until`

A `lookup` request contains `type="lookup"`, the authenticated caller's `router_id`, `target_router_id`, and a fresh `client_nonce`. The response echoes the nonce and includes a signed RDR with the same nonce inside the signed payload. Lookup validity is at most 30 seconds. Unknown routers receive a signed `UNKNOWN` record. Only a Router-CA-issued client certificate that is currently valid and active in the registry can access directory data. Requests are rate-limited to 120 lookup/directory-sync requests per authenticated router per rolling 60 seconds. Live lookup concurrency is capped at 4 per authenticated router and 64 globally; excess requests receive a rate-limited error. Unauthenticated and denied lookups disclose no directory record and are audited without secrets.

## Directory sync and heartbeat

`directory-sync` accepts `since_seq` and returns a signed bundle containing `directory_seq`, signed RDRs, revoked serials, policy, `issued_at`, and `expires_at`. The default bundle lifetime is 600 seconds and the server caps it at 600 seconds. The implementation returns a full snapshot even when `since_seq` is current; it does not yet optimize to deltas.

`sync` remains compatible and includes the signed bundle. `heartbeat` carries the current `directory_seq`, revocation state, policy, and signed bundle. A heartbeat cannot make an expired signature fresh. Routers reject stale bundles by default (`stale_grace_seconds=0`).

## Administrative CLI

- `nls-router-ca register-router ROUTER_ID --token-file FILE` preserves the protected token-file workflow and existing flags.
- Repeat `--rsa-public-key-sha256 SHA256`, `--wan-endpoint IP:PORT` (bracket IPv6 as `[IPv6]:PORT`), `--gateway-ip IP`, and `--prefix CIDR` to set administrator-owned directory metadata.
- `nls-router-ca update-router ROUTER_ID` updates operator-owned directory metadata. `nls-router-ca disable-router ROUTER_ID` disables a router without revoking its certificate; `enable-router` re-enables a disabled router but never reactivates a revoked router. `nls-router-ca revoke-router ROUTER_ID` revokes the router and all its active certificates.
- `nls-router-ca revoke-certificate SERIAL` remains available.
- `nls-router-ca export-directory --output FILE` writes an offline signed bundle for operator transfer.

Registration metadata is validated before persistence. The first endpoint MUST be bracketed IPv6 `[IPv6]:PORT`; port range is 1–65535, IPv6 zone identifiers are rejected, and unspecified, loopback, multicast, link-local, and IPv4-mapped addresses are rejected (ULA is allowed). Additional endpoints use the existing bracketed-IPv6 or IPv4 `IP:PORT` formats. The first endpoint determines `originalIP`; changing it changes `originalIP`. M1/M3 are sent to the peer's `originalIP` and the port parsed from its first endpoint. The `list-routers` command is read-only and reports router ID, endpoints, effective status, and original-IP usability. Directory changes increment the global `directory_seq` and the router's `record_seq`. SQLite migration uses `schema_version` and guarded, repeatable column additions; schema version 4 preserves legacy rows but marks records without a valid first endpoint or with a duplicate originalIP unusable. A unique registry index prevents two usable routers from claiming the same originalIP.

## Offline trust mode

The operator imports a bundle on the router with `sudo nlsxnetos router-ca import FILE`. Import verifies the pinned control identity, canonical-CBOR signature, record signatures, expiry, and monotonic directory sequence before an atomic cache write. Cache reads re-verify signatures; unsigned `/etc/nlsxnetos/router-ca.yaml` is not a trust source. Offline mode still fails closed on expired bundle freshness by default and is operationally degraded because it cannot observe revocation after export.

## Audit, failures and limitations

Lookup, denied lookup, router revocation, and certificate revocation are audited without credentials or private material. Statuses are computed from registry state and certificate validity. Directory records authorize identities and prefixes but must never install Linux routes; route creation remains an operator action.

The control protocol is a custom experimental protocol and requires independent cryptographic review. The directory bundle currently uses full snapshots rather than incremental deltas. Production hardening, soak tests, NAT behavior and independent review remain open until their own gates pass.

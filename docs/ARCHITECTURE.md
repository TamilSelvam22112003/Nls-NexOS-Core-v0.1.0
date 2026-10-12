# Architecture

## Repository roles

- **Nls-NexOS-Core** runs Router-CA control-plane services: registered router inventory, enrollment authorization, certificate issuance, revocation/status management, audit records, and a management API.
- **NlsxNetOS** runs on edge routers: local identity/key management, management reachability checks, CSR generation, certificate validation/storage, mTLS control client, and NLS session/policy consumer.

The Core repository must not implement a second packet-forwarding path. NLS data-plane packet protection and forwarding belong to NlsxNetOS.

## Required four-phase workflow

1. **L3 reachability:** verify the IPv6 route and use ping/traceroute as diagnostics. Then verify the service with HTTPS using the pre-provisioned, pinned Router-CA root. Ping alone does not authenticate the service.
2. **PKI enrollment:** generate the router private key locally, create a CSR, and submit it with a fresh request ID/nonce/timestamp plus an authorized bootstrap credential over validated TLS. The CA checks registration, authorization policy, CSR signature, key binding, freshness and replay state before signing a constrained certificate.
3. **Mutual NLS control channel:** establish TLS 1.3 mutual authentication with server and client certificate validation. The server must map the verified certificate identity to an active registry record and authorization policy. Use separate bootstrap and authenticated-control policy.
4. **Session/policy synchronization:** deliver versioned policy and authenticated revocation state over mTLS. NLS peers perform ephemeral X25519/HKDF key agreement bound to the authenticated handshake. Do not transmit raw symmetric data-plane keys.

## Address confidentiality

Ordinary IPv6 forwarding requires a usable outer destination address, so the outer IPv6 source/destination fields remain visible to transit IP routers. Sensitive original source/destination metadata and the original IP packet belong inside an NLS inner packet protected by authenticated encryption. Encrypting only a destination field in the ordinary outer IPv6 header is not compatible with normal routing.

## Trust boundaries

- Never transmit router private keys. Generate them locally and restrict filesystem access.
- A MAC or IP address is inventory data, not strong cryptographic identity proof. Identity should be bound to private-key possession and an approved enrollment credential or hardware attestation.
- The CA signing key must be separated from the database and strongly protected; production should use an offline or HSM-backed key where practical.
- Use parameterized database queries, uniqueness constraints, bounded inputs, anti-replay controls, strict certificate profiles, and audit events.
- Bootstrap credentials must be high entropy, protected, rate-limited, and rotated or invalidated after initial enrollment.

## Proposed source tree

```text
src/nls_nexos_core/
  api.py                 enrollment and health API
  auth.py                credential and client identity authorization
  ca.py                  CA-signed certificate issuance
  cli.py                 bootstrap, registration and server commands
  config.py              validated settings
  database.py            registry, replay, certificate and audit tables
  models.py              typed protocol models
  service.py             enrollment business logic
  tls.py                 TLS and certificate validation helpers
  errors.py              stable API errors
```

## Explicitly incomplete in this prototype

The initial repository scaffold does not yet provide a complete production HTTPS listener, post-enrollment mTLS enforcement, working policy/revocation endpoints, a router enrollment client integrated into NlsxNetOS, Debian packaging, or a successful end-to-end Ubuntu VM test. Do not expose it to untrusted networks until those gaps are closed and security-reviewed.
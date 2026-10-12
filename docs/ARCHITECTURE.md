# Architecture

## Repository roles

- **Nls-NexOS-Core** runs the Router-CA control-plane service: registered router inventory, certificate issuance, revocation foundations, audit trail, and mutual-TLS API.
- **NlsxNetOS** runs on the edge routers: local identity/key management, management reachability checks, CSR generation, certificate import, control-channel client, and NLS session/policy consumer.

The Core repository must not implement a second packet-forwarding path. NLS data-plane packet protection and forwarding belong to NlsxNetOS.

## Four phases

1. **Reachability** — validate configured CA endpoint reachability at L3. ICMP is diagnostic only; an application-layer health request determines service readiness.
2. **PKI enrollment** — generate the router private key locally, create a CSR, prove enrollment authorization, and submit it over a channel that already authenticates the configured CA.
3. **Mutual TLS control channel** — use TLS 1.3 with server certificate validation and client certificate validation. The client certificate is issued only after authorized enrollment; initial enrollment uses pinned CA trust plus a strong one-time/pre-shared enrollment credential.
4. **Session/policy synchronization** — after mTLS, fetch versioned policy and revocation state and establish ephemeral X25519/HKDF session keys in the NLS session protocol. Never send raw symmetric keys in the control response.

## Address confidentiality

IP source and destination fields in the outer IPv6 header are needed for normal routing and remain visible to network devices. Place private endpoint metadata and original inner IP packets inside authenticated encryption. Public-key encryption is not applied directly to IP header fields. Use TLS 1.3 for the management control channel.

## Proposed tree

```text
src/nls_nexos_core/
  api.py                 FastAPI endpoints
  auth.py                enrollment credential validation
  ca.py                  CA-signed certificate issuance
  cli.py                 command-line server runner
  config.py              validated service settings
  database.py            registry, replay and audit tables
  models.py              typed protocol models
  service.py             enrollment/business logic
  tls.py                 TLS setup and certificate validation helpers
  errors.py               stable API errors
```

## Trust boundaries

- The CA signing key is a high-value offline/separately protected secret, never a database field or API response.
- Enrollment token file permissions should be root-only (0600) and secrets should be rotated after bootstrapping.
- Router ID + IP + MAC do not authenticate a device. The proof uses the CSR key, an approved enrollment token or hardware attestation, registry policy, freshness and CA trust.
- Database data is untrusted input. Use parameterized queries, uniqueness constraints, and strict input validation.

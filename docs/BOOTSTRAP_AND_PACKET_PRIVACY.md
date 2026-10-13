# Router-CA bootstrap contract and NLS key roles

## Boot-time Router-CA workflow

1. The router is provisioned out-of-band with the CA IPv6 endpoint, pinned Router-CA Ed25519 NLS-control identity public key, CA root certificate, a global bootstrap token, and a router-specific enrollment token. Never learn a trust key from the same unauthenticated network path it is meant to secure.
2. The NlsxNetOS control agent waits for network-online, connects to the configured TCP endpoint, and retries on failure. TCP reachability is not authentication.
3. NLS Control v1 authenticates the CA against the pinned Ed25519 identity. A fresh X25519 exchange and transcript-bound HKDF-SHA-256 derive directional AES-256-GCM keys. Enrollment tokens, CSR, and enrollment responses travel inside encrypted NLS control records.
4. Router-CA checks both credentials, registered-router state, CSR proof-of-possession, request timestamp/nonce/replay state, and policy before issuing an identity certificate.
5. The router reconnects using the certificate. The CA validates certificate issuer, validity, router identity, registry state, and revocation state before policy/heartbeat operations.
6. Data-plane registration is separate from CA control enrollment: the destination router's endpoint, identity public key, prefix, and RSA encryption public key must be distributed in authenticated Router-CA policy/registry state before encrypted user traffic can be sent.

## Do not use the CA RSA key as the data-plane recipient key

The Router-CA RSA signing key signs CA-issued certificates. Its public key verifies signatures; it is not the router's data-plane encryption key. NLS packet confidentiality is end-to-end between NLS routers: NlsxNetOS encrypts the complete original IP packet (including original source address and payload) with a fresh AES-256-GCM key, then wraps that data key with the destination router's registered RSA-OAEP-SHA-256 encryption public key. Only the destination router can decrypt it.

Encrypting every payload to the CA RSA public key would require the CA to decrypt every packet and would make the CA a central plaintext observer. That conflicts with the intended router-to-router data-plane confidentiality. The CA public key used for control bootstrap is the pinned Ed25519 NLS-control identity key, while the CA certificate's RSA key is used for certificate-signature verification; these are separate roles.

## Acceptance criteria

- CA endpoint is reachable after boot and the service retries if not.
- A TCP listener is confirmed to be the Router-CA process.
- Router enrollment succeeds through NLS Control v1, and the issued certificate is validated locally against the pre-provisioned root.
- Subsequent certificate-authenticated sync and heartbeat succeed.
- Router policy contains a valid destination endpoint/prefix/identity key and destination RSA encryption public key.
- NLS TUN/routes are active only when valid destination configuration exists.
- Cross-router packet tests confirm the original source IP and payload are not visible in the encapsulation header and the packet is only decryptable with the intended destination router private key.

This is an experimental custom protocol, not a TLS implementation with independent security review. Do not deploy it on production/critical networks before review.

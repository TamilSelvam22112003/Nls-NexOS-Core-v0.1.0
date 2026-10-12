# Architecture

## Repository roles

- **Nls-NexOS-Core** is intended to provide Router-CA enrollment, router authorization, CA-signed identity certificates, revocation state, audit and policy distribution.
- **NlsxNetOS** runs at edge routers and owns local key generation, Layer-3 diagnostics, NLS handshake/data-plane encapsulation, certificate storage/validation, and the NLS control client.
- The Router-CA is a control-plane service, not a transit router. Forwarding remains in NlsxNetOS/Linux routing.

## Required four phases

1. **Layer-3 reachability:** verify the management route to the Router-CA endpoint and use ping/traceroute as diagnostics. ICMP reachability does not authenticate the Router-CA.
2. **PKI enrollment:** generate the router key locally and sign a CSR. Submit the CSR, router ID, fresh request ID/nonce/timestamp, a server bootstrap credential and a router-specific enrollment token inside an authenticated NLS enrollment exchange. The CA validates registry status, both credential gates, CSR signature/key binding, freshness and replay state before issuing a constrained certificate.
3. **Mutual NLS control channel:** establish a persistent, mutually authenticated NLS control session. The handshake must bind the router and CA identities, use signed ephemeral key agreement, derive session keys with HKDF, and reject replayed or stale messages. The Core repository does not yet implement this listener or integrate the NLS handshake.
4. **Policy/session sync:** distribute versioned policy and authenticated revocation state over the NLS control session. Data-plane peers derive traffic keys locally; the CA must not send raw symmetric keys or receive router private keys.

## NLS and address confidentiality

Ordinary IP forwarding requires a routable outer destination address; the outer IPv6 source/destination fields remain visible to transit IP routers. Private original endpoints and the inner IP packet belong in authenticated-encrypted NLS encapsulation. Encrypting only the ordinary outer destination field is incompatible with standard IP forwarding.

## Trust boundaries

- Generate and store router private keys locally. Never transmit them.
- IP/MAC addresses are inventory attributes, not cryptographic identity proofs.
- Pin the Router-CA trust anchor out-of-band before first enrollment; authenticate the CA before sending bootstrap credentials.
- Keep the CA signing key separate from the registry and protect it with offline/HSM-backed custody where practical.
- Use distinct bootstrap and router-specific enrollment credentials, parameterized database queries, unique request IDs, nonce/freshness checks, bounded input, strict certificate profiles and audit events.

## Current code boundary

The Core repository contains certificate/registry business logic and a developer-only FastAPI adapter. It does **not** implement an NLS network listener, Router-CA NLS handshake, or live NLS enrollment. The adapter is not a protocol replacement and must not be exposed as the production transport.

## Explicitly incomplete

NLS control framing/listener, router-side enrollment agent, certificate import/validation on NlsxNetOS, control-session policy/revocation messaging, renewal/rotation, Debian packaging and end-to-end multi-VM validation remain incomplete.

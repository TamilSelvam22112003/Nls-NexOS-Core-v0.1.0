# Boot Enrollment Flow

## 1. Layer-3 reachability

Provision the Router-CA management IPv6 address and trust anchor out-of-band. Confirm there is a route before starting NLS enrollment. Example diagnostics (replace the documentation address and interface):

```bash
ip -6 route get 2001:db8::10
ping -6 -I <management-interface> -c 3 2001:db8::10
tracepath6 2001:db8::10
```

ICMP can be filtered. A future NLS `NLS_CA_PROBE` exchange must authenticate the CA identity; that probe is not implemented in the current Core scaffold.

## 2. Cryptographic identity and enrollment

1. Generate the router private key locally with restrictive permissions.
2. Create a CSR and sign it with the local private key; never transmit the private key.
3. Send an `NLS_ENROLL_REQUEST` inside an authenticated-encrypted NLS bootstrap exchange to the configured Router-CA endpoint.
4. Include a fresh request ID, nonce, timestamp, router identity, signed CSR, server bootstrap credential and per-router enrollment token.
5. The CA verifies the CSR signature, router allow-list/status, both credential gates, expected public-key binding, freshness and replay state.
6. The CA returns a constrained signed router identity certificate and CA chain. The router validates issuer, signature, validity, expected identity and purpose, then atomically installs the certificate.

The NLS bootstrap/control listener and the router-side enrollment agent required by these steps are **not yet implemented** in the two-repository workflow.

## 3. Mutual NLS control channel

After certificate installation, establish the persistent NLS control session. It must authenticate both peer identities, bind them into the handshake transcript, perform ephemeral key agreement, derive keys with HKDF, and enforce sequence/replay windows. A standard TLS channel is not a substitute for the requested NLS protocol.

## 4. Policy, revocation and data-plane keys

Once the mutual NLS control session is established, synchronize versioned policy and authenticated revocation state. Routers derive data-plane session keys locally from authenticated ephemeral key agreement; never transmit raw symmetric keys. Expose states such as `NO_ROUTE`, `CA_UNREACHABLE`, `ENROLLMENT_REQUIRED`, `CERTIFICATE_INVALID`, `NLS_CONTROL_READY`, `POLICY_SYNCED` and `NLS_SESSION_READY`.

Outer IP addresses required for normal routing remain visible. Sensitive original endpoints and packet payload belong inside NLS authenticated encryption.

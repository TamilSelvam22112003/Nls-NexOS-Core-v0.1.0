# Boot Enrollment Flow

## 1. L3 reachability

The edge agent loads a preconfigured CA address and CA root certificate, performs a route/reachability diagnostic, then checks the HTTPS health endpoint. Do not assume ping proves that the CA application is available or authentic.

Suggested diagnostics on Ubuntu:

```bash
ip -6 route get 2001:db8::10
ping -6 -c 3 2001:db8::10
tracepath6 2001:db8::10
curl --cacert /etc/nlsxnetos/router-ca/ca-root.crt https://[2001:db8::10]:8443/health
```

Replace documentation addresses with configured values. ICMP may be filtered; that should not be treated as proof that the TCP/TLS service is down.

## 2. PKI enrollment

1. Generate a device private key locally and set file permissions to 0600.
2. Generate a CSR with router ID in a controlled subject/SAN field.
3. Connect using the pinned Router-CA root certificate.
4. Send router ID, CSR, nonce/request ID and enrollment token over HTTPS.
5. CA checks token, registered identity and CSR signature; MAC/IP values are supporting inventory metadata only.
6. CA signs a leaf certificate with restricted Key Usage and Extended Key Usage.
7. Client validates the signed certificate against the pinned CA root and expected identity, then writes it atomically.

Never transmit the private key. A certificate response is signed by the CA; the HTTP/TLS channel provides confidentiality and integrity.

## 3. Mutual TLS

After certificate import, the agent reconnects using TLS 1.3 with client-certificate authentication. The CA service validates the client chain, revocation/expiry, identity and authorization on every new control channel. In production, client certificates should have an explicit clientAuth EKU and a stable router ID SAN.

## 4. Session and policy sync

After mutual authentication, the agent fetches versioned policy and current revocation information. NLS session establishment performs ephemeral X25519, transcript-bound authentication and HKDF-SHA-256 key derivation. Data-plane symmetric keys are derived locally, not sent in plaintext by the CA. Use AES-256-GCM with unique nonces and sequence/replay protection.

## 5. Operational state

The agent should report distinct statuses: `UNCONFIGURED`, `NO_ROUTE`, `CA_UNREACHABLE`, `ENROLLMENT_REQUIRED`, `ENROLLMENT_DENIED`, `CERTIFICATE_INVALID`, `MTLS_READY`, `POLICY_SYNCED`, `NLS_SESSION_READY`.

Failure must fail closed for NLS traffic: retain routing/management recovery path, but do not silently accept an unverified CA or untrusted peer.

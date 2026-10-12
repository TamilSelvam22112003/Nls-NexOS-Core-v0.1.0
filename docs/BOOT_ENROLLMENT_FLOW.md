# Boot Enrollment Flow

1. **Reachability:** verify the IPv6 route; ping/traceroute are diagnostic only. Make an HTTPS health request using the pre-provisioned Router-CA root certificate.
2. **Enrollment:** generate the router private key locally, create and sign a CSR, then send router ID, CSR, fresh request ID/nonce/timestamp and an authorized bootstrap credential over validated TLS. The CA checks registry authorization, CSR signature, freshness and replay state before signing a short-lived router identity certificate.
3. **Mutual control channel:** reconnect using TLS 1.3 mutual authentication. Validate server and client certificate chains, identity, expiry, EKU, revocation status and authorization.
4. **Policy and session sync:** fetch signed/versioned security policy and revocation state. NLS peers derive ephemeral session keys with X25519 and HKDF; do not transmit raw symmetric keys.

Example diagnostics (replace the documentation address):

```bash
ip -6 route get 2001:db8::10
ping -6 -c 3 2001:db8::10
tracepath6 2001:db8::10
curl --cacert /etc/nlsxnetos/router-ca/ca-root.crt 'https://[2001:db8::10]:8443/health'
```

Outer IPv6 source/destination addresses required for ordinary forwarding remain visible. Put private original endpoints and payload inside the authenticated-encrypted NLS inner packet.
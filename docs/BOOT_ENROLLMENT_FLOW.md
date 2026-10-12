# Boot and Enrollment Flow

## 1. L3 reachability

Provision the Router-CA root certificate, pinned Ed25519 control public key, global bootstrap credential and router-specific token through a trusted out-of-band channel. Configure a real routable IPv6 address and management route.

```bash
ip -6 route get 2001:db8::10
ping -6 -c 3 2001:db8::10
tracepath6 2001:db8::10
```

Replace the documentation address. Ping/traceroute demonstrate reachability only; the pinned NLS handshake authenticates the Router-CA. NLS control defaults to TCP 4790; NLS data-plane UDP defaults to 4789.

## 2. Router-CA initialization

Install dependencies, configure `config/router-ca.example.yaml`, and run:

```bash
nls-router-ca --config /etc/nls-nexos-core/router-ca.yaml init
```

The CA reports the root certificate, root fingerprint, NLS control public-key pin and creates a global bootstrap token. Protect the CA signing key and token. Register each router using its high-entropy router-specific token file:

```bash
nls-router-ca --config /etc/nls-nexos-core/router-ca.yaml register-router router-001 --token-file /secure/path/router-001.token
nls-router-ca --config /etc/nls-nexos-core/router-ca.yaml serve
```

## 3. Router enrollment

Configure `/etc/nlsxnetos/router-ca-client.yaml` with the real endpoint, matching `server_id`, exact base64 public key printed by `init`, router ID and trust/certificate/token paths. Replace the example placeholder key. Install the CA root and both token files using owner-only permissions.

```bash
sudo nlsxnetos router-ca-client enroll --config /etc/nlsxnetos/router-ca-client.yaml
```

The router generates/retains its private key locally, signs a CSR, sends it only inside encrypted NLS records, validates the returned CA root against its pre-provisioned trust anchor, and imports the leaf certificate atomically after checking issuer, validity, purpose, identity and local-key match.

## 4. Persistent mutual NLS channel

```bash
sudo systemctl enable --now nls-ca-client.service
sudo ss -tnp | grep ':4790'
sudo journalctl -u nls-ca-client.service -f
```

The daemon reconnects using the issued identity certificate and synchronizes policy/revocation data over the persistent NLS control protocol. A successful CA enrollment does not by itself prove the NLS user-data plane has a working peer route/TUN path.

## 5. Verify installed state

```bash
sudo nlsxnetos router-ca-client status --config /etc/nlsxnetos/router-ca-client.yaml
sudo cat /var/lib/nlsxnetos/security/nls-policy.json
sudo cat /var/lib/nlsxnetos/security/nls-revocations.json
sudo ls -l /var/lib/nlsxnetos/identity/router.crt
```

Treat the control protocol as an experimental custom protocol, not TLS; independent cryptographic review is required before production.
# Boot and Enrollment Flow

## 1. L3 reachability

Copy the Router-CA root certificate, pinned Ed25519 NLS control public key, and enrollment credentials to the router through a trusted provisioning channel. Configure the correct CA management address and route.

```bash
ip -6 route get 2001:db8::10
ping -6 -c 3 2001:db8::10
tracepath6 2001:db8::10
```

Replace the documentation address with the actual server address. These commands test reachability; the NLS Control v1 handshake authenticates the peer. The Router-CA listener is TCP port 4790 by default; the router-to-router NLS data plane uses UDP port 4789.

## 2. Router-CA initialization

On the CA host, install dependencies and the Core package/source environment, copy `config/router-ca.example.yaml` to the configured server path, and initialize keys:

```bash
nls-router-ca --config /etc/nls-nexos-core/router-ca.yaml init
```

The command reports the root certificate, root SHA-256 fingerprint, and Ed25519 NLS control public key. Keep the CA signing key and bootstrap token private; distribute only the root certificate, control public-key pin and authorized per-router enrollment credential to the intended router.

Register the router using a protected token file:

```bash
nls-router-ca --config /etc/nls-nexos-core/router-ca.yaml register-router router-001 --token-file /secure/path/router-001.token
nls-router-ca --config /etc/nls-nexos-core/router-ca.yaml serve
```

The token file must contain at least 32 random characters. The global bootstrap token comes from `/etc/nls-nexos-core/enrollment-token`.

## 3. Router configuration and enrollment

1. Install the CA root certificate as `/etc/nlsxnetos/router-ca/ca-root.crt`.
2. Copy the global bootstrap token to `/etc/nlsxnetos/router-ca/bootstrap.token` and this router’s registered token to `/etc/nlsxnetos/router-ca/router.token`. Set both token files to owner `nlsxnetos` and mode `0600`.
3. Edit `/etc/nlsxnetos/router-ca-client.yaml`: set the correct `endpoint`, `server_id`, base64 `server_public_key` printed by the CA `init` command, router ID and paths. Do not leave the placeholder public key.
4. Enroll the router; its Ed25519 private key remains local.

```bash
sudo nlsxnetos router-ca-client enroll --config /etc/nlsxnetos/router-ca-client.yaml
```

The router validates that the returned root matches its pre-provisioned root certificate, verifies the issued leaf signature/validity/EKU/router identity, checks the leaf public key matches its local private key, then installs the certificate atomically.

## 4. Persistent mutual NLS control channel

Enable the client only after provisioning all fields and files:

```bash
sudo systemctl enable --now nls-ca-client.service
sudo ss -tnp | grep ':4790'
sudo journalctl -u nls-ca-client.service -f
```

The client reconnects with the issued certificate, validates policy and revocation responses, and sends periodic encrypted heartbeats. Router-CA validates each certificate against the trust root and active registry row. Invalid, expired or revoked certificates are rejected.

## 5. Verification

```bash
sudo nlsxnetos router-ca-client status --config /etc/nlsxnetos/router-ca-client.yaml
sudo cat /var/lib/nlsxnetos/security/nls-policy.json
sudo cat /var/lib/nlsxnetos/security/nls-revocations.json
sudo ls -l /var/lib/nlsxnetos/identity/router.crt
```

A successful enrollment alone does not mean the NLS user-data plane is running. The router's own NLS data-plane service and its peer/route configuration must also be enabled and validated.

# NLS Bootstrap Privacy Envelope v1 (experimental)

## Wire intent

Before a router has a session key, it sends a bootstrap registration to the
pre-provisioned Router-CA endpoint. The visible network destination is the CA
endpoint. The original router/source address, router identity, CSR, and
enrollment metadata are inside the encrypted payload. The request is encrypted
to the CA's **pre-pinned RSA public key**.

The CA decrypts and validates the request, then returns an acknowledgement
encrypted to the enrolling router's registered RSA public key. The router must
have provisioned that public key/identity binding out-of-band or establish it
through an authenticated enrollment mechanism; never trust a key merely
because it appears in the request.

## Cryptographic construction

- Generate a fresh random 256-bit AES key per envelope.
- Encrypt canonical JSON payload using AES-256-GCM with a fresh 96-bit nonce.
- Wrap only the AES key using RSA-OAEP with SHA-256 and label
  `NLS-BOOTSTRAP-v1`.
- Authenticate version, message type, and visible destination as GCM AAD.
- Reject wrong destination/type, malformed envelope, invalid GCM tag, and
  unsupported versions.
- Source IP and other private metadata must never be copied into cleartext
  outer headers. The visible destination is retained for ordinary routing.

RSA must not encrypt the complete payload directly: RSA-OAEP has a strict
plaintext-size limit. This hybrid envelope avoids that limit.

## Flow

1. Router boots with CA endpoint and CA RSA public key provisioned out-of-band.
2. Router checks IPv6 reachability to the CA endpoint.
3. Router encrypts registration payload (including source IP) to CA public key.
4. CA decrypts, authenticates, authorizes and processes the registration.
5. CA encrypts acknowledgement/policy response to the router's RSA public key.
6. Router decrypts and validates the acknowledgement, then establishes the
   authenticated NLS control session and proceeds to policy sync.
7. For router-to-router data traffic, encrypt the inner original IP packet to
   the **destination router's** key/session, not the CA's key. The CA is not
   automatically the data-plane recipient.

## Status / integration boundary

The accompanying `bootstrap_envelope.py` implements an experimental
hybrid-encryption primitive with tests. It is not yet wired into the TCP
listener, router enrollment client, packet dispatcher, or NLS TUN data plane.
Do not describe the complete workflow as implemented until those integration
points and cross-repository tests are complete. This custom protocol needs
independent security review before production use.

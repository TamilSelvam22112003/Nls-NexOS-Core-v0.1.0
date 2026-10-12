# NLS Control Record Protocol v1: Control Operations

This is a framed NLS control protocol over TCP, not an HTTP REST API. The default listen port is 4790. All application operations after the signed handshake are JSON objects carried in AES-256-GCM-protected records with strict directional sequence numbers.

## Handshake

- `CLIENT_HELLO`: router ID, Ed25519 public key, ephemeral X25519 public key, fresh nonce, timestamp, optional Router-CA-issued certificate, and Ed25519 signature.
- `SERVER_HELLO`: pinned CA control identity ID/public key, ephemeral X25519 public key, fresh nonce, timestamp, client-hello transcript hash, client-authentication state, and Ed25519 signature.
- Both sides derive directional record keys from ephemeral X25519 with HKDF-SHA-256 bound to the complete signed transcript and verify encrypted Finished records before sending control requests.

## Application messages

- `health`: returns the service ID and protocol version. It does not grant enrollment or control privileges.
- `enroll`: contains an enrollment request (router ID, signed CSR, unique request ID, nonce, timestamp, optional claimed IPv6/MAC), global bootstrap token and router-specific token. Both tokens travel inside encrypted records.
- `sync`: requires a current Router-CA-issued client certificate and returns versioned policy and revoked-certificate state.
- `heartbeat`: requires a current certificate and returns server time, policy and revocation state on the persistent channel.
- `status`: requires a current certificate and returns router ID, certificate serial, policy and revocation state.
- `close`: closes the record channel.

## Enrollment response

The successful `enrollment-result` contains the signed router identity certificate, CA root certificate, serial, validity, policy and revocation bundle. The client must compare the returned root certificate against its pre-provisioned trust anchor and validate the certificate before installing it. Private keys and raw symmetric session keys are never returned.

## Revocation

`nls-router-ca revoke-certificate SERIAL` marks an active certificate revoked. The next new NLS control session with that certificate is refused; connected routers receive revocation state during heartbeats. Production deployments still need a defined revocation refresh/expiry policy and operational CA-key protection.

## Compatibility and security status

This is an experimental custom protocol; do not claim wire compatibility with a standard protocol. Its cryptographic profile and implementation require independent review before production use.

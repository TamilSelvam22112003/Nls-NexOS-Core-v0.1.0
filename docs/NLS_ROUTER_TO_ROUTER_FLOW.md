# Router-to-router NLS flow and temporary vIP

## Required sequence

1. Router boots with the Router-CA trust anchor/public key and authorized CA endpoint provisioned through a trusted installation process.
2. Router checks endpoint reachability. Reachability alone does not establish trust.
3. Router opens the NLS control protocol, validates the CA identity against the pinned key/certificate, and completes authenticated enrollment. Registration and acknowledgements must be protected by the NLS control channel or the hybrid bootstrap envelope.
4. When a LAN packet arrives, the source router resolves the destination endpoint to an authorized router identity and checks whether a valid peer session exists.
5. If a session exists, encapsulate and encrypt the inner IP packet with the session's directional AEAD key. Do not RSA-encrypt the entire packet. If no session exists, queue/drop according to bounded policy while the router performs authenticated peer discovery and a mutually authenticated handshake.
6. The handshake must validate both routers against CA-issued credentials/registry state, bind identities and ephemeral X25519 keys to a transcript, derive directional keys with HKDF-SHA-256, and confirm possession before data forwarding.
7. A temporary vIP can be assigned as an overlay identifier. It must not be calculated as a plain SHA hash of the source IP; use keyed derivation and a fresh session nonce. The vIP is not globally routable and must not be placed in the ordinary WAN source IP header unless the underlay has an explicit route for that overlay.
8. The data packet uses a normal routable outer IP header (WAN source/destination), an NLS header/session ID/sequence, and AEAD-protected inner IP packet. The inner source and destination IPs remain encrypted. Intermediate routers see outer endpoint addresses and traffic metadata.
9. The destination router verifies session, sequence/replay window and AEAD tag, decrypts, checks policy, and forwards to the LAN. Reverse traffic uses the reverse directional key/session.
10. On failure, identity mismatch, revocation, replay, expiry, or authentication failure: fail closed; do not fall back to plaintext. Temporarily block/rate-limit the offending peer with an audit record, but do not automatically permanently block an address solely on one malformed packet.

## Temporary vIP primitive

`vip.py` derives an IPv6 ULA address in `fd42:4e4c:5300::/48` using HMAC-SHA-256 over router IDs and a fresh session nonce, keyed by at least 256 bits of secret material. Only 80 bits of the digest are used because the prefix consumes 48 bits of the 128-bit IPv6 address. This is an overlay identifier; it is not globally routable. It requires collision detection/registration in the session table and must expire with the session.

## Integration status

This design note and vIP helper do not by themselves complete the protocol. Integration remains required in the actual router handshake, CA registry and discovery response, packet encapsulation/de-encapsulation, TUN/forwarding path, session/replay store, and VM cross-repository tests. Do not claim the workflow is complete until these pass.

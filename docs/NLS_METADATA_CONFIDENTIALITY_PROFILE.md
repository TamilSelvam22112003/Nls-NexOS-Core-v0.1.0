# NLS Metadata Confidentiality / Relay Envelope Profile

**Status: DRAFT DESIGN — NOT A RELEASED OR IMPLEMENTED PROTOCOL.** This document is a coordination artifact for the Core and NetOS repositories. It must not be used to claim current router releases provide multi-hop metadata confidentiality. The final wire format and state machine require cross-repository review and a versioned protocol decision.

Companion implementation/design:
- NetOS: https://github.com/TamilSelvam22112003/NlsxNetOS-v0.1.0/pull/68
- NetOS implementation tracker: https://github.com/TamilSelvam22112003/NlsxNetOS-v0.1.0/issues/67
- Core tracker: https://github.com/TamilSelvam22112003/Nls-NexOS-Core-v0.1.0/issues/15

## Implementation alignment note (2026-10-27)

The companion NetOS draft branch now contains a feature-gated destination-preserving NLR1/NLE2 data path and an `nls-endpoint-agent` receive/decrypt/inject plus response-encapsulation loop. This is implementation progress, not protocol acceptance.

- NLR1 protects the prior-hop source locator and opaque inner NLE2 envelope with a direction-specific authenticated hop session key.
- NLE2 encrypts the complete original IP packet to the endpoint's registered RSA encryption key and signs the envelope with the origin router/endpoint Ed25519 identity.
- A destination router forwards a server-owned NLE2 envelope without decrypting it; the server endpoint agent verifies the origin against active Router-CA entries, decrypts it, and injects the recovered packet into its TUN interface.
- For the reverse direction, the endpoint agent routes configured remote prefixes through its TUN, encrypts response packets to the destination router's registered key, and sends NLE2 to the local router for NLR1 forwarding.
- The current draft uses per-packet RSA-OAEP wrapping rather than a negotiated forward-secret endpoint session. It does not meet the final authenticated key-agreement requirement yet and must not be represented as a final protocol.
- The exact-head CI and multi-router WAN packet-capture gates have not yet passed; IPv6 outer fragmentation/reassembly must be tested.

The implementation is feature-gated and does not change the default/released NLE1 data path. Core wire-format/state-machine approval, revocation behavior, replay lifetime, return-path behavior, and a versioned interoperability contract remain required before release.

## 1. Security properties and limits

The profile aims to prevent a passive observer on an untrusted relay-to-relay Internet link from recovering original client/server IP addresses, inner transport ports, endpoint certificates, stable endpoint identifiers, prior-hop locator history, or application payload from cleartext IP/UDP/NLS framing.

It does not protect against a compromised endpoint or a relay that is authorized to decrypt its own hop layer. It does not inherently conceal timing, direction, packet lengths, burst structure, or total traffic volume.

## 2. Outer routing locators

The actual IPv6 source and destination fields remain visible because IP forwarding requires a routable destination. Each hop MUST use:
- outer source: current relay's routable WAN locator;
- outer destination: final server IP address in destination-preserving mode;
- UDP ports: that hop's configured NLS transport ports;
- minimal clear framing: protocol version, opaque hop-scoped token, sequence, nonce and length.

An encrypted address cannot replace the actual IPv6 destination field. Original endpoint identities and prior-hop locators MUST remain inside authenticated encrypted envelopes.

## 3. Draft NLR1 per-hop envelope layout

All integer fields are unsigned, network byte order. The outer IPv6/UDP headers are not part of this NLR1 byte string.

| Offset | Size | Field | Cleartext? |
|---|---:|---|---|
| 0 | 4 | Magic `NLR1` | Yes |
| 4 | 1 | Version = 1 | Yes |
| 5 | 1 | Flags = 0 (reserved; reject nonzero) | Yes |
| 6 | 16 | Opaque hop-scoped token | Yes |
| 22 | 8 | Sequence number | Yes |
| 30 | 12 | AES-GCM nonce | Yes |
| 42 | 4 | Ciphertext length including 16-byte tag | Yes |
| 46 | variable | AES-256-GCM ciphertext and tag | No |

The header bytes from offset 0 through 45 are AEAD associated data. A 32-byte key MUST be unique to a hop/session/direction. Nonces MUST never repeat under the same key. Sequence numbers MUST be monotonic per sending direction and checked against a replay window at the receiver. The opaque token selects hop state and MUST be scoped/rotated to limit cross-session linkability; it is not an identity credential.

The authenticated plaintext is:
- 1-byte address family marker (4 or 6);
- 16-byte normalized next-hop address slot (IPv4 uses four address bytes followed by twelve zero bytes);
- 2-byte next-hop UDP port (1..65535);
- 4-byte inner-envelope length;
- exact inner-envelope bytes.

The authenticated next-hop locator may be carried inside ciphertext for path validation, but it does not become the outer IPv6 destination in destination-preserving mode. The current relay MUST forward only after authentication, locator-policy validation, and replay checks succeed.

The implementation must cap the full UDP payload, including NLR1 header, inner locator fields, and AEAD tag, to a safe path-MTU budget. Oversized packets must be rejected or handled by a separately specified fragmentation/PMTU strategy; silent truncation is forbidden.

## 4. Layer processing

The sender constructs an endpoint-protected inner packet and wraps it in destination delivery and per-hop relay layers. Each relay:
1. verifies its session/token and replay window;
2. authenticates/decrypts exactly one layer;
3. extracts the authenticated next-hop locator and opaque inner envelope;
4. forwards with its own WAN locator as outer source while preserving the final server IP as outer destination;
5. never attempts to decrypt the endpoint envelope.

A relay key MUST NOT be reused as an endpoint key or another hop's key. A destination router's public key does not by itself establish that the application server can decrypt data.

## 5. End-to-end endpoint layer

The endpoint envelope requires authenticated endpoint key agreement (proposed: ephemeral X25519, transcript-bound HKDF-SHA-256, directional AEAD traffic keys). It contains the original IP packet and remains opaque to relays. The destination router cannot route using an encrypted original destination IP; a server-side endpoint agent or another explicitly specified delivery mechanism must receive the opaque envelope and recover the packet only with the endpoint key.

If encryption terminates at the destination router and the router injects plaintext into the server LAN, the property is router-to-router confidentiality, not client-to-server end-to-end confidentiality. Documentation and CLI status MUST distinguish these properties.

## 6. Fail-closed and compatibility rules

- NLR1 is a proposed new data-plane format; it MUST NOT be silently substituted for existing NLE1 or existing handshake formats.
- If the operator requests the metadata-confidentiality profile, missing relays, endpoint trust, keys, route state, or server endpoint agent MUST prevent activation. No silent downgrade to legacy single-hop mode.
- Unknown versions, malformed lengths, invalid address encodings, authentication failures, replayed packets, expired/revoked keys, and locator-policy failures MUST be dropped.
- Key rotation, overlap, endpoint changes, daemon restart, revocation propagation, and replay-window recovery require normative state-machine rules before production deployment.

## 7. Acceptance evidence

Core and NetOS acceptance must include:
- cross-repository wire-format test vectors;
- three or more relays and a separate server endpoint agent;
- round-trip, wrong-key, tamper, replay, wrong source port, wrong local destination/interface, endpoint-change and downgrade tests;
- clean-install and configuration tests on supported Ubuntu releases;
- actual, decodable WAN PCAPs from every untrusted hop with expected packet counts;
- assertions that original IPs, inner ports, certificates, stable identifiers and unique payload canaries are absent from cleartext headers/framing;
- proof that relays without endpoint keys cannot decrypt endpoint content;
- MTU, fragmentation, ICMPv6 Packet Too Big, restart and bidirectional traffic tests.

A capture containing no decodable NLS packets is inconclusive and MUST NOT pass. AES-GCM unit tests alone do not prove metadata confidentiality.


## 10. Normative source-address handling clarification

The NLS source-address requirement is **hop-scoped source-metadata confidentiality**: the relay packages the preceding/current relay's source-locator metadata inside an authenticated encrypted hop envelope addressed to the next authorized relay. The next relay decrypts that envelope with the hop/session key established for it (the next relay's public key may authenticate or establish that session; do not use unauthenticated raw public-key encryption as a substitute for an AEAD session), validates the locator and policy, and uses its own routable WAN locator as the source of the newly emitted outer IPv6 packet when forwarding onward. The forwarding relay may retain the authenticated prior-hop locator only for the scoped operation that requires it; it must not expose it in clear NLS framing or logs.

**Wire-level limitation:** this encrypted source-locator field is metadata carried inside the envelope; it does not encrypt or replace the actual outer IPv6 Source Address field. The actual outer IPv6 source remains the current relay's routable WAN address and is visible to the next relay and to on-path observers. Ordinary Internet IPv6 forwarding cannot deliver a packet to a next hop if the routable outer destination is encrypted in place. If the requirement is to hide even the current relay's actual WAN source address from passive Internet observers, that requires an additional outer tunnel/cover endpoint; it cannot be achieved by encrypting the source field while keeping the same ordinary IPv6 packet routable.

The normative inner hop plaintext must therefore include an authenticated previous_hop_source_locator (address family + normalized address) in addition to the encrypted next_hop_locator and opaque inner envelope. The Core and NetOS codecs and cross-repository test vectors must agree on this field before the profile is considered implementable. Tests must assert that this locator appears only inside ciphertext, that the receiving relay recovers it only with its authorized hop key, and that the forwarded outer source is the forwarding relay's configured WAN locator.


## 11. Normative destination-preserving forwarding mode (required)

This section supersedes earlier draft statements that the outer IPv6 destination is the next relay's WAN locator.

For each NLS data packet across the configured relay path:

- Outer IPv6 source = WAN locator of the relay that most recently emitted the packet.
- Outer IPv6 destination = final server IP, unchanged across intermediate relay hops.
- The encrypted hop envelope carries the authenticated previous-hop source locator, hop/session context, and opaque inner envelope. A next-hop locator can be carried encrypted for policy validation but MUST NOT replace the outer destination.
- Each receiving relay decrypts only its authorized hop layer, validates the previous-hop locator against authenticated peer/session state and the configured path, then emits the protected packet with its own WAN source address and the same final-server destination.
- Original client/server addresses, protected inner transport metadata, and application payload remain encrypted for their intended recipients.

Because the outer destination is not local to an intermediate relay, the implementation MUST provide a tested inline delivery mechanism to the NLS process (for example, narrowly scoped nftables TPROXY plus policy routing and transparent sockets, or a reviewed equivalent). A conventional UDP socket bound only to a local address cannot receive a datagram addressed to the final server IP. The mechanism must preserve the original destination, prevent interception loops, define which NLS packet classes are intercepted, validate ingress interface and peer source port, and fail closed if prerequisites are absent. No silent fallback to next-relay-as-destination mode is allowed.

The operator must provision a deterministic forwarding path through the selected relays. OSPF may establish reachability and choose the next L3 hop, but it does not decrypt NLS envelopes or rewrite data-packet source addresses. NLS forwarding code performs source rewriting. The reverse path must be explicitly defined and tested because the server ordinarily sees the final relay's outer source address.

Acceptance requires a >=3-relay IPv6 lab plus server-side router/endpoint; WAN captures proving the outer destination stays equal to the server IP while outer source changes at every relay; per-hop decryption authorization; no original endpoint/payload canaries in cleartext framing; bidirectional return traffic; stable OSPFv3/RIB/FIB; and fail-closed behavior when TPROXY/policy routing or peer trust is missing. Documentation alone does not mean the current runtime implements this mode.

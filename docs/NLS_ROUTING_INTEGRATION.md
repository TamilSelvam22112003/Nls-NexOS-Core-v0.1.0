# NLS routing integration and forwarding workflow

**Status:** Companion Router-CA architecture reference. The current design is experimental and requires evidence from the paired NetOS integration tests; this document is not a production security certification.

## Responsibility boundary

Nls-NexOS Core is the Router-CA/control-plane service. It enrolls router identities, issues and revokes certificates, maintains the router registry, returns nonce-bound signed Router Directory Records (RDRs), and distributes signed directory bundles and policy. NetOS routers consume this trust information when establishing NLS data sessions.

OSPF and BGP remain routing protocols operated by FRRouting on the routers. Router-CA does not replace OSPF/BGP, does not calculate SPF or BGP best paths, and must not create forwarding routes from registry metadata. Route installation remains operator-controlled.

## Router identity and lookup

Each router has a local Ed25519 identity key and a separately managed RSA-3072 encryption key. The router's private keys remain local. Enrollment binds the RSA public key to the enrollment request using a request-bound proof of possession. The Router-CA issues a certificate and records authorized WAN endpoints, gateways, prefixes, status, serial, and record sequence.

For lookup(router_id, client_nonce):

1. Authenticate and authorize the caller over the NLS Control Record Protocol v1 channel.
2. Enforce caller status, rate limits, request validation, and registry policy.
3. Resolve the target RDR from the registry.
4. Return a signed record that echoes the caller nonce and has no more than the specified 30-second validity.
5. Sign directory records using the pinned Ed25519 control/directory identity key and the domain-separated canonical-CBOR preimage NLS-DIR-v1 || canonical-CBOR(payload).
6. Reject stale, malformed, sequence-rolled-back, revoked, disabled, or mismatched records at the client.
7. Never accept unsigned YAML or an unauthenticated network-supplied public key as a trust source.

Offline directory bundles must be signed, imported explicitly by the operator, checked for expiry and sequence rollback, and visibly marked as having degraded freshness. The default live mode fails closed when freshness is lost.

## NLS session relationship

The Router-CA supplies identity and authorization facts; the routers establish the data-plane session. The CA does not possess router session keys and does not decrypt client traffic.

For an S-to-D session, S obtains D's signed RDR, then performs the NLH2 M1–M4 exchange with D. Both endpoints independently cross-check peer-supplied identity against fresh signed directory data. After successful key confirmation, the peers use the NLE2 session-key data plane. Ordinary transit routers forward outer IPv6 packets; they do not decrypt/re-encrypt each transit hop in the current endpoint-tunnel specification.

The temporary vIP is defined by the paired NetOS docs/nls/MASTER_SPEC.md hybrid NLH2 amendment. It is a short-lived bootstrap value subject to the specified address policy and validation. It is not an identity credential and must never replace signature, certificate, or signed-RDR verification.

## OSPF/BGP coexistence

Routing adjacencies and route selection remain in FRRouting. The Router-CA may authorize router identities and prefixes, but route installation is an operator action. NLS data sessions must not intercept OSPF, BGP, required ICMPv6, Neighbor Discovery, or DHCP traffic unless a separately specified and tested mechanism explicitly supports that traffic.

## Security and evidence

The control protocol is custom and is not TLS. Its signed handshake, ephemeral key agreement, transcript-bound derivation, AEAD records, sequence checks, and directory signatures require continued interoperability and independent security review. Do not claim production readiness or categorical superiority over TLS/IPsec.

Required evidence comes from the paired repository's unit, security, cross-repository, and multi-router integration tests. Documentation alone does not establish successful packet forwarding, OSPF/BGP compatibility, or security.

# NLS vIP derivation test vectors

**Status:** Stage 5 shared fixture; no implementation conformance is implied until both repositories run it in CI.
**Normative source:** `docs/nls/MASTER_SPEC.md`, hybrid NLH2 amendment and Stage 3 vIP derivation invariants.
**Fixture:** `tests/vectors/vip_derivation_v1.json`.

## What this fixture checks

- Exact ordered fields for `NLS-vIP-v1`.
- 32-bit big-endian length prefix on every field.
- Packed 16-byte IPv6 address inputs.
- Full DER-byte inputs as opaque byte strings.
- 32-byte nonce and unsigned 64-bit big-endian time bucket.
- SHA-512 output and first-16-byte IPv6 candidate extraction.
- A deterministic rejected candidate followed by a fresh-nonce candidate.

## Important fixture limitation

The certificate and key byte strings are synthetic byte sequences used to test byte framing and hashing. They are **not valid X.509 certificates or valid SubjectPublicKeyInfo credentials** and must never be used in authentication tests or deployment. A separate integration fixture must use generated test PKI credentials and their actual DER encodings.

The second candidate is only a candidate. Passing the broad `2000::/3` prefix check is not sufficient: the implementation must apply the complete pinned policy-v1 exclusion table from the master specification.

## Required runner behavior

Both NetOS and NexOS Core test runners must consume the same JSON fixture and assert:

1. Each field's encoded bytes and order are exact.
2. The complete encoded input length is 224 bytes for each listed candidate.
3. SHA-512 digest equals the fixture's expected digest.
4. The candidate equals the expected IPv6 address.
5. Attempt 0 is rejected under the broad policy prefix and attempt 1 is passed to full policy validation.
6. Invalid input lengths, altered field order, altered endian encoding, and text-encoded IP addresses fail negative tests.
7. No digest rewriting, masking, or prefixing is performed.

Until both repositories implement and execute these assertions, mark cross-repository vector conformance **UNVERIFIED**. Do not call this fixture a passing test suite.

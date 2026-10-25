"""Normative NLS-vIP-v1 derivation primitive.

This module only encodes and hashes the inputs specified by MASTER_SPEC.md.
It deliberately does not accept/reject candidates against policy-v1: callers
must apply the complete pinned address-policy table and redraw a fresh nonce
when a candidate is disallowed. Never rewrite digest bits to fit policy.
"""
from __future__ import annotations

import hashlib
import ipaddress

_DOMAIN = b"NLS-vIP-v1"
_NONCE_BYTES = 32
_TIME_BUCKET_BYTES = 8
_MAX_U32 = (1 << 32) - 1
_MAX_U64 = (1 << 64) - 1


def _original_ip_bytes(value: str, field_name: str) -> bytes:
    if not isinstance(value, str) or "%" in value:
        raise ValueError(f"{field_name} must be an unscoped IPv6 address string")
    try:
        address = ipaddress.ip_address(value)
    except ValueError as exc:
        raise ValueError(f"{field_name} must be an IPv6 address") from exc
    if not isinstance(address, ipaddress.IPv6Address):
        raise ValueError(f"{field_name} must be an IPv6 address")
    if (
        address.is_unspecified
        or address.is_loopback
        or address.is_multicast
        or address.is_link_local
        or address.ipv4_mapped is not None
    ):
        raise ValueError(f"{field_name} is not a permitted originalIP")
    return address.packed


def _bytes_field(value: bytes, field_name: str) -> bytes:
    if not isinstance(value, bytes) or not value:
        raise ValueError(f"{field_name} must be non-empty bytes")
    return value


def encode_vip_derivation_input(
    destination_original_ip: str,
    destination_certificate_der: bytes,
    destination_ed25519_spki_der: bytes,
    source_original_ip: str,
    source_certificate_der: bytes,
    source_ed25519_spki_der: bytes,
    vip_nonce: bytes,
    time_bucket: int,
) -> bytes:
    """Return exact uint32-length-prefixed NLS-vIP-v1 input bytes."""
    destination_ip = _original_ip_bytes(destination_original_ip, "destination_originalIP")
    source_ip = _original_ip_bytes(source_original_ip, "source_originalIP")
    destination_certificate_der = _bytes_field(destination_certificate_der, "destination_certificate_der")
    destination_ed25519_spki_der = _bytes_field(destination_ed25519_spki_der, "destination_ed25519_spki_der")
    source_certificate_der = _bytes_field(source_certificate_der, "source_certificate_der")
    source_ed25519_spki_der = _bytes_field(source_ed25519_spki_der, "source_ed25519_spki_der")
    if not isinstance(vip_nonce, bytes) or len(vip_nonce) != _NONCE_BYTES:
        raise ValueError("vip_nonce must be exactly 32 bytes")
    if type(time_bucket) is not int or not 0 <= time_bucket <= _MAX_U64:
        raise ValueError("time_bucket must be an unsigned 64-bit integer")

    fields = (
        _DOMAIN,
        destination_ip,
        destination_certificate_der,
        destination_ed25519_spki_der,
        source_ip,
        source_certificate_der,
        source_ed25519_spki_der,
        vip_nonce,
        time_bucket.to_bytes(_TIME_BUCKET_BYTES, "big"),
    )
    encoded = bytearray()
    for field in fields:
        if len(field) > _MAX_U32:
            raise ValueError("vIP derivation field exceeds uint32 length limit")
        encoded.extend(len(field).to_bytes(4, "big"))
        encoded.extend(field)
    return bytes(encoded)


def derive_vip_candidate(
    destination_original_ip: str,
    destination_certificate_der: bytes,
    destination_ed25519_spki_der: bytes,
    source_original_ip: str,
    source_certificate_der: bytes,
    source_ed25519_spki_der: bytes,
    vip_nonce: bytes,
    time_bucket: int,
) -> ipaddress.IPv6Address:
    """Derive the candidate vIP; policy validation is a separate mandatory step."""
    encoded = encode_vip_derivation_input(
        destination_original_ip,
        destination_certificate_der,
        destination_ed25519_spki_der,
        source_original_ip,
        source_certificate_der,
        source_ed25519_spki_der,
        vip_nonce,
        time_bucket,
    )
    return ipaddress.IPv6Address(hashlib.sha512(encoded).digest()[:16])

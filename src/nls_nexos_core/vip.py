"""Temporary NLS virtual IPv6 address generation.

Addresses are overlay-only ULA /128s. The configured /64 must be unique to the
NLS deployment. SHA-256 derives the 64-bit interface identifier from a router
identity and fresh boot/session nonce; the Router-CA registry must still check
collisions, ownership and expiry. A hash-derived vIP is not proof of identity.
"""
from __future__ import annotations

DEFAULT_VIP_PREFIX = "fd42:4e4c:5300::/48"

import hashlib
import hmac
import ipaddress
import secrets


def generate_temporary_vip(router_identity: bytes, overlay_prefix: str,
                           *, nonce: bytes | None = None) -> tuple[str, bytes]:
    if not isinstance(router_identity, bytes) or len(router_identity) < 16:
        raise ValueError("router_identity must contain at least 16 bytes")
    network = ipaddress.IPv6Network(overlay_prefix, strict=True)
    if network.prefixlen != 64 or (int(network.network_address) >> 121) != 0b1111110:
        raise ValueError("overlay_prefix must be a ULA IPv6 /64 (fd00::/8)")
    nonce = secrets.token_bytes(32) if nonce is None else nonce
    if not isinstance(nonce, bytes) or len(nonce) < 16:
        raise ValueError("nonce must contain at least 16 random bytes")
    digest = hashlib.sha256(b"NLS-vIP-v1\x00" + router_identity + nonce).digest()
    iid = int.from_bytes(digest[:8], "big")
    if iid in (0, (1 << 64) - 1):
        digest = hashlib.sha256(digest + b"retry").digest()
        iid = int.from_bytes(digest[:8], "big")
    address = ipaddress.IPv6Address(int(network.network_address) | iid)
    return str(address), nonce


def derive_temporary_vip(secret: bytes, router_id: str, peer_id: str, nonce: bytes, prefix: str = DEFAULT_VIP_PREFIX) -> str:
    """Derive the same session-scoped overlay vIP contract as NlsxNetOS."""
    if not isinstance(secret, bytes) or len(secret) < 32:
        raise ValueError("vIP derivation secret must contain at least 32 bytes")
    if not isinstance(nonce, bytes) or len(nonce) < 16:
        raise ValueError("vIP nonce must contain at least 16 bytes")
    network = ipaddress.IPv6Network(prefix, strict=True)
    if network.prefixlen != 48 or (int(network.network_address) >> 121) != 0b1111110:
        raise ValueError("NLS vIP prefix must be a ULA IPv6 /48")
    context = b"NLS-TEMP-VIP-v1\x00" + router_id.encode() + b"\x00" + peer_id.encode() + b"\x00" + nonce
    digest = hmac.new(secret, context, hashlib.sha256).digest()
    return str(ipaddress.IPv6Address(int(network.network_address) | int.from_bytes(digest[:10], "big")))

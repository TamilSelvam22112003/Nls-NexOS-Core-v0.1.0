"""Pinned NLS vIP policy-v1 candidate validation.

The literal exclusion set is normative and must not be fetched from IANA at
runtime. Changing it requires a new policy version and specification change.
"""
from __future__ import annotations

import hashlib
import ipaddress

POLICY_VERSION = 1
GLOBAL_UNICAST_V6 = ipaddress.ip_network("2000::/3")
POLICY_V1_EXCLUSION_PREFIXES = (
    "2001::/23",
    "2001::/32",
    "2001:1::1/128",
    "2001:1::2/128",
    "2001:1::3/128",
    "2001:2::/48",
    "2001:3::/32",
    "2001:4:112::/48",
    "2001:10::/28",
    "2001:20::/28",
    "2001:30::/28",
    "2001:db8::/32",
    "2002::/16",
    "2620:4f:8000::/48",
    "3fff::/20",
)
POLICY_V1_EXCLUSIONS = tuple(
    ipaddress.ip_network(prefix) for prefix in POLICY_V1_EXCLUSION_PREFIXES
)
POLICY_V1_TABLE_SHA256 = "6639dadc8a64373a682874fb8e83e16a7e6898463b91c74da09c756527ab57ad"
_SERIALIZED_TABLE = ("\n".join(POLICY_V1_EXCLUSION_PREFIXES) + "\n").encode("ascii")


def validate_vip_candidate(candidate: str | ipaddress.IPv6Address,
                           policy_version: int = POLICY_VERSION) -> ipaddress.IPv6Address:
    """Return the IPv6 candidate if policy accepts it; otherwise raise ValueError."""
    if type(policy_version) is not int or policy_version != POLICY_VERSION:
        raise ValueError("unsupported vip_policy_version")
    try:
        address = candidate if isinstance(candidate, ipaddress.IPv6Address) else ipaddress.ip_address(candidate)
    except (ValueError, TypeError) as exc:
        raise ValueError("vIP candidate must be an IPv6 address") from exc
    if not isinstance(address, ipaddress.IPv6Address):
        raise ValueError("vIP candidate must be an IPv6 address")
    if address not in GLOBAL_UNICAST_V6:
        raise ValueError("vIP candidate is outside 2000::/3")
    if any(address in network for network in POLICY_V1_EXCLUSIONS):
        raise ValueError("vIP candidate falls within policy-v1 exclusion")
    return address


def verify_policy_v1_table_hash() -> bool:
    """Return whether the embedded literal table matches its normative SHA-256."""
    return hashlib.sha256(_SERIALIZED_TABLE).hexdigest() == POLICY_V1_TABLE_SHA256

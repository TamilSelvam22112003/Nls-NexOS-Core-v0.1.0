"""Boundary and pinned-table conformance tests for NLS vIP policy-v1."""
import ipaddress

import pytest

from nls_nexos_core.vip_policy import (
    GLOBAL_UNICAST_V6,
    POLICY_V1_EXCLUSION_PREFIXES,
    POLICY_V1_EXCLUSIONS,
    POLICY_V1_TABLE_SHA256,
    validate_vip_candidate,
    verify_policy_v1_table_hash,
)


def test_pinned_policy_table_hash_matches_specification():
    assert verify_policy_v1_table_hash()
    assert POLICY_V1_TABLE_SHA256 == "6639dadc8a64373a682874fb8e83e16a7e6898463b91c74da09c756527ab57ad"


@pytest.mark.parametrize("version", [0, 2, -1, True, "1", None])
def test_unknown_policy_version_fails_closed(version):
    with pytest.raises(ValueError, match="vip_policy_version"):
        validate_vip_candidate("2001:4860::1", version)


@pytest.mark.parametrize("address", ["1::1", "3fff::1", "4000::1", "::1", "192.0.2.1"])
def test_rejects_outside_global_unicast_or_special_purpose(address):
    with pytest.raises(ValueError):
        validate_vip_candidate(address)


def test_global_unicast_boundaries():
    assert validate_vip_candidate("2000::") == ipaddress.IPv6Address("2000::")
    assert validate_vip_candidate("3fff:ffff:ffff:ffff:ffff:ffff:ffff:ffff") == ipaddress.IPv6Address("3fff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")
    for address in ("1fff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "4000::"):
        with pytest.raises(ValueError):
            validate_vip_candidate(address)


@pytest.mark.parametrize("prefix", POLICY_V1_EXCLUSION_PREFIXES)
def test_every_exclusion_rejects_its_first_and_last_address(prefix):
    network = ipaddress.ip_network(prefix)
    for address in (network.network_address, network.broadcast_address):
        with pytest.raises(ValueError, match="policy-v1 exclusion"):
            validate_vip_candidate(address)


def test_each_exclusion_adjacent_addresses_follow_full_policy():
    for network in POLICY_V1_EXCLUSIONS:
        for integer in (int(network.network_address) - 1, int(network.broadcast_address) + 1):
            if not 0 <= integer < (1 << 128):
                continue
            address = ipaddress.IPv6Address(integer)
            if address not in GLOBAL_UNICAST_V6:
                with pytest.raises(ValueError):
                    validate_vip_candidate(address)
            elif any(address in excluded for excluded in POLICY_V1_EXCLUSIONS):
                with pytest.raises(ValueError):
                    validate_vip_candidate(address)
            else:
                assert validate_vip_candidate(address) == address

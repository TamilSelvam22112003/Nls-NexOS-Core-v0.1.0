"""Cross-check the shared NLS-vIP-v1 vector fixture."""
import json
from pathlib import Path

import pytest

from nls_nexos_core.vip_derivation import derive_vip_candidate, encode_vip_derivation_input


FIXTURE = Path(__file__).resolve().parents[1] / "vectors" / "vip_derivation_v1.json"


def _fixture():
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


def _derive(fields, candidate):
    return derive_vip_candidate(
        fields["destination_originalIP"],
        bytes.fromhex(fields["destination_certificate_der_hex"]),
        bytes.fromhex(fields["destination_ed25519_spki_der_hex"]),
        fields["source_originalIP"],
        bytes.fromhex(fields["source_certificate_der_hex"]),
        bytes.fromhex(fields["source_ed25519_spki_der_hex"]),
        bytes.fromhex(candidate["vip_nonce_hex"]),
        fields["time_bucket"],
    )


def test_vip_derivation_vectors_match_exact_digest_and_candidate():
    fixture = _fixture()
    fields = fixture["fields"]
    for candidate in fixture["candidates"]:
        encoded = encode_vip_derivation_input(
            fields["destination_originalIP"],
            bytes.fromhex(fields["destination_certificate_der_hex"]),
            bytes.fromhex(fields["destination_ed25519_spki_der_hex"]),
            fields["source_originalIP"],
            bytes.fromhex(fields["source_certificate_der_hex"]),
            bytes.fromhex(fields["source_ed25519_spki_der_hex"]),
            bytes.fromhex(candidate["vip_nonce_hex"]),
            fields["time_bucket"],
        )
        import hashlib
        assert len(encoded) == candidate["encoded_input_length"]
        assert hashlib.sha512(encoded).hexdigest() == candidate["sha512_hex"]
        assert str(_derive(fields, candidate)) == candidate["candidate_vip"]


def test_vip_derivation_rejects_wrong_nonce_length():
    f = _fixture()
    fields = f["fields"]
    with pytest.raises(ValueError, match="vip_nonce"):
        derive_vip_candidate(
            fields["destination_originalIP"],
            bytes.fromhex(fields["destination_certificate_der_hex"]),
            bytes.fromhex(fields["destination_ed25519_spki_der_hex"]),
            fields["source_originalIP"],
            bytes.fromhex(fields["source_certificate_der_hex"]),
            bytes.fromhex(fields["source_ed25519_spki_der_hex"]),
            b"short",
            fields["time_bucket"],
        )


@pytest.mark.parametrize("bad_ip", ["127.0.0.1", "::1", "::", "fe80::1%eth0", "ff02::1", "::ffff:192.0.2.1"])
def test_vip_derivation_rejects_prohibited_original_ip_forms(bad_ip):
    f = _fixture()
    fields = f["fields"]
    with pytest.raises(ValueError):
        derive_vip_candidate(
            bad_ip,
            bytes.fromhex(fields["destination_certificate_der_hex"]),
            bytes.fromhex(fields["destination_ed25519_spki_der_hex"]),
            fields["source_originalIP"],
            bytes.fromhex(fields["source_certificate_der_hex"]),
            bytes.fromhex(fields["source_ed25519_spki_der_hex"]),
            bytes.fromhex(f["candidates"][1]["vip_nonce_hex"]),
            fields["time_bucket"],
        )


@pytest.mark.parametrize("bad_bucket", [-1, 1 << 64, True, "58000000"])
def test_vip_derivation_rejects_invalid_time_bucket(bad_bucket):
    f = _fixture()
    fields = f["fields"]
    with pytest.raises(ValueError, match="time_bucket"):
        derive_vip_candidate(
            fields["destination_originalIP"],
            bytes.fromhex(fields["destination_certificate_der_hex"]),
            bytes.fromhex(fields["destination_ed25519_spki_der_hex"]),
            fields["source_originalIP"],
            bytes.fromhex(fields["source_certificate_der_hex"]),
            bytes.fromhex(fields["source_ed25519_spki_der_hex"]),
            bytes.fromhex(f["candidates"][1]["vip_nonce_hex"]),
            bad_bucket,
        )

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_router_ca_systemd_unit_is_hardened_and_state_writable():
    service = (ROOT / "deploy/systemd/nls-router-ca.service").read_text(encoding="utf-8")
    assert "ReadWritePaths=/var/lib/nls-nexos-core /var/log/nls-nexos-core" in service
    assert "MemoryDenyWriteExecute=true" in service
    assert "SystemCallFilter=@system-service @network-io" in service
    assert "SystemCallErrorNumber=EPERM" in service
    assert "CapabilityBoundingSet=" in service
    assert "ProtectSystem=strict" in service


def test_router_ca_tmpfiles_keeps_private_identity_directory():
    tmpfiles = (ROOT / "deploy/tmpfiles/nls-nexos-core.conf").read_text(encoding="utf-8")
    assert "d /var/lib/nls-nexos-core/identity 0700 nls-ca nls-ca -" in tmpfiles
    assert "d /var/lib/nls-nexos-core 0750 nls-ca nls-ca -" in tmpfiles

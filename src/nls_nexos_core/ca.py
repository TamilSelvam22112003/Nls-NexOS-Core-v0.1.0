from datetime import datetime, timedelta, timezone
from pathlib import Path
import hashlib
import ipaddress
import re
import secrets
import time

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID, ObjectIdentifier

from .config import Settings
from .database import Registry
from .models import EnrollmentRequest, EnrollmentResponse


ROUTER_ID_OID = ObjectIdentifier("1.3.6.1.4.1.55555.1.1")


class EnrollmentDenied(Exception):
    pass


class CertificateAuthority:
    def __init__(self, settings: Settings, registry: Registry, token: str):
        self.settings = settings
        self.registry = registry
        self.token = token
        self.ca_cert = x509.load_pem_x509_certificate(settings.ca_certificate.read_bytes())
        self.ca_key = serialization.load_pem_private_key(settings.ca_private_key.read_bytes(), password=None)
        if not isinstance(self.ca_key, rsa.RSAPrivateKey) or self.ca_key.key_size < 3072:
            raise RuntimeError("CA signing key must be RSA >= 3072 bits for this prototype")
        if self.ca_cert.public_key().public_numbers() != self.ca_key.public_key().public_numbers():
            raise RuntimeError("CA private key does not match configured CA certificate")

    def enroll(self, req: EnrollmentRequest, presented_token: str) -> EnrollmentResponse:
        now_epoch = int(time.time())
        now = datetime.now(timezone.utc)
        if not secrets.compare_digest(self.token, presented_token):
            self.registry.audit("ENROLL_DENIED", req.router_id, "invalid enrollment credential", now_epoch)
            raise EnrollmentDenied("enrollment denied")
        if abs(now_epoch - req.timestamp) > 300:
            self.registry.audit("ENROLL_DENIED", req.router_id, "stale request timestamp", now_epoch)
            raise EnrollmentDenied("enrollment request expired")
        if len(req.nonce) < 32 or not re.fullmatch(r"[A-Za-z0-9_-]+", req.nonce):
            raise EnrollmentDenied("invalid nonce")
        try:
            csr = x509.load_pem_x509_csr(req.csr_pem.encode("utf-8"))
        except (ValueError, TypeError) as exc:
            raise EnrollmentDenied("invalid CSR") from exc
        if not csr.is_signature_valid:
            raise EnrollmentDenied("CSR signature invalid")
        router = self.registry.get_router(req.router_id)
        if not router or not router["registered"] or router["status"] != "ACTIVE":
            self.registry.audit("ENROLL_DENIED", req.router_id, "router not registered/active", now_epoch)
            raise EnrollmentDenied("enrollment denied")
        try:
            public_der = csr.public_key().public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        except (ValueError, TypeError) as exc:
            raise EnrollmentDenied("unsupported CSR public key") from exc
        public_digest = hashlib.sha256(public_der).hexdigest()
        expected = router.get("expected_public_key_sha256")
        if expected and not secrets.compare_digest(expected.lower(), public_digest):
            raise EnrollmentDenied("CSR public key does not match registered key")
        if req.claimed_ipv6:
            try:
                ipaddress.IPv6Address(req.claimed_ipv6)
            except ValueError as exc:
                raise EnrollmentDenied("invalid claimed IPv6 address") from exc
            allowed = router.get("allowed_ipv6")
            if allowed and req.claimed_ipv6 != allowed:
                raise EnrollmentDenied("claimed IPv6 does not match registry")
        if req.claimed_mac:
            if not re.fullmatch(r"(?i)([0-9a-f]{2}:){5}[0-9a-f]{2}", req.claimed_mac):
                raise EnrollmentDenied("invalid claimed MAC")
            allowed_mac = router.get("allowed_mac")
            if allowed_mac and req.claimed_mac.lower() != allowed_mac.lower():
                raise EnrollmentDenied("claimed MAC does not match registry")
        nonce_digest = hashlib.sha256(req.nonce.encode("utf-8")).hexdigest()
        if not self.registry.is_request_new(req.request_id, req.router_id, nonce_digest, now_epoch):
            raise EnrollmentDenied("request replay detected")
        not_before = now - timedelta(minutes=2)
        not_after = now + timedelta(days=self.settings.certificate_days)
        subject = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, req.router_id),
        ])
        serial_int = x509.random_serial_number()
        builder = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(self.ca_cert.subject)
            .public_key(csr.public_key())
            .serial_number(serial_int)
            .not_valid_before(not_before.replace(tzinfo=None))
            .not_valid_after(not_after.replace(tzinfo=None))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(
                digital_signature=True, content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False, key_cert_sign=False,
                crl_sign=False, encipher_only=None, decipher_only=None,
            ), critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(req.router_id)]), critical=False)
            .add_extension(x509.UnrecognizedExtension(ROUTER_ID_OID, req.router_id.encode()), critical=False)
        )
        cert = builder.sign(private_key=self.ca_key, algorithm=hashes.SHA256())
        pem = cert.public_bytes(serialization.Encoding.PEM).decode("ascii")
        before_s = not_before.isoformat()
        after_s = not_after.isoformat()
        serial = format(serial_int, "x")
        digest = hashlib.sha256(pem.encode()).hexdigest()
        self.settings.issued_cert_dir.mkdir(parents=True, exist_ok=True)
        target = self.settings.issued_cert_dir / f"{serial}.crt"
        tmp = target.with_suffix(".crt.tmp")
        tmp.write_text(pem, encoding="ascii")
        tmp.chmod(0o640)
        tmp.replace(target)
        self.registry.record_certificate(serial, req.router_id, before_s, after_s, digest, now_epoch)
        self.registry.audit("CERT_ISSUED", req.router_id, f"serial={serial}", now_epoch)
        return EnrollmentResponse(
            router_id=req.router_id,
            serial_number=serial,
            certificate_pem=pem,
            ca_certificate_pem=self.ca_cert.public_bytes(serialization.Encoding.PEM).decode("ascii"),
            not_before=before_s,
            not_after=after_s,
        )

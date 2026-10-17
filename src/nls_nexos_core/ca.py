from datetime import datetime, timedelta, timezone
from ipaddress import IPv6Address
import hashlib
import re
import secrets
import time
import base64

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID

from .database import Registry
from .models import EnrollmentRequest, EnrollmentResponse


class EnrollmentDenied(Exception):
    """The router does not satisfy enrollment policy."""


class CertificateAuthority:
    def __init__(self, settings, registry: Registry, token: str):
        self.settings, self.registry, self.token = settings, registry, token
        self.ca_cert = x509.load_pem_x509_certificate(settings.ca_certificate.read_bytes())
        self.ca_key = serialization.load_pem_private_key(settings.ca_private_key.read_bytes(), password=None)
        if not isinstance(self.ca_key, rsa.RSAPrivateKey) or self.ca_key.key_size < 3072:
            raise RuntimeError("CA key must be RSA >= 3072 bits")
        if self.ca_cert.public_key().public_numbers() != self.ca_key.public_key().public_numbers():
            raise RuntimeError("CA key does not match CA certificate")

    def enroll(
        self,
        req: EnrollmentRequest,
        presented_bootstrap_token: str,
        presented_router_token: str,
    ) -> EnrollmentResponse:
        epoch = int(time.time())
        now = datetime.now(timezone.utc)
        if not secrets.compare_digest(self.token, presented_bootstrap_token):
            self.registry.audit("ENROLL_DENIED", req.router_id, "invalid bootstrap credential", epoch)
            raise EnrollmentDenied("enrollment denied")
        if abs(epoch - req.timestamp) > 300 or not re.fullmatch(r"[A-Za-z0-9_-]{32,128}", req.nonce):
            raise EnrollmentDenied("enrollment denied")

        try:
            csr = x509.load_pem_x509_csr(req.csr_pem.encode("utf-8"))
        except (ValueError, TypeError) as exc:
            raise EnrollmentDenied("enrollment denied") from exc
        if not csr.is_signature_valid:
            raise EnrollmentDenied("enrollment denied")

        router = self.registry.get_router(req.router_id)
        if not router or not router["registered"] or router["status"] != "ACTIVE":
            self.registry.audit("ENROLL_DENIED", req.router_id, "router not registered or active", epoch)
            raise EnrollmentDenied("enrollment denied")

        # The presented bootstrap token must also match this specific router's
        # allow-listed token hash. A valid global bootstrap token alone is not
        # sufficient authorization to enroll every registered router.
        registered_token_hash = router.get("enrollment_token_sha256")
        presented_token_hash = hashlib.sha256(presented_router_token.encode("utf-8")).hexdigest()
        if not registered_token_hash or not secrets.compare_digest(
            registered_token_hash.lower(), presented_token_hash
        ):
            self.registry.audit("ENROLL_DENIED", req.router_id, "router credential binding mismatch", epoch)
            raise EnrollmentDenied("enrollment denied")

        public_der = csr.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        key_fingerprint = hashlib.sha256(public_der).hexdigest()
        expected = router.get("expected_public_key_sha256")
        if expected and not secrets.compare_digest(expected.lower(), key_fingerprint):
            raise EnrollmentDenied("enrollment denied")

        # RSA encryption key and proof-of-possession are request-bound. Network
        # metadata is deliberately not read from EnrollmentRequest.
        try:
            rsa_public = serialization.load_pem_public_key(req.rsa_encryption_public_key.encode("ascii"))
            if not isinstance(rsa_public, rsa.RSAPublicKey) or rsa_public.key_size != 3072:
                raise EnrollmentDenied("enrollment denied")
            rsa_der = rsa_public.public_bytes(
                serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
            )
            rsa_fingerprint = hashlib.sha256(rsa_der).hexdigest()
            expected_rsa = router.get("expected_rsa_public_key_sha256")
            if expected_rsa and not secrets.compare_digest(expected_rsa.lower(), rsa_fingerprint):
                raise EnrollmentDenied("enrollment denied")
            challenge = (
                b"NLS-ENROLL-RSA-v1|" + req.router_id.encode("utf-8") + b"|" +
                req.request_id.encode("ascii") + b"|" + req.nonce.encode("ascii") + b"|" +
                rsa_fingerprint.encode("ascii")
            )
            proof = base64.b64decode(req.rsa_proof_of_possession.encode("ascii"), validate=True)
            rsa_public.verify(
                proof, challenge,
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                hashes.SHA256(),
            )
        except EnrollmentDenied:
            raise
        except Exception as exc:
            self.registry.audit("ENROLL_DENIED", req.router_id, "RSA proof-of-possession failed", epoch)
            raise EnrollmentDenied("enrollment denied") from exc

        if req.claimed_ipv6:
            try:
                IPv6Address(req.claimed_ipv6)
            except ValueError as exc:
                raise EnrollmentDenied("enrollment denied") from exc
            if router.get("allowed_ipv6") and req.claimed_ipv6 != router["allowed_ipv6"]:
                raise EnrollmentDenied("enrollment denied")
        if req.claimed_mac:
            if not re.fullmatch(r"(?i)([0-9a-f]{2}:){5}[0-9a-f]{2}", req.claimed_mac):
                raise EnrollmentDenied("enrollment denied")
            if router.get("allowed_mac") and req.claimed_mac.lower() != router["allowed_mac"].lower():
                raise EnrollmentDenied("enrollment denied")

        nonce_digest = hashlib.sha256(req.nonce.encode("utf-8")).hexdigest()
        if not self.registry.is_request_new(req.request_id, req.router_id, nonce_digest, epoch):
            raise EnrollmentDenied("enrollment denied")

        not_before = now - timedelta(minutes=2)
        not_after = now + timedelta(days=self.settings.certificate_days)
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, req.router_id)])
        serial = x509.random_serial_number()
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(self.ca_cert.subject)
            .public_key(csr.public_key())
            .serial_number(serial)
            .not_valid_before(not_before.replace(tzinfo=None))
            .not_valid_after(not_after.replace(tzinfo=None))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True, content_commitment=False,
                    key_encipherment=False, data_encipherment=False,
                    key_agreement=False, key_cert_sign=False, crl_sign=False,
                    encipher_only=None, decipher_only=None,
                ),
                critical=True,
            )
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(req.router_id)]), critical=False)
            .sign(private_key=self.ca_key, algorithm=hashes.SHA256())
        )
        pem = cert.public_bytes(serialization.Encoding.PEM).decode("ascii")
        serial_hex = format(serial, "x")
        before_s, after_s = not_before.isoformat(), not_after.isoformat()
        cert_digest = hashlib.sha256(pem.encode("ascii")).hexdigest()
        self.settings.issued_cert_dir.mkdir(parents=True, exist_ok=True)
        target = self.settings.issued_cert_dir / f"{serial_hex}.crt"
        tmp = target.with_suffix(".tmp")
        tmp.write_text(pem, encoding="ascii")
        tmp.chmod(0o640)
        tmp.replace(target)
        self.registry.record_certificate(serial_hex, req.router_id, before_s, after_s, cert_digest, epoch)
        # RDR ed25519_public_key is the standard-base64 encoding of the raw 32-byte
        # Ed25519 public key consumed by NlsxNetOS. The X.509 certificate remains PEM.
        ed_raw_b64 = base64.b64encode(csr.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )).decode("ascii")
        rsa_pem = rsa_public.public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode("ascii")
        self.registry.record_enrollment_keys(req.router_id, ed_raw_b64, rsa_pem, epoch)
        self.registry.audit("CERT_ISSUED", req.router_id, f"serial={serial_hex}", epoch)
        return EnrollmentResponse(
            router_id=req.router_id,
            serial_number=serial_hex,
            certificate_pem=pem,
            ca_certificate_pem=self.ca_cert.public_bytes(serialization.Encoding.PEM).decode("ascii"),
            not_before=before_s,
            not_after=after_s,
        )

"""TCP listener for the experimental NLS Control Record Protocol v1."""
from __future__ import annotations

import hashlib
import ipaddress
import logging
import socket
import threading
import time
from datetime import datetime, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, padding, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from .api import handle_control_request
from .control_protocol import NLSControlError, server_handshake
from .database import Registry

LOG = logging.getLogger("nls-nexos-core.control")


class NLSControlServer:
    def __init__(self, settings, registry: Registry, authority, control_identity_key):
        self.settings = settings
        self.registry = registry
        self.authority = authority
        self.control_identity_key = control_identity_key
        self._seen_nonces: dict[str, float] = {}
        self._nonce_lock = threading.Lock()
        self._lookup_times: dict[str, list[float]] = {}
        self._lookup_lock = threading.Lock()
        self._active_lookup_counts: dict[str, int] = {}
        self._active_lookup_total = 0
        self._lookup_concurrency_lock = threading.Lock()
        self.max_concurrent_lookups_per_router = 4
        self.max_concurrent_lookups_total = 64
        self._stopping = threading.Event()

    def _fresh_nonce(self, nonce: str) -> bool:
        now = time.monotonic()
        with self._nonce_lock:
            for value, expiry in list(self._seen_nonces.items()):
                if expiry <= now:
                    self._seen_nonces.pop(value, None)
            if nonce in self._seen_nonces:
                return False
            self._seen_nonces[nonce] = now + 2 * self.settings.max_clock_skew_seconds
            return True

    @staticmethod
    def _cert_public_raw(certificate):
        key = certificate.public_key()
        if not isinstance(key, ed25519.Ed25519PublicKey):
            raise NLSControlError("router certificate identity key type is invalid")
        return key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)

    def _authorize_client_certificate(self, hello: dict) -> dict:
        """Validate a direct Router-CA-issued client certificate and registry state."""
        try:
            cert = x509.load_pem_x509_certificate(hello["certificate_pem"].encode("ascii"))
            ca_cert = self.authority.ca_cert
            now = datetime.now(timezone.utc)
            not_before = getattr(cert, "not_valid_before_utc", None)
            not_after = getattr(cert, "not_valid_after_utc", None)
            if not_before is None:
                not_before = cert.not_valid_before.replace(tzinfo=timezone.utc)
            if not_after is None:
                not_after = cert.not_valid_after.replace(tzinfo=timezone.utc)
            if cert.issuer != ca_cert.subject:
                raise NLSControlError("router certificate issuer mismatch")
            if not (not_before <= now <= not_after):
                raise NLSControlError("router certificate is expired or not yet valid")
            if self._cert_public_raw(cert) != __import__("base64").b64decode(
                hello["identity_public_key"], validate=True
            ):
                raise NLSControlError("router certificate does not match the NLS identity key")
            common_names = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
            if len(common_names) != 1 or common_names[0].value != hello.get("router_id"):
                raise NLSControlError("router certificate identity mismatch")
            basic = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
            if basic.ca:
                raise NLSControlError("router certificate must not be a CA")
            eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
            if ExtendedKeyUsageOID.CLIENT_AUTH not in eku:
                raise NLSControlError("router certificate is not valid for client authentication")
            ca_key = ca_cert.public_key()
            if not isinstance(ca_key, rsa.RSAPublicKey):
                raise NLSControlError("unsupported Router-CA certificate signing key")
            ca_key.verify(cert.signature, cert.tbs_certificate_bytes,
                          padding.PKCS1v15(), cert.signature_hash_algorithm)
            router = self.registry.get_router(hello["router_id"])
            if not router or not router["registered"] or router["status"] != "ACTIVE":
                raise NLSControlError("router is not active in the registry")
            serial = format(cert.serial_number, "x")
            issued = self.registry.get_certificate(serial)
            if not issued or issued["status"] != "ACTIVE" or issued["router_id"] != hello["router_id"]:
                raise NLSControlError("router certificate is not active in the registry")
            return {"router_id": hello["router_id"], "serial_number": serial}
        except NLSControlError:
            raise
        except Exception as exc:
            raise NLSControlError("router certificate validation failed") from exc

    def _client_authenticated(self, hello: dict) -> dict | None:
        if hello.get("certificate_pem") is None:
            return None
        return self._authorize_client_certificate(hello)

    def _dispatch(self, message: dict, auth: dict | None) -> dict:
        action = message.get("type") if isinstance(message, dict) else None
        reserved_lookup_router = None
        if action in ("lookup", "directory-sync"):
            if not auth:
                self.registry.audit("DIRECTORY_LOOKUP_DENIED", None, "missing active client certificate", int(time.time()))
                return {"type": "error", "code": "not-authorized", "message": "directory access denied"}
            router_id = auth["router_id"]
            router = self.registry.get_router(router_id)
            cert = self.registry.get_certificate(auth.get("serial_number", ""))
            if (not router or not router.get("registered") or router.get("status") != "ACTIVE"
                    or not cert or cert.get("status") != "ACTIVE" or cert.get("router_id") != router_id):
                self.registry.audit("DIRECTORY_LOOKUP_DENIED", router_id, "certificate or router no longer active", int(time.time()))
                return {"type": "error", "code": "not-authorized", "message": "directory access denied"}
            try:
                from datetime import datetime, timezone
                expiry = datetime.fromisoformat(cert["not_after"].replace("Z", "+00:00"))
                if expiry.tzinfo is None:
                    expiry = expiry.replace(tzinfo=timezone.utc)
                if expiry.timestamp() <= time.time():
                    self.registry.audit("DIRECTORY_LOOKUP_DENIED", router_id, "client certificate expired", int(time.time()))
                    return {"type": "error", "code": "not-authorized", "message": "directory access denied"}
            except (KeyError, ValueError, TypeError):
                self.registry.audit("DIRECTORY_LOOKUP_DENIED", router_id, "invalid certificate expiry metadata", int(time.time()))
                return {"type": "error", "code": "not-authorized", "message": "directory access denied"}
            now = time.monotonic()
            with self._lookup_lock:
                recent = [t for t in self._lookup_times.get(router_id, []) if now - t < 60]
                # A single authenticated NLS handshake can require fresh peer and
                # local RDR lookups on both ends. Keep a bounded per-router limit,
                # but allow the required repeated-rekey acceptance exercise.
                if len(recent) >= 120:
                    self.registry.audit("DIRECTORY_LOOKUP_DENIED", router_id, "rate limit exceeded", int(time.time()))
                    self._lookup_times[router_id] = recent
                    return {"type": "error", "code": "rate-limited", "message": "directory request rate limit exceeded"}
                recent.append(now)
                self._lookup_times[router_id] = recent
            if action == "lookup":
                with self._lookup_concurrency_lock:
                    active_for_router = self._active_lookup_counts.get(router_id, 0)
                    if (active_for_router >= self.max_concurrent_lookups_per_router
                            or self._active_lookup_total >= self.max_concurrent_lookups_total):
                        self.registry.audit("DIRECTORY_LOOKUP_DENIED", router_id, "concurrent lookup cap exceeded", int(time.time()))
                        return {"type": "error", "code": "rate-limited", "message": "directory concurrency limit exceeded"}
                    self._active_lookup_counts[router_id] = active_for_router + 1
                    self._active_lookup_total += 1
                    reserved_lookup_router = router_id
        try:
            return handle_control_request(
                message=message,
                authority=self.authority,
                registry=self.registry,
                settings=self.settings,
                authenticated_router=auth,
                control_identity_key=self.control_identity_key,
            )
        finally:
            if reserved_lookup_router is not None:
                with self._lookup_concurrency_lock:
                    count = self._active_lookup_counts.get(reserved_lookup_router, 0) - 1
                    if count > 0:
                        self._active_lookup_counts[reserved_lookup_router] = count
                    else:
                        self._active_lookup_counts.pop(reserved_lookup_router, None)
                    self._active_lookup_total -= 1

    def _handle_client(self, conn: socket.socket, address) -> None:
        channel = None
        try:
            conn.settimeout(90)
            channel, hello, auth = server_handshake(
                conn,
                self.control_identity_key,
                self.settings.control_id,
                authorize_client=self._client_authenticated,
                nonce_guard=self._fresh_nonce,
                max_clock_skew_seconds=self.settings.max_clock_skew_seconds,
            )
            label = (auth or {}).get("router_id", hello.get("router_id", "unidentified"))
            LOG.info("NLS control session established from %s as %s authenticated=%s",
                     address, label, bool(auth))
            while not self._stopping.is_set():
                try:
                    request = channel.recv()
                except socket.timeout:
                    LOG.info("NLS control idle timeout from %s", address)
                    break
                try:
                    response = self._dispatch(request, auth)
                except PermissionError:
                    response = {"type": "error", "code": "not-authorized",
                                "message": "operation requires a current Router-CA identity certificate"}
                except Exception:
                    LOG.exception("NLS control request failed from %s", address)
                    response = {"type": "error", "code": "request-failed",
                                "message": "request could not be completed"}
                channel.send(response)
                if request.get("type") == "close":
                    break
        except (EOFError, OSError, NLSControlError) as exc:
            LOG.info("NLS control connection from %s closed: %s", address, exc)
        finally:
            if channel is not None:
                try:
                    channel.close()
                except OSError:
                    pass
            else:
                try:
                    conn.close()
                except OSError:
                    pass

    def serve_forever(self) -> None:
        host = self.settings.host
        try:
            address = ipaddress.ip_address(host.split("%", 1)[0])
            family = socket.AF_INET6 if address.version == 6 else socket.AF_INET
        except ValueError as exc:
            raise ValueError("Router-CA listen host must be an IPv4 or IPv6 address") from exc
        listener = socket.socket(family, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if family == socket.AF_INET6 and hasattr(socket, "IPV6_V6ONLY"):
            listener.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        listener.bind((host, self.settings.port))
        listener.listen(128)
        listener.settimeout(1.0)
        LOG.info("Router-CA listening for NLS Control v1 on %s:%d", host, self.settings.port)
        try:
            while not self._stopping.is_set():
                try:
                    conn, address = listener.accept()
                except socket.timeout:
                    continue
                threading.Thread(target=self._handle_client, args=(conn, address), daemon=True).start()
        finally:
            listener.close()

    def stop(self) -> None:
        self._stopping.set()

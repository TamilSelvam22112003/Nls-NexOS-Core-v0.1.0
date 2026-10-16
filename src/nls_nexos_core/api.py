"""Transport-independent handlers for the NLS Control Record Protocol."""
from __future__ import annotations

import time
from pydantic import ValidationError

from .ca import EnrollmentDenied
from .directory import signed_directory_bundle, signed_rdr
from .models import EnrollmentRequest


def _policy(settings) -> dict:
    return {
        "policy_version": settings.policy_version,
        "nls_protocol_version": 1,
        "control_protocol": "NLS-Control-v1",
        "key_exchange": "X25519",
        "key_derivation": "HKDF-SHA256",
        "record_cipher": "AES-256-GCM",
        "key_distribution": "derive-locally-per-session; never transmit raw symmetric keys",
        "replay_window": settings.replay_window,
        "max_clock_skew_seconds": settings.max_clock_skew_seconds,
        "session_timeout_seconds": settings.session_timeout_seconds,
        "key_rotation_seconds": settings.key_rotation_seconds,
    }


def _bundle(registry, settings, control_identity_key=None) -> dict:
    result = {
        "policy": _policy(settings),
        "revocations": {
            "version": 1,
            "revoked_certificates": registry.list_revoked_certificates(),
        },
        "directory_seq": registry.directory_seq(),
    }
    if control_identity_key is not None:
        result["directory_bundle"] = signed_directory_bundle(registry, settings, control_identity_key)
    return result


def handle_control_request(message: dict, authority, registry, settings,
                           authenticated_router: dict | None = None,
                           control_identity_key=None) -> dict:
    if not isinstance(message, dict):
        return {"type": "error", "code": "bad-request", "message": "request must be an object"}
    action = message.get("type")
    if action == "health":
        return {"type": "health-result", "ok": True, "control_id": settings.control_id,
                "protocol_version": 1}
    if action == "enroll":
        if authenticated_router and message.get("request", {}).get("router_id") != authenticated_router["router_id"]:
            return {"type": "error", "code": "not-authorized", "message": "router identity mismatch"}
        try:
            req = EnrollmentRequest.model_validate(message.get("request"))
            bootstrap_token = message.get("bootstrap_token")
            router_token = message.get("router_token")
            if not isinstance(bootstrap_token, str) or not isinstance(router_token, str):
                raise EnrollmentDenied("enrollment denied")
            response = authority.enroll(req, bootstrap_token, router_token)
        except (ValidationError, EnrollmentDenied, ValueError, TypeError):
            return {"type": "error", "code": "enrollment-denied", "message": "enrollment denied"}
        return {
            "type": "enrollment-result", "ok": True,
            "router_id": response.router_id, "serial_number": response.serial_number,
            "certificate_pem": response.certificate_pem,
            "ca_certificate_pem": response.ca_certificate_pem,
            "not_before": response.not_before, "not_after": response.not_after,
            **_bundle(registry, settings, control_identity_key),
        }

    if action in ("lookup", "directory-sync", "sync", "heartbeat", "status"):
        if not authenticated_router:
            if action in ("lookup", "directory-sync"):
                registry.audit("DIRECTORY_LOOKUP_DENIED", None, "missing active client certificate", int(time.time()))
                return {"type": "error", "code": "not-authorized", "message": "directory access denied"}
            raise PermissionError("a valid Router-CA-issued client certificate is required")
        router_id = authenticated_router["router_id"]
        requested_router_id = message.get("router_id", router_id)
        if requested_router_id != router_id:
            registry.audit("CONTROL_DENIED", router_id, "router identity mismatch", int(time.time()))
            return {"type": "error", "code": "not-authorized", "message": "router identity mismatch"}
        if action == "lookup":
            target = message.get("target_router_id")
            nonce = message.get("client_nonce")
            if not isinstance(target, str) or not 1 <= len(target) <= 128 or not isinstance(nonce, str) or not 16 <= len(nonce) <= 128:
                registry.audit("DIRECTORY_LOOKUP_DENIED", router_id, "invalid lookup parameters", int(time.time()))
                return {"type": "error", "code": "bad-request", "message": "invalid lookup request"}
            record = signed_rdr(registry, target, control_identity_key, client_nonce=nonce) if control_identity_key else None
            registry.audit("DIRECTORY_LOOKUP", router_id, "target=" + target, int(time.time()))
            if record is None:
                from .directory import sign_payload
                record = sign_payload({
                    "router_id": target, "ed25519_public_key": None, "rsa_encryption_public_key": None,
                    "wan_endpoints": [], "gateway_ips": [], "prefixes": [], "certificate_serial": None,
                    "status": "UNKNOWN", "record_seq": 0, "issued_at": int(time.time()), "client_nonce": nonce,
                    "valid_until": int(time.time()) + 30,
                }, control_identity_key)
            return {"type": "lookup-result", "ok": True, "client_nonce": nonce, "record": record}
        if action == "directory-sync":
            since_seq = message.get("since_seq", 0)
            if type(since_seq) is not int or since_seq < 0:
                return {"type": "error", "code": "bad-request", "message": "invalid since_seq"}
            bundle = signed_directory_bundle(registry, settings, control_identity_key) if control_identity_key else None
            return {"type": "directory-sync-result", "ok": True, "since_seq": since_seq,
                    "directory_bundle": bundle, "directory_seq": registry.directory_seq(),
                    "revoked_serials": bundle["payload"]["revoked_serials"] if bundle else []}
        if action == "status":
            return {"type": "status-result", "ok": True, "router_id": router_id,
                    "certificate_serial": authenticated_router["serial_number"],
                    **_bundle(registry, settings, control_identity_key)}
        if action == "heartbeat":
            bundle = _bundle(registry, settings, control_identity_key)
            return {"type": "heartbeat-result", "ok": True,
                    "server_time": int(time.time()), "directory_seq": registry.directory_seq(),
                    "revocation_state": bundle["revocations"], **bundle}
        return {"type": "sync-result", "ok": True, **_bundle(registry, settings, control_identity_key)}
    if action == "close":
        return {"type": "close-result", "ok": True}
    return {"type": "error", "code": "unsupported-operation", "message": "unsupported NLS control operation"}

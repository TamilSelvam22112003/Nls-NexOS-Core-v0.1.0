"""Transport-independent request handlers for the NLS Control Record Protocol."""
from __future__ import annotations

from pydantic import ValidationError

from .ca import EnrollmentDenied
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


def _bundle(registry, settings) -> dict:
    return {
        "policy": _policy(settings),
        "revocations": {
            "version": 1,
            "revoked_certificates": registry.list_revoked_certificates(),
        },
    }


def handle_control_request(message: dict, authority, registry, settings,
                           authenticated_router: dict | None = None) -> dict:
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
            "type": "enrollment-result",
            "ok": True,
            "router_id": response.router_id,
            "serial_number": response.serial_number,
            "certificate_pem": response.certificate_pem,
            "ca_certificate_pem": response.ca_certificate_pem,
            "not_before": response.not_before,
            "not_after": response.not_after,
            **_bundle(registry, settings),
        }
    if action in ("sync", "heartbeat", "status"):
        if not authenticated_router:
            raise PermissionError("a valid Router-CA-issued client certificate is required")
        requested_router_id = message.get("router_id", authenticated_router["router_id"])
        if requested_router_id != authenticated_router["router_id"]:
            return {"type": "error", "code": "not-authorized", "message": "router identity mismatch"}
        if action == "status":
            return {"type": "status-result", "ok": True,
                    "router_id": authenticated_router["router_id"],
                    "certificate_serial": authenticated_router["serial_number"],
                    **_bundle(registry, settings)}
        if action == "heartbeat":
            return {"type": "heartbeat-result", "ok": True,
                    "server_time": __import__("time").time_ns() // 1_000_000_000,
                    **_bundle(registry, settings)}
        return {"type": "sync-result", "ok": True, **_bundle(registry, settings)}
    if action == "close":
        return {"type": "close-result", "ok": True}
    return {"type": "error", "code": "unsupported-operation", "message": "unsupported NLS control operation"}

"""Regression tests for authenticated Router-CA directory lookup limits."""
from __future__ import annotations

import threading
import time

from nls_nexos_core.control import NLSControlServer


class _Registry:
    def __init__(self):
        self.events = []

    def get_router(self, router_id):
        return {"router_id": router_id, "registered": 1, "status": "ACTIVE"}

    def get_certificate(self, serial):
        return {
            "serial_number": serial,
            "router_id": "router-a",
            "status": "ACTIVE",
            "not_after": "2099-01-01T00:00:00+00:00",
        }

    def audit(self, event, router_id, detail, timestamp):
        self.events.append((event, router_id, detail, timestamp))


def _server():
    server = object.__new__(NLSControlServer)
    server.registry = _Registry()
    server._lookup_times = {}
    server._lookup_lock = threading.Lock()
    server._active_lookup_counts = {}
    server._active_lookup_total = 0
    server._lookup_concurrency_lock = threading.Lock()
    server.max_concurrent_lookups_per_router = 4
    server.max_concurrent_lookups_total = 64
    return server


def _lookup_request():
    return {"type": "lookup", "target_router_id": "router-b", "client_nonce": "n" * 32}


def test_lookup_rate_limit_rejects_121st_request_in_a_minute():
    server = _server()
    now = time.monotonic()
    server._lookup_times["router-a"] = [now - 1.0] * 120

    response = server._dispatch(_lookup_request(), {"router_id": "router-a", "serial_number": "abc123"})

    assert response["type"] == "error"
    assert response["code"] == "rate-limited"
    assert server.registry.events[-1][0] == "DIRECTORY_LOOKUP_DENIED"
    assert server._active_lookup_total == 0


def test_lookup_concurrency_cap_rejects_without_leaking_reservation():
    server = _server()
    server._active_lookup_counts["router-a"] = server.max_concurrent_lookups_per_router
    server._active_lookup_total = server.max_concurrent_lookups_per_router

    response = server._dispatch(_lookup_request(), {"router_id": "router-a", "serial_number": "abc123"})

    assert response["type"] == "error"
    assert response["code"] == "rate-limited"
    assert server._active_lookup_counts["router-a"] == server.max_concurrent_lookups_per_router
    assert server._active_lookup_total == server.max_concurrent_lookups_per_router
    assert server.registry.events[-1][0] == "DIRECTORY_LOOKUP_DENIED"

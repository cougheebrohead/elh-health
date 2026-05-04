"""Vitalstack smoke tests — DB-free."""
from __future__ import annotations

import importlib


def test_modules_import():
    for mod in ("server", "db", "orgs", "auth", "audit", "sso", "scim", "ratelimit"):
        importlib.import_module(mod)


def test_password_roundtrip():
    from auth import hash_password, verify_password
    h = hash_password("Solid-Pa55phrase-2026!")
    assert verify_password("Solid-Pa55phrase-2026!", h)
    assert not verify_password("wrong", h)
    assert not verify_password("", h)
    assert not verify_password("x", "")


def test_password_pbkdf2_iterations():
    from auth import hash_password, PBKDF2_ITERATIONS
    h = hash_password("anything-strong-1234567")
    assert h.startswith("pbkdf2_sha256$")
    iters = int(h.split("$")[1])
    assert iters >= 200_000
    assert PBKDF2_ITERATIONS >= 200_000


def test_rate_limit_per_window():
    from ratelimit import allow
    key = "vs-test-rl"
    for _ in range(2):
        assert allow(key, 2, 60)
    assert not allow(key, 2, 60)


def test_scim_user_serialization_shape():
    from scim import _to_scim_user
    out = _to_scim_user({"id": "abc", "email": "e@x.com", "name": "Ed", "is_active": True})
    assert out["schemas"] == ["urn:ietf:params:scim:schemas:core:2.0:User"]
    assert out["userName"] == "e@x.com"
    assert out["active"] is True
    assert out["meta"]["resourceType"] == "User"

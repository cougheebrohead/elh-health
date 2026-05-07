"""ELH Health smoke tests — DB-free."""
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


def test_password_hash_uses_argon2id():
    """Iron Dome I-2: new hashes are Argon2id (PHC string)."""
    from auth import hash_password
    h = hash_password("anything-strong-1234567")
    assert h.startswith("$argon2id$"), f"expected Argon2id, got {h[:20]}"


def test_legacy_pbkdf2_hashes_still_verify():
    """Lazy-migration: existing pbkdf2_sha256$ hashes from before the
    Iron Dome upgrade must keep verifying."""
    import hashlib
    from auth import verify_password, hash_needs_upgrade
    plain = "legacy-Solid-Pa55phrase-2026!"
    salt = bytes(range(16))
    dk = hashlib.pbkdf2_hmac("sha256", plain.encode(), salt, 200_000)
    legacy = f"pbkdf2_sha256$200000${salt.hex()}${dk.hex()}"
    assert verify_password(plain, legacy)
    assert not verify_password("wrong", legacy)
    assert hash_needs_upgrade(legacy)


def test_argon2_no_rehash_needed():
    from auth import hash_password, hash_needs_upgrade
    assert not hash_needs_upgrade(hash_password("x"))


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

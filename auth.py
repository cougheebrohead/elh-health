"""ELH Health auth — Argon2id password hashing + lockout-aware verify
+ bearer-token sessions.

Iron Dome I-2 parity: shared password hashing with FitApp + elh-coach
via fitapp_core.security.passwords. Legacy "pbkdf2_sha256$..." hashes
keep working through lazy migration; on a successful PBKDF2 verify,
the login flow re-hashes with Argon2id and writes back so the next
login uses the modern algorithm.

SSO is handled separately in sso.py; this module covers password
fallback for org_admin/site_admin local accounts (and members where
the org has sso_required=false).
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from fitapp_core.security import (
    hash_password as _argon2_hash,
    verify_password as _verify_any,
    needs_rehash as _needs_rehash,
)
from fitapp_core.security.ratelimit import lockout_status
from fitapp_core.security.sessions import (
    new_session_token as _new_session_token,
    hash_token as _hash_session_token,
)

from db import db


SESSION_TTL_DAYS = 30

# Lockout policy (matches elh-coach + FitApp)
LOCKOUT_THRESHOLD = 10
LOCKOUT_BASE_S = 15 * 60
LOCKOUT_CAP_S = 120 * 60


def hash_password(plain: str) -> str:
    """Mint Argon2id PHC hash for a new password."""
    if not plain:
        raise ValueError("password required")
    return _argon2_hash(plain)


def verify_password(plain: str, stored: str | None) -> bool:
    """Verify against Argon2id or legacy PBKDF2. Never raises on user
    content."""
    if not stored or not plain:
        return False
    return _verify_any(stored, plain)


def hash_needs_upgrade(stored: str | None) -> bool:
    """True if `stored` is a legacy hash that should be re-hashed
    after a successful verify."""
    if not stored:
        return False
    return _needs_rehash(stored)


# ── per-account login lockout ───────────────────────────────────────

def get_lockout_state(user_id: str) -> tuple[bool, int]:
    """(locked, seconds_remaining) for the given user uuid.

    No row = no failures yet -> not locked.
    """
    row = db.fetch_one(
        "select fail_count, last_fail_at from user_login_failures where user_id = $1",
        user_id,
    )
    if not row or not row.get("last_fail_at"):
        return False, 0
    last = row["last_fail_at"]
    if isinstance(last, str):
        last_ts = datetime.fromisoformat(last.replace("Z", "+00:00")).timestamp()
    else:
        last_ts = last.timestamp()
    return lockout_status(
        now=datetime.now(timezone.utc).timestamp(),
        failure_count=int(row.get("fail_count") or 0),
        last_failure=last_ts,
        threshold=LOCKOUT_THRESHOLD,
        base_lock_s=LOCKOUT_BASE_S,
        cap_lock_s=LOCKOUT_CAP_S,
    )


def record_login_failure(user_id: str) -> None:
    db.execute(
        """insert into user_login_failures (user_id, fail_count, last_fail_at)
           values ($1, 1, now())
           on conflict (user_id) do update
             set fail_count = user_login_failures.fail_count + 1,
                 last_fail_at = now()""",
        user_id,
    )


def clear_login_failures(user_id: str) -> None:
    db.execute(
        """insert into user_login_failures (user_id, fail_count, last_fail_at, locked_until)
           values ($1, 0, null, null)
           on conflict (user_id) do update
             set fail_count = 0, last_fail_at = null, locked_until = null""",
        user_id,
    )


# ── sessions ────────────────────────────────────────────────────────
# Token mint + SHA-256 fingerprint live in fitapp_core.security.sessions
# (shared with FitApp + elh-coach). The DB row shape — org_id, site_id,
# sso_session_id, ip_hash column — stays here because it's health-specific.

import hashlib  # only ip-hash pseudonymity still needs it


def _hash_token(token: str) -> str:
    return _hash_session_token(token)


def issue_session(*, user_id: str, org_id: str,
                  ip: str | None = None, ua: str | None = None,
                  sso_session_id: str | None = None) -> str:
    token = _new_session_token()
    expires = datetime.now(timezone.utc) + timedelta(days=SESSION_TTL_DAYS)
    db.execute(
        """insert into sessions
           (token_hash, user_id, org_id, expires_at, ip_hash, user_agent, sso_session_id)
           values ($1, $2, $3, $4, $5, $6, $7)""",
        _hash_token(token), user_id, org_id, expires.isoformat(),
        hashlib.sha256((ip or "").encode()).hexdigest()[:32] if ip else None,
        (ua or "")[:300],
        sso_session_id,
    )
    return token


def validate_session(token: str) -> dict[str, Any] | None:
    if not token:
        return None
    row = db.fetch_one(
        """select s.user_id, s.org_id, s.expires_at,
                  u.role, u.email, u.name, u.site_id, u.is_active
           from sessions s
           join users u on u.id = s.user_id
           where s.token_hash = $1 and s.expires_at > now()""",
        _hash_token(token),
    )
    if not row:
        return None
    if not row.get("is_active"):
        return None
    try:
        db.execute("update sessions set last_seen_at = now() where token_hash = $1",
                   _hash_token(token))
    except Exception:
        pass
    return {
        "user_id": row["user_id"],
        "org_id": row["org_id"],
        "site_id": row.get("site_id"),
        "role": row["role"],
        "email": row["email"],
        "name": row["name"],
    }


def revoke_session(token: str) -> None:
    if not token:
        return
    db.execute("delete from sessions where token_hash = $1", _hash_token(token))


def revoke_all_user_sessions(user_id: str) -> None:
    db.execute("delete from sessions where user_id = $1", user_id)

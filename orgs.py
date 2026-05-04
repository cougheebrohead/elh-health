"""Org resolver — Vitalstack uses Host header to map to an org.

  <slug>.vitalstack.app   → org by slug
  <custom_domain>         → org by custom domain (rare for enterprise; usually
                            they keep the vitalstack.app subdomain)
  apex (vitalstack.app)   → marketing site (no org)
"""

from __future__ import annotations

import os
import time
from typing import Any

from db import db

APEX_HOST = os.environ.get("APEX_HOST", "vitalstack.app")

_CACHE: dict[str, tuple[float, dict | None]] = {}
_TTL_SEC = 60


def org_resolver(host: str) -> dict[str, Any] | None:
    host = (host or "").lower().split(":")[0]
    if not host:
        return None

    now = time.time()
    cached = _CACHE.get(host)
    if cached and cached[0] > now:
        return cached[1]

    org: dict | None = None
    if host == APEX_HOST or host == f"www.{APEX_HOST}":
        org = None
    elif host.endswith(f".{APEX_HOST}"):
        slug = host[: -(len(APEX_HOST) + 1)]
        org = db.fetch_one("select * from orgs where slug = $1", slug)

    _CACHE[host] = (now + _TTL_SEC, org)
    return org


def invalidate_cache(host: str | None = None) -> None:
    if host is None:
        _CACHE.clear()
    else:
        _CACHE.pop(host.lower(), None)

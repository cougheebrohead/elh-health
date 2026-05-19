"""SCIM 2.0 user provisioning endpoint.

ELH Health supports inbound SCIM so org IT can push users from Okta, Azure
AD, OneLogin, etc. The protocol is v2.0 over HTTPS with a per-org bearer
token (whose sha256 is stored in `scim_config.bearer_token_hash`).

Implemented operations:
  GET  /scim/v2/Users          (list, with filter/startIndex/count)
  GET  /scim/v2/Users/{id}     (read one)
  POST /scim/v2/Users          (create)
  PUT  /scim/v2/Users/{id}     (full replace)
  PATCH /scim/v2/Users/{id}    (partial — RFC 7644 §3.5.2 ops: replace, add, remove)
  DELETE /scim/v2/Users/{id}   (soft-delete: is_active=false)

Group provisioning (Site memberships) is exposed at /scim/v2/Groups.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from db import db


# RFC 7644 §3.12 — SCIM error response envelope.
SCIM_ERROR_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:Error"


def scim_error(status: int, detail: str,
               scim_type: str | None = None) -> tuple[int, dict]:
    """Build an RFC 7644 §3.12 error response.

    Returns (http_status, body_dict). `scimType` is only set for 400-class
    errors that have a defined detail type (invalidValue, invalidSyntax,
    uniqueness, mutability, etc.); 404/500 omit it.
    """
    body: dict[str, Any] = {
        "schemas": [SCIM_ERROR_SCHEMA],
        "status": str(int(status)),
        "detail": detail,
    }
    if scim_type:
        body["scimType"] = scim_type
    return int(status), body


def authenticate_scim_request(org: dict, authorization_header: str) -> bool:
    if not authorization_header.lower().startswith("bearer "):
        return False
    token = authorization_header.split(" ", 1)[1].strip()
    expected_hash = (org or {}).get("bearer_token_hash") or ""
    if not expected_hash:
        return False
    actual = hashlib.sha256(token.encode()).hexdigest()
    return actual == expected_hash


def _to_scim_user(u: dict) -> dict:
    return {
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "id": u["id"],
        "userName": u["email"],
        "name": {"formatted": u["name"]},
        "emails": [{"value": u["email"], "primary": True}],
        "active": bool(u.get("is_active", True)),
        "externalId": u.get("employee_id"),
        "meta": {"resourceType": "User", "location": f"/scim/v2/Users/{u['id']}"},
    }


def list_users(org_id: str, start_index: int = 1, count: int = 100,
               email_filter: str | None = None) -> dict[str, Any]:
    args: list[Any] = [org_id]
    where = "where org_id = $1"
    if email_filter:
        where += " and email = $2"
        args.append(email_filter)
    rows = db.fetch_all(
        f"select id, email, name, is_active, employee_id from users {where} "
        f"order by created_at asc limit {int(count)} offset {int(start_index) - 1}",
        *args,
    )
    return {
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
        "totalResults": len(rows),
        "startIndex": start_index,
        "itemsPerPage": len(rows),
        "Resources": [_to_scim_user(r) for r in rows],
    }


def create_user(org_id: str, body: dict) -> dict:
    email = (body.get("userName") or "").lower()
    if not email:
        raise ValueError("userName required")
    name = (body.get("name", {}).get("formatted")
            or body.get("displayName")
            or email)
    employee_id = body.get("externalId")
    is_active = body.get("active", True)
    row = db.fetch_one(
        """insert into users (org_id, email, name, role, employee_id, is_active)
           values ($1, $2, $3, 'member', $4, $5) returning id, email, name, is_active, employee_id""",
        org_id, email, name, employee_id, is_active,
    )
    return _to_scim_user(row)


def replace_user(org_id: str, user_id: str, body: dict) -> dict:
    email = (body.get("userName") or "").lower()
    name = body.get("name", {}).get("formatted") or body.get("displayName") or email
    is_active = body.get("active", True)
    employee_id = body.get("externalId")
    row = db.fetch_one(
        """update users set email = $1, name = $2, is_active = $3, employee_id = $4,
                            updated_at = now()
           where id = $5 and org_id = $6
           returning id, email, name, is_active, employee_id""",
        email, name, is_active, employee_id, user_id, org_id,
    )
    if not row:
        raise LookupError("user not found")
    return _to_scim_user(row)


def patch_user(org_id: str, user_id: str, body: dict) -> dict:
    """RFC 7644 §3.5.2 supports add / remove / replace. We implement replace
    (the common Okta path) and treat add/remove on `active` as replace."""
    sets: list[str] = []
    args: list[Any] = []
    for op in body.get("Operations", []):
        path = (op.get("path") or "").lower()
        value = op.get("value")
        if path == "active" or path == "":
            v = value if isinstance(value, bool) else (value or {}).get("active")
            if v is not None:
                args.append(bool(v)); sets.append(f"is_active = ${len(args)}")
        elif path == "name.formatted":
            args.append(value); sets.append(f"name = ${len(args)}")
        elif path == "username":
            args.append(str(value).lower()); sets.append(f"email = ${len(args)}")
    if not sets:
        existing = db.fetch_one(
            "select id, email, name, is_active, employee_id from users where id = $1 and org_id = $2",
            user_id, org_id,
        )
        if not existing: raise LookupError("user not found")
        return _to_scim_user(existing)
    args.append(user_id); args.append(org_id)
    row = db.fetch_one(
        f"update users set {', '.join(sets)}, updated_at = now() "
        f"where id = ${len(args) - 1} and org_id = ${len(args)} "
        f"returning id, email, name, is_active, employee_id",
        *args,
    )
    if not row: raise LookupError("user not found")
    return _to_scim_user(row)


def deactivate_user(org_id: str, user_id: str) -> None:
    db.execute(
        "update users set is_active = false, updated_at = now() where id = $1 and org_id = $2",
        user_id, org_id,
    )

"""Cross-org isolation tests for Heads Health Platform.

Skips unless SUPABASE_URL + SUPABASE_SERVICE_KEY are set. On CI against
the staging DB they MUST pass — RLS policies for orgs/sites/users/PHI
must keep org A blind to org B even with a forged org_id in the request.
"""

from __future__ import annotations

import os
import uuid
import pytest


pytestmark = pytest.mark.skipif(
    not (os.environ.get("SUPABASE_URL") and os.environ.get("SUPABASE_SERVICE_KEY")),
    reason="Supabase test env not configured",
)


def _make_org(db, slug, name):
    rows = db.fetch_all(
        "insert into orgs (slug, legal_name, display_name) values ($1,$2,$3) returning id",
        slug, name, name,
    )
    return rows[0]["id"]


def _make_member(db, org_id, email):
    rows = db.fetch_all(
        """insert into users (org_id, email, role, name) values ($1,$2,'member','M')
           returning id""", org_id, email,
    )
    return rows[0]["id"]


def test_org_a_cannot_see_org_b_members():
    from db import db
    a = _make_org(db, f"iso-a-{uuid.uuid4().hex[:6]}", "A")
    b = _make_org(db, f"iso-b-{uuid.uuid4().hex[:6]}", "B")
    _make_member(db, b, f"hidden-{uuid.uuid4().hex[:6]}@b.com")

    leaked = db.fetch_all(
        "select id from users where org_id = $1", b,
        org_id=a, role="org_admin",
    )
    assert leaked == [], f"Org A leaked org B users: {leaked}"


def test_org_a_cannot_update_org_b_member_profile():
    from db import db
    a = _make_org(db, f"iso-c-{uuid.uuid4().hex[:6]}", "A")
    b = _make_org(db, f"iso-d-{uuid.uuid4().hex[:6]}", "B")
    m = _make_member(db, b, f"member-{uuid.uuid4().hex[:6]}@b.com")
    db.execute(
        "insert into member_profiles (user_id, org_id, age) values ($1,$2,30)",
        m, b,
    )
    affected = db.execute(
        "update member_profiles set age = 99 where user_id = $1",
        m, org_id=a, role="org_admin",
    )
    assert affected == 0, "Org A wrote to org B's PHI"

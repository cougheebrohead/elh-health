"""Sales-demo tenant provisioner.

The onboarding wizard hands a prospect's brand kit (from
fitapp_core.scrape_brand) plus a few human-edited fields. We turn
that into a fully-populated, branded org that sales can walk a buyer
through in 30 seconds.

Why a lightweight seed (4 sites · ~60 members · ~6 trainers) instead
of cloning Atlas (8 sites · 240 members):
  - Demos run < 30 minutes; nobody clicks past the third site
  - Fewer rows = faster provision (target < 5 s)
  - Easier to keep believable scale across multiple prospect demos
    on the same DB

Demos are gated by demo_password_hash and watermarked client-side as
'Sales preview — not affiliated with {brand}'. They auto-expire 30 days
out unless extended by sales.
"""

from __future__ import annotations

import hashlib
import json
import random
import re
import secrets
import string
from datetime import datetime, timedelta, timezone
from typing import Any

from auth import hash_password
from db import db


DEMO_TTL_DAYS = 30
SLUG_RE = re.compile(r"[^a-z0-9]+")


def slugify(name: str) -> str:
    """Turn 'Equinox Fitness Club' into 'equinox-fitness-club' that matches
    the orgs.slug check constraint (^[a-z0-9-]{2,60}$)."""
    s = SLUG_RE.sub("-", (name or "").lower()).strip("-")
    return s[:50] if len(s) >= 2 else "demo"


def _unique_slug(base: str) -> str:
    """Append a 6-char random suffix on collision. The suffix also doubles
    as an obscurity gate — the demo URL is `/demo/<slug>` and we don't
    want guessable slugs leaking which prospects we're pitching."""
    candidate = base
    suffix = secrets.token_urlsafe(4).lower().replace("_", "").replace("-", "")[:6]
    candidate = f"{base[:50]}-{suffix}"
    return candidate[:60]


def _safe_color(hex_str: str | None, fallback: str) -> str:
    if not hex_str:
        return fallback
    s = (hex_str or "").strip().lower()
    if re.match(r"^#[0-9a-f]{6}$", s):
        return s
    return fallback


def _gen_demo_password() -> str:
    """Memorable demo password — 4 random words from a small wordlist
    plus a number, e.g. 'iron-tide-flame-orca-7421'. Easy to read off
    a sales call, hard enough to brute-force."""
    words = (
        "iron tide flame orca echo north quartz harbor "
        "vector summit beacon vault ridge cipher prism luna "
        "atlas pulse zenith rally drift cascade keel mosaic"
    ).split()
    pick = "-".join(secrets.choice(words) for _ in range(4))
    num = secrets.randbelow(9000) + 1000
    return f"{pick}-{num}"


# ─── lightweight seed shapes ──────────────────────────────────────────

# Curated to look impressive with minimal rows. Names are generic so
# they read as plausible across any prospect — sales picks the locations
# in the wizard if they want it more specific.
_DEFAULT_SITES = [
    ("hq",      "{brand} HQ — Flagship",      "America/New_York",   "Flagship Location"),
    ("east",    "{brand} East",                "America/New_York",   "East Region"),
    ("west",    "{brand} West",                "America/Los_Angeles","West Region"),
    ("south",   "{brand} South",               "America/Chicago",    "South Region"),
]

_DEFAULT_PROGRAMS = [
    ("summer-cut",         "Summer Cut Challenge",         "campaign"),
    ("glp1-companion",     "GLP-1 Companion Program",      "combined"),
    ("strength-101",       "Strength 101 — New Members",   "workout_template"),
    ("nutrition-reset",    "14-Day Nutrition Reset",       "nutrition_template"),
]

_FIRST_NAMES = (
    "Avery Riley Jordan Casey Morgan Quinn Reese Sage Skyler Taylor "
    "Hayden Logan Parker Rowan Emerson Drew Kai Phoenix Indigo Ellis "
    "Marcus Sienna Theo Maya Kenzo Esme Wren Auden Nico Vienna"
).split()
_LAST_NAMES = (
    "Hale Reyes Okafor Torres Liang Patel Brennan Vasquez Singh Chen "
    "Walker Fischer Mendoza Alvarez Yamada Park Kowalski Nguyen Bauer "
    "Anders Whitfield Quinn Drummond Caro Bishop Tanaka"
).split()


def _fake_email(first: str, last: str, brand_slug: str) -> str:
    return f"{first.lower()}.{last.lower()}@{brand_slug}.example"


def _seed_lightweight(
    rng: random.Random,
    org_id: str,
    brand_name: str,
    brand_slug: str,
    contact_name: str | None,
) -> dict:
    """Create regions / sites / users / programs / outcomes for a demo
    org. Returns a small summary dict for the wizard's success page."""

    # Regions — one for each cardinal site
    region_ids: dict[str, str] = {}
    for slug, label in (("east","East"),("west","West"),("south","South"),("central","Central")):
        row = db.fetch_one(
            "insert into regions (org_id, slug, name) values ($1,$2,$3) returning id",
            org_id, slug, label,
        )
        if row: region_ids[slug] = row["id"]

    # Sites
    site_ids: list[str] = []
    site_names: list[str] = []
    for slug, name_tpl, tz, addr in _DEFAULT_SITES:
        site_name = name_tpl.format(brand=brand_name)
        region_slug = "east" if slug in ("hq","east") else ("west" if slug == "west" else "south")
        row = db.fetch_one(
            """insert into sites (org_id, slug, name, timezone, address, region_id, member_seat_cap)
               values ($1,$2,$3,$4,$5,$6,$7) returning id""",
            org_id, slug, site_name, tz, addr, region_ids.get(region_slug), 5000,
        )
        if row:
            site_ids.append(row["id"])
            site_names.append(site_name)

    # Org admin (the prospect's "exec" view)
    admin_first, admin_last = _split_contact(contact_name) or ("Demo", "Admin")
    admin_email = f"admin@{brand_slug}.example"
    admin_pwd = _gen_demo_password()
    db.execute(
        """insert into users (org_id, email, password_hash, role, name, is_active)
           values ($1,$2,$3,'org_admin',$4,true)""",
        org_id, admin_email, hash_password(admin_pwd), f"{admin_first} {admin_last}",
    )

    # Trainers (6) — one per region + 2 floaters
    trainer_ids: list[str] = []
    for i in range(6):
        f = rng.choice(_FIRST_NAMES); l = rng.choice(_LAST_NAMES)
        site = site_ids[i % len(site_ids)]
        row = db.fetch_one(
            """insert into users (org_id, site_id, email, password_hash, role, name, is_active)
               values ($1,$2,$3,$4,'trainer',$5,true) returning id""",
            org_id, site, _fake_email(f, l, brand_slug),
            hash_password(_gen_demo_password()),
            f"{f} {l}",
        )
        if row: trainer_ids.append(row["id"])

    # Members (60) sprinkled across sites. Demographics live in
    # member_profiles, not users — the dashboards key off counts +
    # engagement, which our lightweight seed leaves to defaults.
    member_count = 0
    for i in range(60):
        f = rng.choice(_FIRST_NAMES); l = rng.choice(_LAST_NAMES)
        site = site_ids[i % len(site_ids)]
        db.execute(
            """insert into users (org_id, site_id, email, password_hash, role, name, is_active)
               values ($1,$2,$3,$4,'member',$5,true)""",
            org_id, site, _fake_email(f"{f}{i}", l, brand_slug),
            hash_password(_gen_demo_password()),
            f"{f} {l}",
        )
        member_count += 1

    # Programs
    for slug, name, ptype in _DEFAULT_PROGRAMS:
        db.execute(
            """insert into programs (org_id, name, slug, program_type, duration_days,
                                     description, target_segment, is_org_wide)
               values ($1,$2,$3,$4,$5,$6,$7,true)""",
            org_id, name, slug, ptype, 28,
            f"{name} for {brand_name} members.",
            "glp1" if "glp1" in slug else "general",
        )

    return {
        "admin_email": admin_email,
        "admin_password": admin_pwd,
        "site_count": len(site_ids),
        "trainer_count": len(trainer_ids),
        "member_count": member_count,
        "program_count": len(_DEFAULT_PROGRAMS),
        "primary_site_name": site_names[0] if site_names else None,
    }


def _split_contact(contact: str | None) -> tuple[str, str] | None:
    if not contact:
        return None
    parts = re.split(r"[,;]", contact, maxsplit=1)[0].strip().split()
    if len(parts) >= 2:
        return parts[0], parts[-1]
    if len(parts) == 1:
        return parts[0], "Demo"
    return None


# ─── public API ───────────────────────────────────────────────────────

def provision_demo(
    *,
    brand_name: str,
    legal_name: str | None = None,
    primary_color: str | None = None,
    accent_color: str | None = None,
    logo_url: str | None = None,
    source_url: str | None = None,
    scraped_brand: dict | None = None,
    prospect_contact: str | None = None,
    sales_owner: str | None = None,
    member_count_hint: int | None = None,
    expiry_days: int = DEMO_TTL_DAYS,
) -> dict:
    """Stand up a sales demo org. Returns:
        { ok, slug, demo_url, demo_password, admin_email, admin_password,
          org_id, expires_at, watermark, summary }
    """
    if not brand_name or len(brand_name.strip()) < 2:
        return {"ok": False, "error": "brand_name is required"}

    brand_name = brand_name.strip()
    base_slug = slugify(brand_name) or "demo"

    # Always append a random suffix — same name two months apart shouldn't
    # collide and the URL stays unguessable.
    slug = _unique_slug(base_slug)
    while db.fetch_one("select id from orgs where slug = $1", slug):
        slug = _unique_slug(base_slug)

    primary = _safe_color(primary_color, "#1F2A3A")
    accent  = _safe_color(accent_color, "#0E7C66")

    demo_password = _gen_demo_password()
    demo_password_hash = hashlib.sha256(demo_password.encode()).hexdigest()
    expires_at = (datetime.now(timezone.utc) + timedelta(days=expiry_days)).isoformat()

    # Insert the org row
    org_row = db.fetch_one(
        """insert into orgs
           (slug, legal_name, display_name, logo_url, brand_primary, brand_accent,
            plan, baa_signed_at, contract_value_usd, invoicing_email,
            max_sites, max_members,
            is_demo, demo_password_hash, demo_expires_at, created_via,
            source_url, scraped_brand, prospect_contact, sales_owner)
           values ($1,$2,$3,$4,$5,$6,$7,now(),$8,$9,$10,$11,
                   true,$12,$13,'wizard',$14,$15,$16,$17)
           returning id""",
        slug,
        legal_name or brand_name,
        brand_name,
        logo_url,
        primary,
        accent,
        "enterprise_plus",
        # Plausible contract value scaled to member count hint, just so the
        # boardroom-view widget shows something believable.
        _suggested_arr(member_count_hint),
        f"ap@{slugify(brand_name)}.example",
        100, 500_000,
        demo_password_hash,
        expires_at,
        source_url,
        json.dumps(scraped_brand) if scraped_brand else None,
        prospect_contact,
        sales_owner,
    )
    if not org_row:
        return {"ok": False, "error": "org insert failed"}
    org_id = org_row["id"]

    rng = random.Random(hashlib.sha256(slug.encode()).digest())
    seed_summary = _seed_lightweight(
        rng=rng,
        org_id=org_id,
        brand_name=brand_name,
        brand_slug=slugify(brand_name),
        contact_name=prospect_contact,
    )

    return {
        "ok": True,
        "org_id": org_id,
        "slug": slug,
        "brand_name": brand_name,
        "demo_url": f"/demo/{slug}",
        "demo_password": demo_password,
        "admin_email": seed_summary["admin_email"],
        "admin_password": seed_summary["admin_password"],
        "expires_at": expires_at,
        "watermark": f"Sales preview — not affiliated with {brand_name}",
        "summary": seed_summary,
    }


def provision_customer(
    *,
    brand_name: str,
    legal_name: str | None = None,
    primary_color: str | None = None,
    accent_color: str | None = None,
    logo_url: str | None = None,
    source_url: str | None = None,
    scraped_brand: dict | None = None,
    owner_email: str,
    owner_name: str,
    plan: str = "enterprise",
    invoicing_email: str | None = None,
    contract_value_usd: float | None = None,
    custom_slug: str | None = None,
    sales_owner: str | None = None,
) -> dict:
    """Stand up a REAL paying customer (not a sales demo).

    Differences from provision_demo:
      - is_demo = false (default), no demo_password, no expiry
      - owner login uses the customer's real email + a temp password
      - one default site instead of a 4-site fake roster
      - no fake trainers, no fake members
      - returns the subdomain URL + apex fallback URL
    """
    if not brand_name or len(brand_name.strip()) < 2:
        return {"ok": False, "error": "brand_name is required"}
    if not owner_email or "@" not in owner_email:
        return {"ok": False, "error": "valid owner_email is required"}
    if plan not in ("enterprise", "enterprise_plus"):
        plan = "enterprise"

    brand_name = brand_name.strip()
    owner_email = owner_email.strip().lower()

    # Slug: prefer customer's chosen slug, otherwise derived from name.
    # Must satisfy ^[a-z0-9-]{2,60}$ on this product.
    base = (custom_slug or slugify(brand_name) or "customer").strip("-")
    base = SLUG_RE.sub("-", base.lower())[:60].strip("-")
    if len(base) < 2:
        base = "customer"

    # If slug taken, suffix until clean
    slug = base
    while db.fetch_one("select id from orgs where slug = $1", slug):
        slug = _unique_slug(base)

    primary = _safe_color(primary_color, "#1F2A3A")
    accent  = _safe_color(accent_color,  "#0E7C66")

    org_row = db.fetch_one(
        """insert into orgs
           (slug, legal_name, display_name, logo_url, brand_primary, brand_accent,
            plan, baa_signed_at, contract_value_usd, invoicing_email,
            max_sites, max_members,
            is_demo, created_via, source_url, scraped_brand, sales_owner)
           values ($1,$2,$3,$4,$5,$6,$7,now(),$8,$9,$10,$11,
                   false,'wizard-customer',$12,$13,$14)
           returning id""",
        slug,
        legal_name or brand_name,
        brand_name,
        logo_url,
        primary,
        accent,
        plan,
        contract_value_usd,
        invoicing_email or owner_email,
        100, 500_000,
        source_url,
        json.dumps(scraped_brand) if scraped_brand else None,
        sales_owner,
    )
    if not org_row:
        return {"ok": False, "error": "org insert failed"}
    org_id = org_row["id"]

    # One default site so the dashboard isn't empty
    db.execute(
        """insert into sites (org_id, slug, name, timezone, address, member_seat_cap)
           values ($1,'main',$2,'America/New_York','Main Location',5000)""",
        org_id, f"{brand_name} — Main Location",
    )

    # Owner admin with a temp password the salesperson hands to the customer
    temp_password = _gen_demo_password()
    db.execute(
        """insert into users (org_id, email, password_hash, role, name, is_active)
           values ($1,$2,$3,'org_admin',$4,true)""",
        org_id, owner_email, hash_password(temp_password), owner_name or owner_email,
    )

    return {
        "ok": True,
        "org_id": org_id,
        "slug": slug,
        "brand_name": brand_name,
        # Subdomain URL (works on Render onrender.com hosts AND on the
        # custom apex once Cloudflare Universal SSL clears for *.elhhealth.app)
        "subdomain_url": f"https://{slug}.elhhealth.app",
        # Apex-fallback URL that works on every host today
        "apex_url": f"https://elh-health.onrender.com/?org={slug}",
        "owner_email": owner_email,
        "owner_temp_password": temp_password,
        "next_steps": [
            "Text the apex_url + temp password to the customer.",
            "They sign in, change their password under Settings.",
            "Once Cloudflare wildcard SSL clears, share the subdomain_url instead.",
        ],
    }


def _suggested_arr(member_count: int | None) -> float:
    """Cheap heuristic: $0.50/MAU/mo × 12 — matches our enterprise pricing
    band so the dashboard ARR widget reads plausibly. Sales can override."""
    if not member_count or member_count <= 0:
        return 240_000.0
    return round(member_count * 0.5 * 12, 2)


# ─── demo gate verification ───────────────────────────────────────────

def verify_demo_password(slug: str, candidate: str) -> dict | None:
    """Used by the /demo/<slug> route. Returns the org row if password
    matches and the demo hasn't expired, else None."""
    if not slug or not candidate:
        return None
    org = db.fetch_one(
        """select id, slug, display_name, logo_url, brand_primary, brand_accent,
                  is_demo, demo_password_hash, demo_expires_at,
                  source_url, scraped_brand
           from orgs
           where slug = $1 and is_demo = true""",
        slug,
    )
    if not org:
        return None
    if org.get("demo_expires_at"):
        try:
            exp = datetime.fromisoformat(org["demo_expires_at"].replace("Z","+00:00"))
            if exp < datetime.now(timezone.utc):
                return None
        except (ValueError, TypeError):
            pass
    candidate_hash = hashlib.sha256(candidate.encode()).hexdigest()
    if not _const_eq(candidate_hash, org.get("demo_password_hash") or ""):
        return None
    return org


def _const_eq(a: str, b: str) -> bool:
    if len(a) != len(b):
        return False
    out = 0
    for x, y in zip(a, b):
        out |= ord(x) ^ ord(y)
    return out == 0


def list_demos(active_only: bool = True) -> list[dict]:
    """Powering the wizard's 'My Demos' table."""
    where = "where is_demo = true"
    if active_only:
        where += " and (demo_expires_at is null or demo_expires_at > now())"
    return db.fetch_all(
        f"""select id, slug, display_name, brand_primary, brand_accent, logo_url,
                   prospect_contact, sales_owner, source_url,
                   demo_expires_at::text as demo_expires_at,
                   created_at::text as created_at
            from orgs {where}
            order by created_at desc
            limit 200""",
    )


def expire_old_demos() -> int:
    """Cron entrypoint — delete demos that expired more than 7 days ago."""
    rows = db.fetch_all(
        """select id from orgs
           where is_demo = true
             and demo_expires_at is not null
             and demo_expires_at < now() - interval '7 days'""",
    )
    n = 0
    for r in rows:
        db.execute("delete from orgs where id = $1", r["id"])
        n += 1
    return n

#!/usr/bin/env python3
"""ELH Health demo seed.

Builds a believable multi-region gym chain — 'Atlas Wellness Group' —
to stand up live demos. Idempotent: re-running won't duplicate.

  Atlas Wellness Group           (org)
  ├─ Northeast region            ─ HQ NYC, Boston, DC
  ├─ Midwest region              ─ Chicago
  ├─ West region                 ─ LA, Seattle
  ├─ South region                ─ Atlanta
  └─ Texas region                ─ Austin

  6 regions · 8 sites · ~240 members · 18 trainers ·
  programs: Summer Cut, GLP-1 Companion, Postpartum Strong,
            Pre-Diabetes Reversal, Member Onboarding
"""
from __future__ import annotations

import json
import os
import random
import sys
import urllib.request
from datetime import date, datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("SUPABASE_URL", "https://skrxpiwhmafescfmlnrz.supabase.co")
os.environ.setdefault(
    "SUPABASE_SERVICE_KEY",
    open("/tmp/elhhealth_keys.env").read().split("SUPABASE_SERVICE_KEY=", 1)[1].strip(),
)

from auth import hash_password

random.seed(20260504)

URL = os.environ["SUPABASE_URL"]
KEY = os.environ["SUPABASE_SERVICE_KEY"]
HDR = {"apikey": KEY, "Authorization": f"Bearer {KEY}", "Content-Type": "application/json"}


def rpc(fn: str, q: str, p: list) -> object:
    body = json.dumps({"q": q, "p": p, "ctx": {}}).encode()
    req = urllib.request.Request(
        f"{URL}/rest/v1/rpc/{fn}", data=body, headers=HDR, method="POST",
    )
    with urllib.request.urlopen(req, timeout=20) as r:
        raw = r.read().decode()
        return json.loads(raw) if raw else None


def query(q, *p): return rpc("app_query", q, list(p)) or []
def execute(q, *p): return rpc("app_exec", q, list(p))


def upsert_org() -> str:
    rows = query("select id from orgs where slug = $1", "atlas")
    if rows:
        return rows[0]["id"]
    rows = query(
        """insert into orgs (slug, legal_name, display_name, brand_primary, brand_accent,
                             plan, baa_signed_at, baa_signer, contract_starts, contract_ends,
                             contract_term_months, contract_value_usd, invoicing_email,
                             max_sites, max_members)
           values ($1,$2,$3,$4,$5,$6,now() - interval '60 days',$7,$8,$9,$10,$11,$12,$13,$14)
           returning id""",
        "atlas", "Atlas Wellness Group, LLC", "Atlas Wellness",
        "#1F2A3A", "#0E7C66", "enterprise_plus", "Marcus Hale, CCO",
        "2026-01-01", "2027-01-01", 12, 480000.00, "ap@atlaswellness.example",
        100, 100000,
    )
    return rows[0]["id"]


REGION_DEFS = [
    ("northeast", "Northeast"),
    ("midwest",   "Midwest"),
    ("west",      "West"),
    ("south",     "South"),
    ("texas",     "Texas"),
    ("mountain",  "Mountain"),
]


def upsert_regions(org_id: str) -> dict[str, str]:
    out = {}
    for slug, name in REGION_DEFS:
        rows = query("select id from regions where org_id = $1 and slug = $2", org_id, slug)
        if rows:
            out[slug] = rows[0]["id"]; continue
        rows = query(
            "insert into regions (org_id, slug, name) values ($1,$2,$3) returning id",
            org_id, slug, name,
        )
        out[slug] = rows[0]["id"]
    return out


SITE_DEFS = [
    # (slug, name, region, tz, address)
    ("nyc",     "Atlas NYC — Flatiron",    "northeast", "America/New_York",  "120 5th Ave, New York, NY"),
    ("bos",     "Atlas Boston — Back Bay", "northeast", "America/New_York",  "500 Boylston St, Boston, MA"),
    ("dc",      "Atlas DC — Logan Circle", "northeast", "America/New_York",  "1400 14th St NW, Washington, DC"),
    ("chi",     "Atlas Chicago — Loop",    "midwest",   "America/Chicago",   "55 E Monroe St, Chicago, IL"),
    ("lax",     "Atlas LA — Santa Monica", "west",      "America/Los_Angeles","1234 Wilshire Blvd, Santa Monica, CA"),
    ("sea",     "Atlas Seattle — Capitol Hill", "west", "America/Los_Angeles","800 Pine St, Seattle, WA"),
    ("atl",     "Atlas Atlanta — Buckhead", "south",    "America/New_York",  "3200 Peachtree Rd NE, Atlanta, GA"),
    ("aus",     "Atlas Austin — Domain",    "texas",    "America/Chicago",   "11410 Century Oaks Terr, Austin, TX"),
]


def upsert_sites(org_id: str, regions: dict[str, str]) -> dict[str, str]:
    out = {}
    for slug, name, region_slug, tz, addr in SITE_DEFS:
        rows = query("select id from sites where org_id = $1 and slug = $2", org_id, slug)
        if rows:
            out[slug] = rows[0]["id"]; continue
        rows = query(
            """insert into sites (org_id, slug, name, timezone, address, region_id, member_seat_cap)
               values ($1,$2,$3,$4,$5,$6,$7) returning id""",
            org_id, slug, name, tz, addr, regions[region_slug], 1500,
        )
        out[slug] = rows[0]["id"]
    return out


# Realistic name pool
FIRST_NAMES = [
    "Aaliyah","Adrian","Alex","Alicia","Amara","Andre","Angelica","Anika","Anthony",
    "Aria","Asha","Beatriz","Brendan","Caleb","Camila","Carmen","Cassidy","Chase",
    "Chloe","Chris","Daniel","David","Devon","Diana","Diego","Dominique","Elena",
    "Eli","Elise","Emma","Erica","Ethan","Eva","Felix","Fernanda","Finn","Gabriel",
    "Gabriela","Grace","Hannah","Harper","Henry","Imani","Isabel","Isaiah","Jade",
    "James","Jamal","Janae","Jasmine","Javier","Jaya","Jenna","Jeremy","Jonas",
    "Jordan","Joseph","Joy","Julian","Kai","Kara","Kayla","Keisha","Kenji","Kira",
    "Lara","Lena","Leo","Lila","Logan","Lucas","Luna","Maddox","Maeve","Maia",
    "Marco","Maria","Mariana","Marcus","Mateo","Maya","Mia","Miles","Mira","Naomi",
    "Natalia","Niamh","Nico","Noah","Olivia","Omar","Owen","Paloma","Pedro","Priya",
    "Quinn","Rachel","Rafael","Raj","Reagan","Reece","Rhea","Ricardo","Riley","Rohan",
    "Rosa","Ryan","Sam","Sara","Selena","Serena","Shane","Simone","Sofia","Soren",
    "Tara","Tatiana","Theo","Tia","Tomas","Trent","Tyler","Uma","Valeria","Vera",
    "Victor","Violet","Wesley","Willow","Xander","Yara","Yusuf","Zara","Zion",
]
LAST_NAMES = [
    "Adams","Aguilar","Allen","Anderson","Bailey","Baker","Barnes","Bell","Bennett",
    "Brooks","Brown","Bryant","Carter","Castro","Chen","Cohen","Collins","Cooper",
    "Cox","Cruz","Davis","Diaz","Edwards","Ellis","Evans","Fischer","Foster","Garcia",
    "Gomez","Gonzalez","Graham","Gray","Green","Hall","Harris","Hayes","Henderson",
    "Hernandez","Hill","Hughes","Hunter","Ibarra","Jackson","James","Jenkins","Jensen",
    "Johnson","Jones","Kelly","Kim","King","Lee","Lewis","Lopez","Martin","Martinez",
    "Mitchell","Moore","Morgan","Morris","Murphy","Nelson","Nguyen","O'Neill","Owens",
    "Park","Parker","Patel","Pearson","Perez","Peters","Phillips","Powell","Price",
    "Ramirez","Reed","Reyes","Rivera","Roberts","Robinson","Rodriguez","Rogers","Rose",
    "Russell","Ryan","Sanchez","Sanders","Santos","Scott","Shah","Silva","Singh","Smith",
    "Stewart","Sullivan","Taylor","Thomas","Thompson","Torres","Turner","Walker","Wang",
    "Ward","Warren","Washington","Watson","Webb","Wells","White","Williams","Wilson",
    "Wood","Wright","Yang","Young","Zhang",
]
TRAINER_LASTS = [
    "Hale","Vasquez","Park","Briggs","Coleman","Adeyemi","Khan","Wright",
    "Romano","Tan","Okafor","Beltran","Foley","Singh","Becker","Ngo","Bauer","Grant",
]


def make_email(first: str, last: str, domain: str = "atlaswellness.example") -> str:
    return f"{first.lower()}.{last.lower().replace(' ','').replace(chr(39),'')}@{domain}"


def upsert_user(org_id: str, site_id: str | None, email: str, role: str,
                name: str, employee_id: str | None = None) -> str:
    rows = query("select id from users where org_id = $1 and email = $2", org_id, email)
    if rows:
        return rows[0]["id"]
    pw_hash = hash_password("Atlas-Demo-2026!")
    rows = query(
        """insert into users (org_id, site_id, email, password_hash, role, name, employee_id, last_login_at)
           values ($1,$2,$3,$4,$5,$6,$7, now() - (interval '1 hour' * $8::int))
           returning id""",
        org_id, site_id, email, pw_hash, role, name, employee_id,
        random.randint(0, 240),
    )
    return rows[0]["id"]


PROGRAM_DEFS = [
    ("summer-cut", "Summer Cut", "campaign", 56,
     "8-week recomp protocol — 18% deficit, lifting 4×/wk, daily protein floor.",
     {"calories": -18, "protein_g": 1.6, "carbs_pct": 35, "fat_pct": 25, "water_l": 3.0},
     "general"),
    ("glp1-companion", "GLP-1 Companion", "campaign", 84,
     "12-week support for members on semaglutide / tirzepatide. Muscle preservation focus.",
     {"calories": -12, "protein_g": 1.8, "carbs_pct": 30, "fat_pct": 30, "water_l": 3.5},
     "glp1"),
    ("postpartum-strong", "Postpartum Strong", "campaign", 84,
     "12-week return to training for postpartum members. Pelvic floor first.",
     {"calories": 0, "protein_g": 1.5, "carbs_pct": 45, "fat_pct": 30, "water_l": 3.0},
     "postpartum"),
    ("pre-diabetes-reversal", "Pre-Diabetes Reversal", "campaign", 168,
     "24-week clinical-grade protocol. Walking, lifting, time-restricted eating, glucose tracking.",
     {"calories": -10, "protein_g": 1.4, "carbs_pct": 30, "fat_pct": 35, "water_l": 3.0},
     "pre-diabetes"),
    ("onboarding", "Member Onboarding", "campaign", 14,
     "First 14 days. Movement, baseline biometrics, trainer pairing, app setup.",
     {"calories": 0, "protein_g": 1.4, "carbs_pct": 40, "fat_pct": 30, "water_l": 2.5},
     "general"),
]


def upsert_programs(org_id: str, creator_id: str) -> dict[str, str]:
    out = {}
    for slug, name, ptype, days, desc, nutrition, segment in PROGRAM_DEFS:
        rows = query("select id from programs where org_id = $1 and slug = $2", org_id, slug)
        if rows:
            out[slug] = rows[0]["id"]; continue
        # Build a sample 7-day workout split
        workouts = [
            {"day": d, "name": w_name, "exercises": [
                {"name": ex, "sets": 4, "reps": "6-10", "rpe": 7}
                for ex in exercises
            ]}
            for d, (w_name, exercises) in enumerate([
                ("Push", ["Bench Press", "Overhead Press", "Incline DB Press", "Tricep Pushdown"]),
                ("Pull", ["Deadlift", "Pull-up", "Barbell Row", "Face Pull"]),
                ("Legs", ["Back Squat", "Romanian DL", "Leg Press", "Calf Raise"]),
                ("Active Recovery", ["Walk 45 min", "Mobility flow", "Foam roll"]),
                ("Push", ["Incline Bench", "Lateral Raise", "Dips", "Skullcrusher"]),
                ("Pull", ["Pendlay Row", "Lat Pulldown", "Hammer Curl", "Reverse Fly"]),
                ("Legs", ["Front Squat", "Walking Lunge", "Leg Curl", "Calf Raise"]),
            ], 1)
        ]
        rows = query(
            """insert into programs
               (org_id, created_by, name, slug, program_type, duration_days, description,
                nutrition_json, workouts_json, target_segment, is_org_wide)
               values ($1,$2,$3,$4,$5,$6,$7,$8::jsonb,$9::jsonb,$10,true)
               returning id""",
            org_id, creator_id, name, slug, ptype, days, desc,
            json.dumps(nutrition), json.dumps(workouts), segment,
        )
        out[slug] = rows[0]["id"]
    return out


CONTENT_DEFS = [
    ("Why protein is the king nutrient", "article", 7, "nutrition,protein"),
    ("Sleep: the underrated training input", "article", 5, "recovery,sleep"),
    ("Walking 8k steps changed my LDL", "article", 6, "cardio,longevity"),
    ("How to read your CBC panel", "video", 9, "labs,clinical"),
    ("Mobility 101: 10-minute daily flow", "video", 10, "mobility,recovery"),
    ("GLP-1 + lifting — protect your muscle", "article", 8, "glp1,nutrition"),
    ("HRV: what it is, what it isn't", "article", 6, "recovery,wearables"),
    ("Cycle-aware training for women", "article", 8, "womens-health,training"),
]


def upsert_content(org_id: str) -> list[str]:
    ids = []
    for title, mtype, dur, tags in CONTENT_DEFS:
        existing = query(
            "select id from content_items where org_id = $1 and title = $2",
            org_id, title,
        )
        if existing:
            ids.append(existing[0]["id"]); continue
        body_md = (
            f"# {title}\n\n"
            "_(seed content — replace with your own articles or video links)_\n\n"
            "1. Why this matters.\n2. What to do.\n3. How to measure.\n"
        )
        rows = query(
            """insert into content_items
               (org_id, title, body_md, media_type, duration_min, tags)
               values ($1,$2,$3,$4,$5,$6) returning id""",
            org_id, title, body_md, mtype, dur, "{" + ",".join(tags.split(",")) + "}",
        )
        ids.append(rows[0]["id"])
    return ids


def seed_member_data(org_id: str, site_ids: dict, trainer_ids: list[str]) -> list[str]:
    """Generate ~30 members per site, distributed across trainers."""
    member_ids: list[str] = []

    # Existing members?
    existing = query(
        "select count(*)::int as n from users where org_id = $1 and role = 'member'",
        org_id,
    )
    if existing and existing[0]["n"] >= 200:
        # Already seeded; just collect ids
        rows = query(
            "select id from users where org_id = $1 and role = 'member'", org_id,
        )
        return [r["id"] for r in rows]

    target_per_site = 30
    for site_slug, site_id in site_ids.items():
        for i in range(target_per_site):
            first = random.choice(FIRST_NAMES)
            last = random.choice(LAST_NAMES)
            email = f"{first.lower()}.{last.lower()}.{site_slug}{i}@atlasmember.example"
            name = f"{first} {last}"
            user_id = upsert_user(org_id, site_id, email, "member", name)
            member_ids.append(user_id)

            # Pick a trainer at this site (round-robin from the trainer pool)
            tr = trainer_ids[(hash(site_slug + str(i)) % len(trainer_ids))]
            existing_tm = query(
                "select id from trainer_members where trainer_id = $1 and member_id = $2",
                tr, user_id,
            )
            if not existing_tm:
                execute(
                    """insert into trainer_members (org_id, site_id, trainer_id, member_id)
                       values ($1,$2,$3,$4)""",
                    org_id, site_id, tr, user_id,
                )

            # Member profile
            existing_p = query("select user_id from member_profiles where user_id = $1", user_id)
            if not existing_p:
                age = random.randint(22, 68)
                sex = random.choice(["male", "female"])
                height_cm = random.randint(155, 192)
                weight_kg = round(random.uniform(54, 115), 1)
                conditions = random.choice([
                    "", "", "", "pre-diabetes",
                    "hypertension", "anxiety", "ibs", "type-2 diabetes",
                ])
                execute(
                    """insert into member_profiles
                       (user_id, org_id, site_id, age, sex, weight_kg, height_cm, conditions, allergies_json)
                       values ($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb)""",
                    user_id, org_id, site_id, age, sex, weight_kg, height_cm, conditions,
                    json.dumps([]),
                )

            # Some recent meals + biometrics
            today = date.today()
            n_meals = random.choices([0, 3, 7, 14, 21], weights=[1, 2, 4, 6, 4])[0]
            for d_back in range(n_meals):
                day = today - timedelta(days=d_back)
                cals = random.randint(1700, 2800)
                items = [
                    {"name": "Mixed bowl", "calories": cals * 0.4, "protein": 35, "carbs": 60, "fat": 20},
                    {"name": "Snack", "calories": cals * 0.15, "protein": 12, "carbs": 18, "fat": 8},
                    {"name": "Dinner", "calories": cals * 0.45, "protein": 50, "carbs": 70, "fat": 25},
                ]
                totals = {
                    "calories": cals,
                    "protein": sum(i["protein"] for i in items),
                    "carbs":   sum(i["carbs"]   for i in items),
                    "fat":     sum(i["fat"]     for i in items),
                }
                execute(
                    """insert into meals (org_id, member_id, eaten_at, log_date, items_json, totals_json, source)
                       values ($1,$2,$3,$4,$5::jsonb,$6::jsonb,$7)""",
                    org_id, user_id,
                    (datetime.combine(day, datetime.min.time(), tzinfo=timezone.utc)
                     + timedelta(hours=12 + random.randint(-3, 5))).isoformat(),
                    day.isoformat(), json.dumps(items), json.dumps(totals),
                    random.choice(["manual", "photo", "barcode"]),
                )

            # Biometrics: weight check-ins
            for d_back in [1, 7, 14, 21, 28]:
                w = round(weight_kg - (d_back * random.uniform(-0.05, 0.15)), 1)
                execute(
                    """insert into biometrics
                       (org_id, member_id, reading_at, weight_kg, heart_rate_bpm, source)
                       values ($1,$2,$3,$4,$5,'manual')""",
                    org_id, user_id,
                    (datetime.now(timezone.utc) - timedelta(days=d_back)).isoformat(),
                    w, random.randint(56, 78),
                )

    return member_ids


def seed_engagement(org_id: str, member_ids: list[str]) -> None:
    # Delete + recompute
    execute("delete from engagement_score where org_id = $1", org_id)
    for mid in member_ids:
        # Fake but plausible engagement profile
        meals_logged = random.choices([0, 5, 12, 22, 28], weights=[1, 2, 4, 5, 3])[0]
        workouts = random.choices([0, 1, 4, 8, 12], weights=[1, 2, 4, 5, 3])[0]
        logins = random.choices([0, 5, 14, 22, 28], weights=[1, 2, 3, 4, 4])[0]
        msgs = random.choices([0, 1, 3, 8], weights=[3, 4, 4, 2])[0]
        score = min(100, int(
            (meals_logged / 30) * 30
            + (workouts / 12) * 30
            + (logins / 30) * 25
            + (msgs / 10) * 15
        ))
        if score >= 75: tier = "crushing"
        elif score >= 50: tier = "on_track"
        elif score >= 25: tier = "slipping"
        else: tier = "ghosting"
        execute(
            """insert into engagement_score
               (member_id, org_id, score, components_json, risk_tier,
                last_login_at, days_active_30)
               values ($1,$2,$3,$4::jsonb,$5,$6,$7)""",
            mid, org_id, score,
            json.dumps({"meals": meals_logged, "workouts": workouts,
                        "logins": logins, "msgs": msgs}),
            tier,
            (datetime.now(timezone.utc)
             - timedelta(days=random.randint(0, 30 if score > 25 else 60))).isoformat(),
            min(30, logins + random.randint(0, 3)),
        )


def seed_enrollments(org_id: str, member_ids: list[str], programs: dict[str, str]) -> None:
    # Distribute enrollments believably
    plan = [
        ("summer-cut", 0.30),
        ("onboarding", 0.18),
        ("glp1-companion", 0.12),
        ("postpartum-strong", 0.05),
        ("pre-diabetes-reversal", 0.10),
    ]
    today = date.today()
    for mid in member_ids:
        for slug, pct in plan:
            if random.random() < pct:
                existing = query(
                    "select id from program_enrollments where program_id = $1 and member_id = $2",
                    programs[slug], mid,
                )
                if existing: continue
                started = today - timedelta(days=random.randint(7, 60))
                ad = random.randint(20, 95)
                status = random.choices(
                    ["active", "completed", "dropped", "paused"],
                    weights=[6, 2, 1, 1],
                )[0]
                execute(
                    """insert into program_enrollments
                       (org_id, program_id, member_id, started_at, status, adherence_pct)
                       values ($1,$2,$3,$4,$5,$6)""",
                    org_id, programs[slug], mid, started.isoformat(), status, ad,
                )


def seed_messages(org_id: str, member_ids: list[str]) -> None:
    """A handful of realistic trainer↔member exchanges per member."""
    for mid in random.sample(member_ids, min(60, len(member_ids))):
        rows = query(
            """select tm.trainer_id from trainer_members tm
               where tm.member_id = $1 and tm.status = 'active' limit 1""",
            mid,
        )
        if not rows: continue
        tr = rows[0]["trainer_id"]
        existing = query(
            "select id from messages where trainer_id = $1 and member_id = $2 limit 1",
            tr, mid,
        )
        if existing: continue
        sample = [
            ("trainer", "Hey — checked your week. Strong consistency on lifts. Let's bump protein 20g."),
            ("member",  "Thx coach. Will do. Sleep was rough Tue/Wed though."),
            ("trainer", "Noted. Push HRV check via your Whoop and we'll lighten Friday if needed."),
        ]
        for who, body in sample:
            sender = tr if who == "trainer" else mid
            execute(
                """insert into messages (org_id, trainer_id, member_id, sender_id, body, sent_at)
                   values ($1,$2,$3,$4,$5, now() - (random() * interval '14 days'))""",
                org_id, tr, mid, sender, body,
            )


def main():
    print("→ org")
    org_id = upsert_org()
    print(f"  Atlas Wellness Group: {org_id}")

    print("→ regions")
    regions = upsert_regions(org_id)
    for s, i in regions.items(): print(f"  {s}: {i}")

    print("→ sites")
    sites = upsert_sites(org_id, regions)
    for s, i in sites.items(): print(f"  {s}: {i}")

    print("→ org_admin + sales_admin")
    org_admin_id = upsert_user(
        org_id, sites["nyc"], "marcus.hale@atlaswellness.example",
        "org_admin", "Marcus Hale", "EMP-1001",
    )
    print(f"  org_admin: {org_admin_id}")

    print("→ region managers")
    region_managers = {}
    for slug, name in REGION_DEFS:
        first = random.choice(FIRST_NAMES)
        last = random.choice(["Hale","Chen","Park","Briggs","Vasquez","Adeyemi"])
        email = make_email(first, last + "-" + slug)
        rid = upsert_user(org_id, None, email, "region_manager", f"{first} {last}", f"EMP-RM-{slug}")
        execute("update regions set manager_user_id = $1 where id = $2", rid, regions[slug])
        region_managers[slug] = rid

    print("→ site admins")
    site_admins = {}
    for site_slug, site_id in sites.items():
        first = random.choice(FIRST_NAMES)
        last = random.choice(TRAINER_LASTS)
        email = make_email(first, last + "-sa-" + site_slug)
        sa = upsert_user(org_id, site_id, email, "site_admin", f"{first} {last}", f"EMP-SA-{site_slug}")
        site_admins[site_slug] = sa

    print("→ trainers (≥ 2 per site)")
    trainer_ids: list[str] = []
    for site_slug, site_id in sites.items():
        for i in range(random.randint(2, 3)):
            first = random.choice(FIRST_NAMES)
            last = random.choice(TRAINER_LASTS)
            email = make_email(first, last + "-tr-" + site_slug + str(i))
            tid = upsert_user(org_id, site_id, email, "trainer", f"{first} {last}", f"EMP-TR-{site_slug}{i}")
            trainer_ids.append(tid)
    print(f"  {len(trainer_ids)} trainers")

    print("→ programs")
    programs = upsert_programs(org_id, org_admin_id)
    for s, i in programs.items(): print(f"  {s}: {i}")

    print("→ content_items")
    content_ids = upsert_content(org_id)
    print(f"  {len(content_ids)} content items")

    print("→ members + meals + biometrics  (this takes ~30s)")
    member_ids = seed_member_data(org_id, sites, trainer_ids)
    print(f"  {len(member_ids)} members")

    print("→ engagement scores")
    seed_engagement(org_id, member_ids)

    print("→ program enrollments")
    seed_enrollments(org_id, member_ids, programs)

    print("→ messages")
    seed_messages(org_id, member_ids)

    print("→ a few program outcomes (to back the population-health charts)")
    # Pick GLP-1 enrollments and write outcomes
    glp1_enrollments = query(
        """select e.id from program_enrollments e
           join programs p on p.id = e.program_id
           where p.slug = 'glp1-companion' limit 60""",
    )
    for e in glp1_enrollments:
        existing = query("select id from program_outcomes where enrollment_id = $1 limit 1", e["id"])
        if existing: continue
        for metric, vstart, vend in [
            ("weight_kg",  random.uniform(82, 110), None),
            ("hba1c",      random.uniform(5.8, 7.4), None),
            ("ldl",        random.uniform(110, 165), None),
        ]:
            delta_pct = random.uniform(-0.08, -0.02)
            vend = round(vstart * (1 + delta_pct), 2)
            vstart = round(vstart, 2)
            execute(
                """insert into program_outcomes
                   (org_id, enrollment_id, metric, value_start, value_end, delta)
                   values ($1,$2,$3,$4,$5,$6)""",
                org_id, e["id"], metric, vstart, vend, round(vend - vstart, 2),
            )

    print()
    print("──────────────────────────────────────────────")
    print(f"DEMO ORG: Atlas Wellness ({org_id})")
    print(f"DEMO ADMIN: marcus.hale@atlaswellness.example / Atlas-Demo-2026!")
    print(f"  Sites:    {len(sites)}")
    print(f"  Regions:  {len(regions)}")
    print(f"  Trainers: {len(trainer_ids)}")
    print(f"  Members:  {len(member_ids)}")
    print(f"  Programs: {len(programs)}")
    print("──────────────────────────────────────────────")


if __name__ == "__main__":
    main()

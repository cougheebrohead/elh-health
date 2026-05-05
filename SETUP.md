# ELH Health — production setup

## 1. Apply migrations

ELH Health Supabase project: **`skrxpiwhmafescfmlnrz`**.

```bash
export DATABASE_URL='postgres://postgres:<DB_PASSWORD>@db.skrxpiwhmafescfmlnrz.supabase.co:5432/postgres'
psql "$DATABASE_URL" -f migrations/0001_init.sql
psql "$DATABASE_URL" -f migrations/0002_app_query_rpc.sql
psql "$DATABASE_URL" -f migrations/0003_rls_policies.sql
```

## 2. Deploy on Render

`render.yaml` is ready. Either:

- **Dashboard:** https://dashboard.render.com/blueprint/new → connect
  `cougheebrohead/elhhealth`. Add envs from `.env.example`.
- **CLI:** `render login && render services create blueprint render.yaml`.

## 3. DNS

Apex `elhhealth.app` and wildcard `*.elhhealth.app` to the Render service.

## 4. SSO — finish the SAML signature validator before going live

`sso.saml_assert_callback` intentionally raises `NotImplementedError`
until the X.509 signature validation is implemented against the per-org
cert. Wire `signxml` (or equivalent) before any SSO assertion is trusted.
This is a hard gate: the unsigned path will not issue a session.

## 5. First org (manual, for the demo)

Once migrations are applied, create a demo org:

```sql
insert into orgs (slug, legal_name, display_name)
values ('demo', 'Demo Health Co.', 'Demo Health');

insert into users (org_id, email, password_hash, role, name)
select id, 'admin@demo.example', '<pbkdf2_sha256$...>', 'org_admin', 'Demo Admin'
from orgs where slug = 'demo';
```

The password hash can be generated locally:

```bash
python3 -c "from auth import hash_password; print(hash_password('your-password'))"
```

## 6. Pilot rollout

For the first 1–3 customers:

1. They send IdP metadata + SCIM bearer token (we hash + store).
2. We provision their org, sites, and initial admins.
3. They run a 30-member pilot for 4–8 weeks.
4. After the pilot, they sign the annual MSA (`/legal/MSA-template.docx`,
   not yet committed).

## 7. Compliance milestones (planned dates from contract calendar)

- **2026-Q3:** SOC 2 Type II audit (first observation period closes 2026-11-01)
- **2026-Q3:** External pentest by a specialist firm
- **2026-Q3:** First BAA execution with pilot customer

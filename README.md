# ELH Health

Enterprise health platform. Multi-site tenancy, SSO, SCIM, audit-chained
PHI access, BAA-ready.

Sells direct (no Stripe Checkout). Pricing: $8 / member / month for the
Enterprise tier; Enterprise Plus is custom.

## Architecture

- `orgs` are customers (gym chains, clinics, telehealth practices)
- `sites` are physical locations or virtual cohorts under an org
- `users` are scoped to an org, optionally to a default site, with one of
  four roles: `org_admin`, `site_admin`, `trainer`, `member`
- Every PHI table is RLS-locked by org_id + site_id + role context
- Every PHI read inserts an audit row with a SHA-256 chain digest
- SSO via SAML 2.0 (Okta, Azure AD, Google) and OIDC
- SCIM 2.0 inbound user provisioning with per-org bearer auth

Built on `fitapp-core` for nutrition, cycle, glucose primitives.

## Local

```bash
cp .env.example .env
pip install -r requirements.txt
python server.py
```

## Migrations

```bash
psql "$DATABASE_URL" -f migrations/0001_init.sql
psql "$DATABASE_URL" -f migrations/0002_app_query_rpc.sql
psql "$DATABASE_URL" -f migrations/0003_rls_policies.sql
```

## Tests

```bash
pytest tests/
```

Cross-org isolation tests in `tests/test_isolation.py` are blocking on CI.

## Production

- Hosting: Render (Oregon)
- DB: Supabase (project `skrxpiwhmafescfmlnrz`)
- DNS: Cloudflare for `elhhealth.app` + wildcard `*.elhhealth.app`
- Email: Resend
- Errors: Sentry

## SSO setup checklist (per Org)

1. Customer IT exports IdP metadata (SAML) or registers OIDC client.
2. ELH Health admin pastes IdP entity ID, SSO URL, and X.509 cert into
   `orgs` row.
3. Test SP-initiated login at `https://{slug}.elhhealth.app/api/sso/login`.
4. (Optional) Set `sso_required=true` to disable password fallback.

## SCIM setup

1. Customer IT generates a SCIM bearer in their IdP.
2. ELH Health admin pastes its SHA-256 hash into `scim_config` row +
   sets `enabled=true`.
3. Customer IT configures the IdP SCIM endpoint to
   `https://{slug}.elhhealth.app/scim/v2/`.

-- Same CTE-wrapper fix as CoachHQ but keyed on org_id/site_id GUCs.

create or replace function app_query(
    q text,
    p jsonb default '[]'::jsonb,
    ctx jsonb default '{}'::jsonb
) returns setof jsonb
language plpgsql
security definer
set search_path = public
as $$
declare
    rec record;
    oid text := ctx->>'org_id';
    uid text := ctx->>'user_id';
    rol text := ctx->>'role';
    sid text := ctx->>'site_id';
begin
    if oid is not null then perform set_config('app.org_id',    oid, true); end if;
    if uid is not null then perform set_config('app.user_id',   uid, true); end if;
    if rol is not null then perform set_config('app.user_role', rol, true); end if;
    if sid is not null then perform set_config('app.site_id',   sid, true); end if;

    if jsonb_array_length(p) = 0 then
        for rec in execute 'with q as (' || q || ') select to_jsonb(q.*) as j from q' loop
            return next rec.j;
        end loop;
    else
        for rec in execute 'with q as (' || q || ') select to_jsonb(q.*) as j from q'
            using p->>0, p->>1, p->>2, p->>3, p->>4,
                  p->>5, p->>6, p->>7, p->>8, p->>9
        loop
            return next rec.j;
        end loop;
    end if;
end;
$$;

create or replace function app_exec(
    q text,
    p jsonb default '[]'::jsonb,
    ctx jsonb default '{}'::jsonb
) returns int
language plpgsql
security definer
set search_path = public
as $$
declare
    n int;
    oid text := ctx->>'org_id';
    uid text := ctx->>'user_id';
    rol text := ctx->>'role';
    sid text := ctx->>'site_id';
begin
    if oid is not null then perform set_config('app.org_id',    oid, true); end if;
    if uid is not null then perform set_config('app.user_id',   uid, true); end if;
    if rol is not null then perform set_config('app.user_role', rol, true); end if;
    if sid is not null then perform set_config('app.site_id',   sid, true); end if;

    if jsonb_array_length(p) = 0 then
        execute q;
    else
        execute q using
            p->>0, p->>1, p->>2, p->>3, p->>4,
            p->>5, p->>6, p->>7, p->>8, p->>9;
    end if;
    get diagnostics n = ROW_COUNT;
    return n;
end;
$$;

revoke all on function app_query(text, jsonb, jsonb) from anon, authenticated, public;
revoke all on function app_exec (text, jsonb, jsonb) from anon, authenticated, public;
grant execute on function app_query(text, jsonb, jsonb) to service_role;
grant execute on function app_exec (text, jsonb, jsonb) to service_role;

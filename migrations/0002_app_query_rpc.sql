-- App-layer RPC, identical pattern to CoachHQ but tenant-keyed by org_id.
-- The ctx passed in carries org_id, user_id, role, site_id so RLS in 0003
-- can enforce the org→site→trainer→member hierarchy.

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
    result jsonb;
    oid text := ctx->>'org_id';
    uid text := ctx->>'user_id';
    rol text := ctx->>'role';
    sid text := ctx->>'site_id';
begin
    if oid is not null then perform set_config('app.org_id',   oid, true); end if;
    if uid is not null then perform set_config('app.user_id',  uid, true); end if;
    if rol is not null then perform set_config('app.user_role', rol, true); end if;
    if sid is not null then perform set_config('app.site_id',  sid, true); end if;

    if jsonb_array_length(p) = 0 then
        for result in execute q loop return next result; end loop;
    else
        execute 'select jsonb_agg(row_to_json(t)) from (' || q || ') t'
            into result
            using
                p->>0, p->>1, p->>2, p->>3, p->>4,
                p->>5, p->>6, p->>7, p->>8, p->>9;
        if result is null then return; end if;
        for result in select * from jsonb_array_elements(result) loop return next result; end loop;
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
    if oid is not null then perform set_config('app.org_id',   oid, true); end if;
    if uid is not null then perform set_config('app.user_id',  uid, true); end if;
    if rol is not null then perform set_config('app.user_role', rol, true); end if;
    if sid is not null then perform set_config('app.site_id',  sid, true); end if;

    if jsonb_array_length(p) = 0 then
        execute q;
    else
        execute q
            using
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

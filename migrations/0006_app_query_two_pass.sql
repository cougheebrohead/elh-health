-- Two-pass substitution to handle $-chars inside values (PBKDF2 hashes etc).

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
    final text := q;
    v text;
    i int;
    n int := jsonb_array_length(p);
    oid text := ctx->>'org_id';
    uid text := ctx->>'user_id';
    rol text := ctx->>'role';
    sid text := ctx->>'site_id';
begin
    if oid is not null then perform set_config('app.org_id',    oid, true); end if;
    if uid is not null then perform set_config('app.user_id',   uid, true); end if;
    if rol is not null then perform set_config('app.user_role', rol, true); end if;
    if sid is not null then perform set_config('app.site_id',   sid, true); end if;

    for i in reverse n - 1 .. 0 loop
        final := regexp_replace(final, '\$' || (i + 1)::text || '(?!\d)',
                                ':__a_' || (i + 1)::text || '_b__', 'g');
    end loop;
    for i in 0 .. n - 1 loop
        v := case jsonb_typeof(p->i)
                when 'null'    then 'NULL'
                when 'number'  then (p->>i)
                when 'boolean' then (p->>i)
                else                quote_literal(p->>i)
             end;
        final := replace(final, ':__a_' || (i + 1)::text || '_b__', v);
    end loop;

    for rec in execute 'with q as (' || final || ') select to_jsonb(q.*) as j from q' loop
        return next rec.j;
    end loop;
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
    rows_n int;
    final text := q;
    v text;
    i int;
    n int := jsonb_array_length(p);
    oid text := ctx->>'org_id';
    uid text := ctx->>'user_id';
    rol text := ctx->>'role';
    sid text := ctx->>'site_id';
begin
    if oid is not null then perform set_config('app.org_id',    oid, true); end if;
    if uid is not null then perform set_config('app.user_id',   uid, true); end if;
    if rol is not null then perform set_config('app.user_role', rol, true); end if;
    if sid is not null then perform set_config('app.site_id',   sid, true); end if;

    for i in reverse n - 1 .. 0 loop
        final := regexp_replace(final, '\$' || (i + 1)::text || '(?!\d)',
                                ':__a_' || (i + 1)::text || '_b__', 'g');
    end loop;
    for i in 0 .. n - 1 loop
        v := case jsonb_typeof(p->i)
                when 'null'    then 'NULL'
                when 'number'  then (p->>i)
                when 'boolean' then (p->>i)
                else                quote_literal(p->>i)
             end;
        final := replace(final, ':__a_' || (i + 1)::text || '_b__', v);
    end loop;

    execute final;
    get diagnostics rows_n = ROW_COUNT;
    return rows_n;
end;
$$;

revoke all on function app_query(text, jsonb, jsonb) from anon, authenticated, public;
revoke all on function app_exec (text, jsonb, jsonb) from anon, authenticated, public;
grant execute on function app_query(text, jsonb, jsonb) to service_role;
grant execute on function app_exec (text, jsonb, jsonb) to service_role;

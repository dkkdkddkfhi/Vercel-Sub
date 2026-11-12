-- Sub Panel database schema for Supabase/PostgreSQL
-- Safe to run more than once. The service-role key is used by the API.

create extension if not exists pgcrypto;

create table if not exists public.users (
  id uuid primary key default gen_random_uuid(),
  username text not null,
  pass_hash text not null,
  salt text not null default '',
  role text not null default 'user' check (role in ('admin', 'user')),
  created_at timestamptz not null default now()
);

create unique index if not exists users_username_lower_uq
  on public.users (lower(username));

create table if not exists public.sessions (
  token text primary key,
  user_id uuid not null references public.users(id) on delete cascade,
  expires_at timestamptz not null,
  created_at timestamptz not null default now()
);

create index if not exists sessions_user_id_idx on public.sessions (user_id);
create index if not exists sessions_expires_at_idx on public.sessions (expires_at);

create table if not exists public.sections (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references public.users(id) on delete cascade,
  title text not null default '',
  content text not null default '',
  sub_key text,
  slug text,
  expires_at timestamptz,
  sort_no integer not null default 0,
  created_at timestamptz not null default now()
);

-- Upgrade older installations without deleting existing data.
alter table public.users add column if not exists salt text not null default '';
alter table public.users add column if not exists role text not null default 'user';
alter table public.users add column if not exists created_at timestamptz not null default now();
alter table public.sessions add column if not exists created_at timestamptz not null default now();
alter table public.sections add column if not exists slug text;
alter table public.sections add column if not exists expires_at timestamptz;
alter table public.sections add column if not exists sort_no integer not null default 0;
alter table public.sections add column if not exists created_at timestamptz not null default now();

create unique index if not exists sections_sub_key_uq
  on public.sections (sub_key) where sub_key is not null;
create unique index if not exists sections_slug_uq
  on public.sections (slug) where slug is not null;
create index if not exists sections_user_sort_idx
  on public.sections (user_id, sort_no, created_at);

-- Enforce the per-user limit in the database as well as in the API.
-- The advisory lock makes the count safe when two inserts arrive together.
create or replace function public.enforce_sections_limit()
returns trigger
language plpgsql
as $$
begin
  perform pg_advisory_xact_lock(hashtextextended(NEW.user_id::text, 0));
  if (select count(*) from public.sections where user_id = NEW.user_id) >= 200 then
    raise exception 'section_limit_reached' using errcode = 'check_violation';
  end if;
  return NEW;
end;
$$;

drop trigger if exists sections_limit_before_insert on public.sections;
create trigger sections_limit_before_insert
before insert on public.sections
for each row execute function public.enforce_sections_limit();

-- The API uses the server-side service-role key. Keep direct client access closed.
alter table public.users enable row level security;
alter table public.sessions enable row level security;
alter table public.sections enable row level security;

-- Create the first-login account only when it does not already exist.
insert into public.users (username, pass_hash, salt, role)
select 'admin', 'DEFAULT', '', 'admin'
where not exists (
  select 1 from public.users where lower(username) = 'admin'
);

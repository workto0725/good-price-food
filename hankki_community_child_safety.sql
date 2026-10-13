begin;

-- 사용자별 차단 목록. 관리자가 하는 작성 제한과 별도로, 각 사용자가 직접 관리합니다.
create table if not exists public.hankki_community_user_blocks(
  blocker_id uuid not null references auth.users(id) on delete cascade,
  blocked_user_id uuid not null references auth.users(id) on delete cascade,
  blocked_nickname text not null default '' check(char_length(blocked_nickname)<=20),
  created_at timestamptz not null default now(),
  primary key(blocker_id,blocked_user_id),
  check(blocker_id<>blocked_user_id)
);

-- 작성자 신고와 게시물 신고를 분리해 관리합니다.
create table if not exists public.hankki_community_user_reports(
  id uuid primary key default gen_random_uuid(),
  reporter_id uuid not null references auth.users(id) on delete cascade,
  reported_user_id uuid not null references auth.users(id) on delete cascade,
  post_id uuid not null references public.hankki_community_posts(id) on delete cascade,
  reason text not null check(char_length(reason) between 3 and 500),
  resolved boolean not null default false,
  created_at timestamptz not null default now(),
  unique(reporter_id,reported_user_id,post_id),
  check(reporter_id<>reported_user_id)
);

alter table public.hankki_community_user_blocks enable row level security;
alter table public.hankki_community_user_reports enable row level security;
revoke all on public.hankki_community_user_blocks,public.hankki_community_user_reports from anon,authenticated;

drop policy if exists own_user_blocks_read on public.hankki_community_user_blocks;
create policy own_user_blocks_read on public.hankki_community_user_blocks
  for select to authenticated using(blocker_id=auth.uid());
drop policy if exists own_user_blocks_add on public.hankki_community_user_blocks;
create policy own_user_blocks_add on public.hankki_community_user_blocks
  for insert to authenticated with check(blocker_id=auth.uid() and blocker_id<>blocked_user_id);
drop policy if exists own_user_blocks_remove on public.hankki_community_user_blocks;
create policy own_user_blocks_remove on public.hankki_community_user_blocks
  for delete to authenticated using(blocker_id=auth.uid());
grant select,insert,delete on public.hankki_community_user_blocks to authenticated;

drop policy if exists read_user_reports on public.hankki_community_user_reports;
create policy read_user_reports on public.hankki_community_user_reports
  for select to authenticated using(reporter_id=auth.uid() or public.hankki_is_admin());
drop policy if exists send_user_reports on public.hankki_community_user_reports;
create policy send_user_reports on public.hankki_community_user_reports
  for insert to authenticated with check(
    reporter_id=auth.uid()
    and reporter_id<>reported_user_id
    and exists(
      select 1 from public.hankki_community_posts p
      where p.id=post_id and p.author_id=reported_user_id and p.status='published'
    )
  );
grant select on public.hankki_community_user_reports to authenticated;
grant insert(reporter_id,reported_user_id,post_id,reason) on public.hankki_community_user_reports to authenticated;

-- 서버에서도 차단한 작성자의 공개 글이 차단한 사용자에게 노출되지 않도록 합니다.
create or replace function public.hankki_is_user_blocked(p_author uuid)
returns boolean language sql stable security definer set search_path=''
as $$
  select auth.uid() is not null and exists(
    select 1 from public.hankki_community_user_blocks b
    where b.blocker_id=auth.uid() and b.blocked_user_id=p_author
  )
$$;
revoke all on function public.hankki_is_user_blocked(uuid) from public;
grant execute on function public.hankki_is_user_blocked(uuid) to anon,authenticated;

drop policy if exists public_posts on public.hankki_community_posts;
create policy public_posts on public.hankki_community_posts
  for select to anon,authenticated
  using(status='published' and not public.hankki_is_user_blocked(author_id));

create or replace function public.hankki_resolve_user_report(p_id uuid)
returns void language plpgsql security definer set search_path=''
as $$
begin
  if not public.hankki_is_admin() then raise exception 'ADMIN_ONLY'; end if;
  update public.hankki_community_user_reports set resolved=true where id=p_id;
  if not found then raise exception 'REPORT_NOT_FOUND'; end if;
  insert into public.hankki_community_audit(actor,action,target)
    values(auth.uid(),'resolve_user_report',p_id);
end
$$;
revoke all on function public.hankki_resolve_user_report(uuid) from public;
grant execute on function public.hankki_resolve_user_report(uuid) to authenticated;

commit;

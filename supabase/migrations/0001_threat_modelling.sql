-- Design review records. Scores are operator-assessed, not a security certification.
create function touch_updated() returns trigger language plpgsql as $$begin new.updated_at=clock_timestamp(); return new; end$$;
create function append_only() returns trigger language plpgsql as $$begin raise exception 'Evidence is append-only'; end$$;
create function bump_revision() returns trigger language plpgsql as $$begin update models set revision=revision+1 where id=coalesce(new.model_id,old.model_id); return coalesce(new,old); end$$;
create table models (id uuid primary key default gen_random_uuid(), created_at timestamptz not null default now(), updated_at timestamptz not null default now(), code text not null unique, name text not null, owner text not null default '', scope text not null default '', next_review date, revision integer not null default 1, source jsonb not null default '{}');
create trigger models_updated before update on models for each row execute function touch_updated();
alter table models enable row level security;
revoke all on models from public;
create table zones (id uuid primary key default gen_random_uuid(), created_at timestamptz not null default now(), updated_at timestamptz not null default now(), model_id uuid not null references models(id), code text not null, name text not null, trust_level numeric(5,2) check(trust_level between 0 and 100), source jsonb not null default '{}', unique(model_id,code), unique(model_id,id));
create trigger zones_updated before update on zones for each row execute function touch_updated();
alter table zones enable row level security;
revoke all on zones from public;
create table components (id uuid primary key default gen_random_uuid(), created_at timestamptz not null default now(), updated_at timestamptz not null default now(), model_id uuid not null references models(id), code text not null, name text not null, kind text not null, zone_id uuid, source jsonb not null default '{}', foreign key(model_id,zone_id) references zones(model_id,id), unique(model_id,code), unique(model_id,id));
create trigger components_updated before update on components for each row execute function touch_updated();
alter table components enable row level security;
revoke all on components from public;
create table flows (id uuid primary key default gen_random_uuid(), created_at timestamptz not null default now(), updated_at timestamptz not null default now(), model_id uuid not null references models(id), code text not null, name text not null, source_id uuid not null, target_id uuid not null, data_description text not null default '', protocol text not null default '', bidirectional boolean not null default false, source jsonb not null default '{}', foreign key(model_id,source_id) references components(model_id,id), foreign key(model_id,target_id) references components(model_id,id), unique(model_id,code), unique(model_id,id));
create trigger flows_updated before update on flows for each row execute function touch_updated();
alter table flows enable row level security;
revoke all on flows from public;
create table threats (id uuid primary key default gen_random_uuid(), created_at timestamptz not null default now(), updated_at timestamptz not null default now(), model_id uuid not null references models(id), code text not null, name text not null, component_id uuid, flow_id uuid, category text not null default 'unclassified', likelihood numeric(5,2) check(likelihood between 0 and 100), impact numeric(5,2) check(impact between 0 and 100), owner text not null default '', due_on date, state text not null default 'open' check(state in ('open','closed')), rationale text not null default '', source jsonb not null default '{}', check((component_id is null) <> (flow_id is null)), foreign key(model_id,component_id) references components(model_id,id), foreign key(model_id,flow_id) references flows(model_id,id), unique(model_id,code), unique(model_id,id));
create trigger threats_updated before update on threats for each row execute function touch_updated();
alter table threats enable row level security;
revoke all on threats from public;
create table controls (id uuid primary key default gen_random_uuid(), created_at timestamptz not null default now(), updated_at timestamptz not null default now(), model_id uuid not null references models(id), threat_id uuid not null, code text not null, name text not null, owner text not null default '', due_on date, source jsonb not null default '{}', foreign key(model_id,threat_id) references threats(model_id,id), unique(threat_id,code), unique(model_id,id));
create trigger controls_updated before update on controls for each row execute function touch_updated();
alter table controls enable row level security;
revoke all on controls from public;
create table verifications (id uuid primary key default gen_random_uuid(), created_at timestamptz not null default now(), updated_at timestamptz not null default now(), model_id uuid not null references models(id), control_id uuid not null, verified boolean not null, actor text not null check(length(trim(actor))>0), evidence text not null check(length(trim(evidence))>0), note text not null, verified_on date not null check(verified_on<=current_date), foreign key(model_id,control_id) references controls(model_id,id));
create trigger verifications_updated before update on verifications for each row execute function touch_updated();
alter table verifications enable row level security;
revoke all on verifications from public;
create table acceptances (id uuid primary key default gen_random_uuid(), created_at timestamptz not null default now(), updated_at timestamptz not null default now(), model_id uuid not null references models(id), threat_id uuid not null, actor text not null check(length(trim(actor))>0), reason text not null check(length(trim(reason))>0), evidence text not null check(length(trim(evidence))>0), expires_on date not null, foreign key(model_id,threat_id) references threats(model_id,id));
create trigger acceptances_updated before update on acceptances for each row execute function touch_updated();
alter table acceptances enable row level security;
revoke all on acceptances from public;
create table reviews (id uuid primary key default gen_random_uuid(), created_at timestamptz not null default now(), updated_at timestamptz not null default now(), model_id uuid not null references models(id), revision integer not null, actor text not null check(length(trim(actor))>0), evidence text not null check(length(trim(evidence))>0), note text not null, next_review date not null);
create trigger reviews_updated before update on reviews for each row execute function touch_updated();
alter table reviews enable row level security;
revoke all on reviews from public;
create table activity (id uuid primary key default gen_random_uuid(), created_at timestamptz not null default now(), updated_at timestamptz not null default now(), model_id uuid not null references models(id), actor text not null, action text not null, detail jsonb not null);
create trigger activity_updated before update on activity for each row execute function touch_updated();
alter table activity enable row level security;
revoke all on activity from public;
create table imports (id uuid primary key default gen_random_uuid(), created_at timestamptz not null default now(), updated_at timestamptz not null default now(), model_id uuid not null references models(id), sha256 text not null unique, original_json text not null, filename text not null, actor text not null, report jsonb not null);
create trigger imports_updated before update on imports for each row execute function touch_updated();
alter table imports enable row level security;
revoke all on imports from public;
create trigger zones_revision after insert or update or delete on zones for each row execute function bump_revision();
create index zones_model_idx on zones(model_id);
create trigger components_revision after insert or update or delete on components for each row execute function bump_revision();
create index components_model_idx on components(model_id);
create trigger flows_revision after insert or update or delete on flows for each row execute function bump_revision();
create index flows_model_idx on flows(model_id);
create trigger threats_revision after insert or update or delete on threats for each row execute function bump_revision();
create index threats_model_idx on threats(model_id);
create trigger controls_revision after insert or update or delete on controls for each row execute function bump_revision();
create index controls_model_idx on controls(model_id);
create trigger verifications_revision after insert or update or delete on verifications for each row execute function bump_revision();
create index verifications_model_idx on verifications(model_id);
create trigger acceptances_revision after insert or update or delete on acceptances for each row execute function bump_revision();
create index acceptances_model_idx on acceptances(model_id);
create trigger verifications_immutable before update or delete on verifications for each row execute function append_only();
create trigger acceptances_immutable before update or delete on acceptances for each row execute function append_only();
create trigger reviews_immutable before update or delete on reviews for each row execute function append_only();
create trigger activity_immutable before update or delete on activity for each row execute function append_only();
create trigger imports_immutable before update or delete on imports for each row execute function append_only();

create unique index model_code_case on models(lower(code));
create view control_desk as
 select c.*, t.code as threat_code, m.code as model, coalesce(v.verified,false) as verified, v.actor as verifier, v.evidence, v.verified_on,
 case when coalesce(v.verified,false) then 'verified' when c.due_on<current_date then 'overdue' else 'needs evidence' end as attention
 from controls c join threats t on t.id=c.threat_id join models m on m.id=c.model_id
 left join lateral (select * from verifications v where v.control_id=c.id order by v.created_at desc,v.id desc limit 1) v on true;
create view threat_desk as
 select t.*, m.code as model, coalesce(c.name,f.name) as surface,
 round(t.likelihood*t.impact/100.0,1) as score,
 (select count(*)::integer from control_desk d where d.threat_id=t.id) as controls,
 (select count(*)::integer from control_desk d where d.threat_id=t.id and not d.verified) as unverified,
 a.expires_on as acceptance_expires, a.actor as accepted_by,
 case when t.state='closed' then 'closed' when a.expires_on>=current_date and a.created_at>=t.updated_at then 'accepted' else 'open' end as disposition
 from threats t join models m on m.id=t.model_id left join components c on c.id=t.component_id left join flows f on f.id=t.flow_id
 left join lateral (select * from acceptances a where a.threat_id=t.id order by a.created_at desc,a.id desc limit 1) a on true;
create view boundary_desk as
 select f.id,f.model_id,m.code as model,f.code,f.name,s.name as source_component,d.name as target_component,
 zs.name as source_zone,zt.name as target_zone,f.protocol,f.data_description,f.bidirectional,
 case when s.zone_id is null or d.zone_id is null then 'unknown zone' when s.zone_id<>d.zone_id then 'crosses boundary' else 'same zone' end as boundary,
 (select count(*)::integer from threats t where t.flow_id=f.id) as threats
 from flows f join models m on m.id=f.model_id join components s on s.id=f.source_id join components d on d.id=f.target_id
 left join zones zs on zs.id=s.zone_id left join zones zt on zt.id=d.zone_id;
create view review_desk as
 select m.id,m.code,m.name,m.owner,m.scope,m.revision,m.next_review,r.revision as reviewed_revision,r.actor as reviewer,
 case when r.id is null then 'never reviewed' when r.revision<>m.revision then 'changed since review' when m.next_review<current_date then 'review overdue' else 'current review' end as attention,
 (select count(*)::integer from threat_desk t where t.model_id=m.id and t.disposition='open') as open_threats,
 (select count(*)::integer from threat_desk t where t.model_id=m.id and t.score>=60 and t.disposition='open') as high_open
 from models m left join lateral(select * from reviews r where r.model_id=m.id order by r.created_at desc,r.id desc limit 1) r on true;
revoke all on control_desk,threat_desk,boundary_desk,review_desk from public;

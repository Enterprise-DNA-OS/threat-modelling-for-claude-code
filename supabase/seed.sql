
insert into models(id,code,name,owner,scope,next_review) values
 ('10000000-0000-4000-8000-000000000001','DEMO-PORTAL','Customer portal','Mira Chen','Synthetic customer records and document uploads',current_date-3),
 ('10000000-0000-4000-8000-000000000002','DEMO-BATCH','Nightly export','Arun Singh','Synthetic account export to an internal review folder',current_date+7) on conflict do nothing;
insert into zones(id,model_id,code,name,trust_level) values
 ('20000000-0000-4000-8000-000000000001','10000000-0000-4000-8000-000000000001','PUBLIC','Public internet',0),
 ('20000000-0000-4000-8000-000000000002','10000000-0000-4000-8000-000000000001','PRIVATE','Private service',80) on conflict do nothing;
insert into components(id,model_id,code,name,kind,zone_id) values
 ('30000000-0000-4000-8000-000000000001','10000000-0000-4000-8000-000000000001','BROWSER','Customer browser','client','20000000-0000-4000-8000-000000000001'),
 ('30000000-0000-4000-8000-000000000002','10000000-0000-4000-8000-000000000001','API','Portal service','service','20000000-0000-4000-8000-000000000002'),
 ('30000000-0000-4000-8000-000000000003','10000000-0000-4000-8000-000000000001','STORE','Document store','storage','20000000-0000-4000-8000-000000000002'),
 ('30000000-0000-4000-8000-000000000004','10000000-0000-4000-8000-000000000002','EXPORT','Export worker','service',null) on conflict do nothing;
insert into flows(id,model_id,code,name,source_id,target_id,data_description,protocol) values
 ('40000000-0000-4000-8000-000000000001','10000000-0000-4000-8000-000000000001','UPLOAD','Document upload','30000000-0000-4000-8000-000000000001','30000000-0000-4000-8000-000000000002','Customer files','HTTPS'),
 ('40000000-0000-4000-8000-000000000002','10000000-0000-4000-8000-000000000001','READ','Document retrieval','30000000-0000-4000-8000-000000000002','30000000-0000-4000-8000-000000000003','Private document contents','') on conflict do nothing;
insert into threats(id,model_id,code,name,flow_id,component_id,category,likelihood,impact,owner,due_on,rationale) values
 ('50000000-0000-4000-8000-000000000001','10000000-0000-4000-8000-000000000001','T-ACCESS','Another account reads private files',null,'30000000-0000-4000-8000-000000000002','Information Disclosure',80,90,'Arun Singh',current_date-4,'Synthetic workshop assessment'),
 ('50000000-0000-4000-8000-000000000002','10000000-0000-4000-8000-000000000001','T-UPLOAD','Oversized upload exhausts capacity','40000000-0000-4000-8000-000000000001',null,'Denial of Service',70,60,'Mira Chen',current_date+2,'Synthetic workshop assessment'),
 ('50000000-0000-4000-8000-000000000003','10000000-0000-4000-8000-000000000002','T-EXPORT','Export permission is unclear',null,'30000000-0000-4000-8000-000000000004','Information Disclosure',null,null,'',null,'Needs a workshop') on conflict do nothing;
insert into controls(id,model_id,threat_id,code,name,owner,due_on) values
 ('60000000-0000-4000-8000-000000000001','10000000-0000-4000-8000-000000000001','50000000-0000-4000-8000-000000000001','C-ACCOUNT','Check account ownership on each read','Arun Singh',current_date-2),
 ('60000000-0000-4000-8000-000000000002','10000000-0000-4000-8000-000000000001','50000000-0000-4000-8000-000000000002','C-SIZE','Reject oversized uploads','Mira Chen',current_date+2) on conflict do nothing;
insert into acceptances(id,model_id,threat_id,actor,reason,evidence,expires_on) values
 ('70000000-0000-4000-8000-000000000001','10000000-0000-4000-8000-000000000001','50000000-0000-4000-8000-000000000002','Demo risk owner','Temporary synthetic exception','demo://EXCEPTION-01',current_date-1) on conflict do nothing;

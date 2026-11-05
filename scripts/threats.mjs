#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';
import {createHash,randomUUID} from 'node:crypto';
import {pathToFileURL} from 'node:url';
import {getDb,REPO_ROOT} from './lib/db.mjs';
import {table} from './lib/format.mjs';

export const commands={
 help:'List commands and flags',models:'Read every model and review state','update-model':'Set model scope, owner and review date','set-component-zone':'Assign the reviewed component zone','set-flow-context':'Record protocol and data for a flow','assign-control':'Assign a control owner and due date',model:'Read one model and its evidence',
 'trust-boundaries':'Review flows crossing trust zones','threat-register':'Read threat scores and dispositions',
 'control-queue':'Read controls still needing verification','review-due':'Read stale and overdue design reviews',
 'acceptance-expiry':'Review expired or soon-expiring risk decisions',attention:'Read overdue work and evidence gaps',
 compliance:'Check design-review evidence against documented rules',activity:'Read the recorded activity',
 'add-model':'Create a scoped model','add-zone':'Record a trust zone','add-component':'Record a system component',
 'add-flow':'Record data movement','add-threat':'Record an assessed design threat','add-control':'Assign a mitigation',
 'assess-threat':'Record likelihood, impact and ownership','verify-control':'Record a completed verification',
 'invalidate-control':'Record failed or outdated verification','close-threat':'Close only after verified controls',
 'accept-risk':'Record a time-limited authorised risk decision','review-model':'Record review evidence for this revision',
 'log-note':'Record a workshop or progress note',import:'Import an IriusRisk OTM JSON export',export:'Write a complete private JSON snapshot',
 'weekly-review':'Draft a review from three current reports','draft-treatment':'Draft a threat treatment sheet','draft-review':'Draft a model review brief'
};
export const flags={
 help:[],models:[],'update-model':['model','name','owner','scope','due','actor'],'set-component-zone':['model','component','zone','actor'],'set-flow-context':['model','flow','data','protocol','actor'],'assign-control':['model','control','owner','due','actor'],model:['model'],'trust-boundaries':['model'],'threat-register':['model'],'control-queue':['model'],
 'review-due':['model'],'acceptance-expiry':['model'],attention:['model'],compliance:['model'],activity:['model'],
 'add-model':['code','name','owner','scope','due','actor'],'add-zone':['model','code','name','trust','actor'],
 'add-component':['model','code','name','kind','zone','actor'],'add-flow':['model','code','name','source','target','data','protocol','bidirectional','actor'],
 'add-threat':['model','code','name','component','flow','category','likelihood','impact','owner','due','rationale','actor'],
 'add-control':['model','threat','code','name','owner','due','actor'],'assess-threat':['model','threat','likelihood','impact','owner','due','rationale','actor'],
 'verify-control':['model','control','evidence','date','note','actor'],'invalidate-control':['model','control','evidence','date','note','actor'],
 'close-threat':['model','threat','reason','actor'],'accept-risk':['model','threat','expires','reason','evidence','actor'],
 'review-model':['model','evidence','note','next','actor'],'log-note':['model','note','actor'],import:['file','dry-run','actor'],
 export:['file'],'weekly-review':['model'],'draft-treatment':['model','threat'],'draft-review':['model']
};
export function parse(argv){
 const a=[...argv],c=a.shift()||'help',f={};
 if(c==='import'&&a[0]==='iriusrisk')a.shift();
 for(const x of a){if(!x.startsWith('--'))throw Error('Flags must use --name=value');const i=x.indexOf('=');const k=x.slice(2,i<0?undefined:i);if(k in f)throw Error('Duplicate flag: '+k);f[k]=i<0?true:x.slice(i+1);}
 return {c:c==='--help'?'help':c,f};
}
const required=(f,k)=>{if(typeof f[k]!=='string'||!f[k].trim())throw Error('Required --'+k+'=value');return f[k].trim();};
export function date(s){if(typeof s!=='string'||!/^\d{4}-\d{2}-\d{2}$/.test(s)||!Number.isFinite(Date.parse(s+'T00:00:00Z'))||new Date(s+'T00:00:00Z').toISOString().slice(0,10)!==s)throw Error('Expected valid ISO date YYYY-MM-DD');return s;}
const today=()=>new Date().toISOString().slice(0,10);
const future=s=>{s=date(s);if(s<today())throw Error('Date must be today or later');return s;};
const score=s=>{if(!/^\d+(?:\.\d{1,2})?$/.test(String(s))||Number(s)<0||Number(s)>100)throw Error('Score must be 0 to 100 with at most two decimals');return Number(s);};
const text=(s,what)=>{if(typeof s!=='string'||!s.trim())throw Error(what+' must be nonempty text');return s;};
const object=(o,what)=>{if(!o||typeof o!=='object'||Array.isArray(o))throw Error(what+' must be an object');return o;};
const serial=x=>JSON.stringify(x);
async function insert(db,name,values){const keys=Object.keys(values);return (await db.query(`insert into ${name}(${keys.join(',')}) values (${keys.map((_,i)=>'$'+(i+1)).join(',')}) returning *`,Object.values(values)))[0];}
async function resolve(db,name,q,modelId){
 if(!q||q===true)throw Error('Choose a '+name+' reference');
 const rows=await db.query(`select * from ${name}${modelId?' where model_id=$1':''}`,modelId?[modelId]:[]);
 const v=String(q).toLowerCase();const exact=rows.filter(r=>[r.id,r.code].some(x=>String(x).toLowerCase()===v));
 const hits=exact.length?exact:rows.filter(r=>r.id.startsWith(v)||r.code.toLowerCase().includes(v)||r.name.toLowerCase().includes(v));
 if(hits.length!==1)throw Error(hits.length?'Ambiguous '+name+': '+hits.map(r=>r.code+' '+r.name+' ['+r.id+']').join('; '):'No match for '+name+': '+q);
 return hits[0];
}
async function audit(db,m,actor,action,detail){await insert(db,'activity',{model_id:m,actor,action,detail:serial(detail)});}
async function withTransaction(db,fn){await db.exec('BEGIN');try{const r=await fn();await db.exec('COMMIT');return r;}catch(e){await db.exec('ROLLBACK');throw e;}}
const readSql={
 models:'select code,name,owner,revision,reviewed_revision,next_review,attention,open_threats,high_open from review_desk',
 'trust-boundaries':'select model,code,source_component,target_component,source_zone,target_zone,boundary,protocol,data_description,threats from boundary_desk',
 'threat-register':'select model,code,name,surface,score,owner,due_on,disposition,controls,unverified,acceptance_expires from threat_desk',
 'control-queue':"select model,code,name,threat_code,owner,due_on,attention from control_desk where not verified",
 'review-due':"select code,name,owner,next_review,revision,reviewed_revision,attention from review_desk where attention<>'current review'",
 'acceptance-expiry':"select model,code,name,accepted_by,acceptance_expires,disposition from threat_desk where acceptance_expires<=current_date+30",
 activity:'select model_id,actor,action,detail,created_at from activity'
};
async function evidenceGaps(db,modelId){
 const rows=[];const add=(m,ref,rule,detail)=>rows.push({model:m,reference:ref,rule,detail});
 const ms=await db.query('select * from review_desk'+(modelId?' where id=$1':''),modelId?[modelId]:[]);
 for(const m of ms){
  if(!m.owner||!m.scope)add(m.code,m.code,'scope-owner','Record the model scope and responsible owner');
  if(!m.next_review)add(m.code,m.code,'review-date','Set the next design review date');
  if(m.attention!=='current review')add(m.code,m.code,'review-current',m.attention);
  const cs=await db.query('select * from components where model_id=$1',[m.id]);
  if(!cs.length)add(m.code,m.code,'design-inventory','Record the system components');
  for(const c of cs)if(!c.zone_id)add(m.code,c.code,'trust-zone','Component has no recorded trust zone');
  for(const f of await db.query('select * from boundary_desk where model_id=$1',[m.id])){
   if(!f.protocol||!f.data_description)add(m.code,f.code,'flow-context','Record the protocol and data moved');
   if(f.boundary!=='same zone'&&!f.threats)add(m.code,f.code,'boundary-review','No threat assessment recorded for this boundary flow');
  }
  for(const t of await db.query('select * from threat_desk where model_id=$1',[m.id])){
   if(t.score===null||!t.rationale)add(m.code,t.code,'risk-assessment','Record likelihood, impact and assessment rationale');
   if(!t.owner||!t.due_on)add(m.code,t.code,'treatment-owner','Record a threat owner and review date');
   if(t.acceptance_expires&&String(t.acceptance_expires)<today()&&t.state!=='closed')add(m.code,t.code,'acceptance-expired','Risk acceptance has expired');
   if(t.state==='closed'&&(t.controls===0||t.unverified>0))add(m.code,t.code,'closure-evidence','Closed threat lacks verified mitigation evidence');
   if(t.disposition==='open'&&t.score>=60)add(m.code,t.code,'high-open','High assessed risk remains open');
  }
  for(const c of await db.query('select * from control_desk where model_id=$1',[m.id])){
   if(!c.owner||!c.due_on)add(m.code,c.code,'control-owner','Record a control owner and due date');
   if(!c.verified)add(m.code,c.code,'control-evidence','Control has no current verification evidence');
  }
 }
 return rows;
}
const allTables=['models','zones','components','flows','threats','controls','verifications','acceptances','reviews','activity','imports'];
export async function run(db,c,f={}){
 if(!Object.hasOwn(commands,c))throw Error('Unknown command: '+c);
 for(const k of Object.keys(f))if(k!=='json'&&!flags[c].includes(k))throw Error('Unknown flag --'+k+' for '+c);
 for(const k of ['json','dry-run','bidirectional'])if(k in f&&f[k]!==true)throw Error('--'+k+' is a boolean flag');
 if(c==='help')return Object.entries(commands).map(([command,purpose])=>({command,purpose,flags:flags[command].map(k=>'--'+k).join(' ')}));
 const m=f.model?await resolve(db,'models',f.model):null;
 if(readSql[c]){
  if(!m)return db.query(readSql[c]+' order by 1,2');
  const sql=readSql[c];const condition=['models','review-due'].includes(c)?'id':'model_id';
  return db.query(sql+(sql.includes(' where ')?' and ':' where ')+condition+'=$1 order by 1,2',[m.id]);
 }
 if(c==='model'){
  if(!m)throw Error('Required --model=value');const result={model:m};
  for(const t of allTables.slice(1))result[t]=await db.query('select * from '+t+' where model_id=$1 order by created_at,id',[m.id]);
  return result;
 }
 if(c==='compliance'||c==='attention'){
  const gaps=await evidenceGaps(db,m?.id);
  if(c==='attention')for(const t of await db.query("select * from threat_desk where disposition='open' and due_on<current_date"+(m?' and model_id=$1':''),m?[m.id]:[]))gaps.push({model:t.model,reference:t.code,rule:'overdue-threat',detail:'Recorded treatment date has passed'});
  return gaps;
 }
 if(c==='export'){
  const file=path.resolve(required(f,'file'));const out={format:'threat-modelling-snapshot-v1',exported_at:new Date().toISOString(),tables:{}};
  await db.exec('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY');try{for(const t of allTables)out.tables[t]=await db.query('select * from '+t+' order by created_at,id');}finally{await db.exec('ROLLBACK');}
  fs.mkdirSync(path.dirname(file),{recursive:true,mode:0o700});fs.writeFileSync(file,serial(out)+'\n',{flag:'wx',mode:0o600});return {file,records:Object.values(out.tables).reduce((n,a)=>n+a.length,0)};
 }
 if(['weekly-review','draft-review','draft-treatment'].includes(c)){
  let title,sections;
  if(c==='weekly-review'){title='Weekly design review';sections={reviews:await run(db,'review-due',f),threats:await run(db,'threat-register',f),controls:await run(db,'control-queue',f)};}
  else if(c==='draft-review'){if(!m)throw Error('Required --model=value');title='Review brief: '+m.name;sections={model:m,gaps:await evidenceGaps(db,m.id),boundaries:await run(db,'trust-boundaries',{model:m.id})};}
  else{if(!m)throw Error('Required --model=value');const t=await resolve(db,'threats',required(f,'threat'),m.id);title='Treatment sheet: '+t.name;sections={threat:t,controls:await db.query('select * from control_desk where threat_id=$1',[t.id])};}
  const dir=path.resolve(process.env.OUTPUT_DIR||REPO_ROOT,'drafts');fs.mkdirSync(dir,{recursive:true,mode:0o700});const file=path.join(dir,c+'-'+randomUUID()+'.md');
  fs.writeFileSync(file,'# '+title+'\n\nInternal draft for human review. No notification or security approval has been sent.\n\n'+Object.entries(sections).map(([k,v])=>'## '+k+'\n\n```json\n'+JSON.stringify(v,null,2)+'\n```').join('\n\n')+'\n',{flag:'wx',mode:0o600});return {file};
 }
 if(c==='import')return importOtm(db,f);
 const actor=required(f,'actor');
 return withTransaction(db,async()=>{
  if(c==='add-model'){
   const r=await insert(db,'models',{code:required(f,'code'),name:required(f,'name'),owner:required(f,'owner'),scope:required(f,'scope'),next_review:date(required(f,'due'))});await audit(db,r.id,actor,c,{id:r.id});return r;
  }
  if(!m)throw Error('Required --model=value');
  // Serialise decisions within a model so evidence cannot change mid-closure or review.
  const locked=(await db.query('select * from models where id=$1 for update',[m.id]))[0];
  let r;
  if(c==='update-model')r=(await db.query('update models set name=$1,owner=$2,scope=$3,next_review=$4,revision=revision+1 where id=$5 returning *',[required(f,'name'),required(f,'owner'),required(f,'scope'),date(required(f,'due')),m.id]))[0];
  else if(c==='set-component-zone'){const x=await resolve(db,'components',required(f,'component'),m.id),z=await resolve(db,'zones',required(f,'zone'),m.id);r=(await db.query('update components set zone_id=$1 where id=$2 returning *',[z.id,x.id]))[0];}
  else if(c==='set-flow-context'){const x=await resolve(db,'flows',required(f,'flow'),m.id);r=(await db.query('update flows set data_description=$1,protocol=$2 where id=$3 returning *',[required(f,'data'),required(f,'protocol'),x.id]))[0];}
  else if(c==='assign-control'){const x=await resolve(db,'controls',required(f,'control'),m.id);r=(await db.query('update controls set owner=$1,due_on=$2 where id=$3 returning *',[required(f,'owner'),date(required(f,'due')),x.id]))[0];}
  else if(c==='add-zone')r=await insert(db,'zones',{model_id:m.id,code:required(f,'code'),name:required(f,'name'),trust_level:score(required(f,'trust'))});
  else if(c==='add-component'){const z=f.zone?await resolve(db,'zones',f.zone,m.id):null;r=await insert(db,'components',{model_id:m.id,code:required(f,'code'),name:required(f,'name'),kind:required(f,'kind'),zone_id:z?.id||null});}
  else if(c==='add-flow'){
   const s=await resolve(db,'components',required(f,'source'),m.id),t=await resolve(db,'components',required(f,'target'),m.id);
   r=await insert(db,'flows',{model_id:m.id,code:required(f,'code'),name:required(f,'name'),source_id:s.id,target_id:t.id,data_description:required(f,'data'),protocol:required(f,'protocol'),bidirectional:!!f.bidirectional});
  }else if(c==='add-threat'){
   if(!!f.component===!!f.flow)throw Error('Choose exactly one --component or --flow');
   const surface=await resolve(db,f.component?'components':'flows',f.component||f.flow,m.id);
   r=await insert(db,'threats',{model_id:m.id,code:required(f,'code'),name:required(f,'name'),component_id:f.component?surface.id:null,flow_id:f.flow?surface.id:null,category:required(f,'category'),likelihood:score(required(f,'likelihood')),impact:score(required(f,'impact')),owner:required(f,'owner'),due_on:date(required(f,'due')),rationale:required(f,'rationale')});
  }else if(c==='add-control'){
   const t=await resolve(db,'threats',required(f,'threat'),m.id);if(t.state==='closed')throw Error('Threat is closed');
   r=await insert(db,'controls',{model_id:m.id,threat_id:t.id,code:required(f,'code'),name:required(f,'name'),owner:required(f,'owner'),due_on:date(required(f,'due'))});
  }else if(c==='assess-threat'){
   const t=await resolve(db,'threats',required(f,'threat'),m.id);if(t.state==='closed')throw Error('Threat is closed');
   r=(await db.query('update threats set likelihood=$1,impact=$2,owner=$3,due_on=$4,rationale=$5 where id=$6 returning *',[score(required(f,'likelihood')),score(required(f,'impact')),required(f,'owner'),date(required(f,'due')),required(f,'rationale'),t.id]))[0];
  }else if(c==='verify-control'||c==='invalidate-control'){
   const ctrl=await resolve(db,'controls',required(f,'control'),m.id);const d=date(required(f,'date'));if(d>today())throw Error('Verification date cannot be in the future');
   const last=(await db.query('select * from verifications where control_id=$1 order by created_at desc,id desc limit 1',[ctrl.id]))[0];if(last&&d<String(last.verified_on))throw Error('Verification date precedes latest evidence');
   r=await insert(db,'verifications',{model_id:m.id,control_id:ctrl.id,verified:c==='verify-control',actor,evidence:required(f,'evidence'),note:required(f,'note'),verified_on:d});
   if(c==='invalidate-control')await db.query("update threats set state='open' where id=$1 and state='closed'",[ctrl.threat_id]);
  }else if(c==='close-threat'){
   const t=await resolve(db,'threats',required(f,'threat'),m.id);if(t.state==='closed')throw Error('Threat is already closed');
   const cs=await db.query('select * from control_desk where threat_id=$1',[t.id]);if(!cs.length||cs.some(x=>!x.verified))throw Error('Closure requires at least one control and verification evidence for every control');
   required(f,'reason');if(t.likelihood===null||t.impact===null||!t.rationale)throw Error('Assess the threat before closure');
   r=(await db.query("update threats set state='closed' where id=$1 returning *",[t.id]))[0];
  }else if(c==='accept-risk'){
   const t=await resolve(db,'threats',required(f,'threat'),m.id);if(t.state==='closed')throw Error('Threat is closed');if(t.likelihood===null||t.impact===null||!t.rationale)throw Error('Assess the threat before accepting risk');
   r=await insert(db,'acceptances',{model_id:m.id,threat_id:t.id,actor,reason:required(f,'reason'),evidence:required(f,'evidence'),expires_on:future(required(f,'expires'))});
  }else if(c==='review-model'){
   required(f,'evidence');required(f,'note');
   r=await insert(db,'reviews',{model_id:m.id,revision:locked.revision,actor,evidence:f.evidence,note:f.note,next_review:future(required(f,'next'))});await db.query('update models set next_review=$1 where id=$2',[r.next_review,m.id]);
  }else if(c==='log-note')r={note:required(f,'note')};
  else throw Error('Unsupported command');
  await audit(db,m.id,actor,c,{...f,json:undefined,result:r});return r;
 });
}

function validateOtm(raw){
 const o=object(JSON.parse(raw),'OTM');if(!['0.1.0','0.2.0'].includes(o.otmVersion))throw Error('Supported OTM versions: 0.1.0 and 0.2.0');
 object(o.project,'project');text(o.project.id,'project.id');text(o.project.name,'project.name');for(const k of ['owner','description'])if(o.project[k]!=null&&typeof o.project[k]!=='string')throw Error('project.'+k+' must be text');
 const map={};
 for(const key of ['trustZones','components','dataflows','threats','mitigations','assets']){
  if(o[key]!=null&&!Array.isArray(o[key]))throw Error(key+' must be an array');
  const entries=o[key]||[];map[key]=new Map();
  for(const e of entries){object(e,key);text(e.id,key+'.id');text(e.name,key+'.name');if(map[key].has(e.id))throw Error('Duplicate '+key+' id '+e.id);map[key].set(e.id,e);}
 }
 const ref=(key,id)=>{if(!map[key].has(id))throw Error('Unknown '+key+' reference '+id);};
 for(const z of map.trustZones.values()){if(z.risk?.trustRating!=null)score(z.risk.trustRating);if(z.parent?.trustZone)ref('trustZones',z.parent.trustZone);}
 const visiting=new Set(),visited=new Set();
 const visit=id=>{if(visiting.has(id))throw Error('Component parent cycle');if(visited.has(id))return;visiting.add(id);const c=map.components.get(id);if(c.parent?.component){ref('components',c.parent.component);visit(c.parent.component);}visiting.delete(id);visited.add(id);};
 for(const c of map.components.values()){text(c.type,'component.type');if(c.parent?.trustZone)ref('trustZones',c.parent.trustZone);if(c.parent?.component&&c.parent?.trustZone)throw Error('Component has two parents');visit(c.id);}
 for(const f of map.dataflows.values()){ref('components',f.source);if(f.destination&&f.target&&f.destination!==f.target)throw Error('Conflicting flow target and destination');ref('components',f.destination??f.target);if(f.bidirectional!=null&&typeof f.bidirectional!=='boolean')throw Error('bidirectional must be boolean');}
 for(const t of map.threats.values()){if(t.risk?.likelihood!=null)score(t.risk.likelihood);if(t.risk?.impact!=null)score(t.risk.impact);}
 for(const surface of [...map.components.values(),...map.dataflows.values()]){
  if(surface.threats!=null&&!Array.isArray(surface.threats))throw Error('Threat instances must be an array');
  const seen=new Set();for(const ti of surface.threats||[]){ref('threats',ti.threat);if(seen.has(ti.threat))throw Error('Duplicate threat instance');seen.add(ti.threat);
   if(ti.mitigations!=null&&!Array.isArray(ti.mitigations))throw Error('Mitigation instances must be an array');
   const sm=new Set();for(const mi of ti.mitigations||[]){ref('mitigations',mi.mitigation);if(sm.has(mi.mitigation))throw Error('Duplicate mitigation instance');sm.add(mi.mitigation);}
  }
 }
 return {o,map};
}
async function importOtm(db,f){
 const file=path.resolve(required(f,'file')),actor=required(f,'actor');const raw=fs.readFileSync(file,'utf8');const {o,map}=validateOtm(raw);const hash=createHash('sha256').update(raw).digest('hex');
 return withTransaction(db,async()=>{
  const old=(await db.query('select * from imports where sha256=$1',[hash]))[0];if(old)return {already_imported:true,model_id:old.model_id};
  if((await db.query('select id from models where lower(code)=lower($1)',[o.project.id])).length)throw Error('Existing model cannot be overwritten. Import a separate project version with a distinct project id.');
  const report={model:o.project.id,components:map.components.size,flows:map.dataflows.size,threats:0,controls:0,warnings:['Original OTM payload retained. Imported control states are unverified. Review source-only definitions, assets, nested zones, diagram layout and custom attributes in the original payload. No vendor threat-generation library is imported.']};
  for(const s of [...map.components.values(),...map.dataflows.values()])for(const t of s.threats||[]){report.threats++;report.controls+=(t.mitigations||[]).length;}
  if(f['dry-run'])return {...report,dry_run:true};
  const m=await insert(db,'models',{code:o.project.id,name:o.project.name,owner:typeof o.project.owner==='string'?o.project.owner:'',scope:o.project.description||'',source:serial(o.project)});
  const zones=new Map(),components=new Map();
  for(const z of map.trustZones.values()){const r=await insert(db,'zones',{model_id:m.id,code:z.id,name:z.name,trust_level:z.risk?.trustRating??null,source:serial(z)});zones.set(z.id,r.id);}
  const zoneFor=c=>c.parent?.trustZone?zones.get(c.parent.trustZone):c.parent?.component?zoneFor(map.components.get(c.parent.component)):null;
  for(const c of map.components.values()){const r=await insert(db,'components',{model_id:m.id,code:c.id,name:c.name,kind:c.type,zone_id:zoneFor(c),source:serial(c)});components.set(c.id,r.id);}
  async function instances(surface,id,kind){
   for(const ti of surface.threats||[]){const d=map.threats.get(ti.threat);const t=await insert(db,'threats',{model_id:m.id,code:kind+':'+surface.id+':'+ti.threat,name:d.name,component_id:kind==='component'?id:null,flow_id:kind==='flow'?id:null,category:Array.isArray(d.categories)?d.categories.join(', '):'unclassified',likelihood:d.risk?.likelihood??null,impact:d.risk?.impact??null,rationale:[d.risk?.likelihoodComment,d.risk?.impactComment].filter(Boolean).join(' / '),source:serial({definition:d,instance:ti})});
    for(const mi of ti.mitigations||[]){const md=map.mitigations.get(mi.mitigation);await insert(db,'controls',{model_id:m.id,threat_id:t.id,code:mi.mitigation,name:md.name,source:serial({definition:md,instance:mi})});}
   }
  }
  for(const c of map.components.values())await instances(c,components.get(c.id),'component');
  for(const f of map.dataflows.values()){const r=await insert(db,'flows',{model_id:m.id,code:f.id,name:f.name,source_id:components.get(f.source),target_id:components.get(f.destination??f.target),data_description:f.description||'',protocol:'',bidirectional:f.bidirectional||false,source:serial(f)});await instances(f,r.id,'flow');}
  await insert(db,'imports',{model_id:m.id,sha256:hash,original_json:raw,filename:path.basename(file),actor,report:serial(report)});await audit(db,m.id,actor,'import',report);return report;
 });
}
export function human(value){
 if(Array.isArray(value)){if(!value.length)return '(none)';return table(value,Object.keys(value[0]).map(key=>({key,label:key,width:key==='detail'||key==='name'?65:35,format:v=>v===null?'unknown':typeof v==='object'?serial(v):String(v)})));}
 return JSON.stringify(value,null,2);
}
if(process.argv[1]&&import.meta.url===pathToFileURL(path.resolve(process.argv[1])).href){
 let db;try{const {c,f}=parse(process.argv.slice(2));db=await getDb();const out=await run(db,c,f);console.log(f.json?JSON.stringify(out):human(out));}
 catch(e){console.error(e.message);process.exitCode=1;}finally{if(db)await db.close();}
}

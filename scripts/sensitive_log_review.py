"""Read-only sensitive-information review over the completed, guarded stage-three delivery."""
import argparse,collections,hashlib,json,re,sys
from pathlib import Path
from datetime import datetime,timezone
ROOT=Path(__file__).resolve().parents[1]
PRIOR=ROOT/'outputs/agent_log_motive_completion_20260924'
OUT=ROOT/'outputs/agent_log_sensitive_review_20260924'
def read(p):
 return [json.loads(x) for x in Path(p).read_text(encoding='utf-8-sig').splitlines() if x.strip()]
def write(p,v):Path(p).write_text(json.dumps(v,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
def lines(p,rows):Path(p).write_text(''.join(json.dumps(x,ensure_ascii=False)+'\n' for x in rows),encoding='utf-8')
def now():return datetime.now(timezone.utc).isoformat()
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
# Deliberately broad retrieval, never a disclosure classifier.
TARGET=re.compile(r'(?i)redact|saniti[sz]|obfuscat|mask(?:ed|ing)?|password|passwd|secret|credential|api.?key|authorization|cookie|\btoken\b|access.?token|refresh.?token|bearer|\bPII\b|personal|sensitive|\bemail\b|\bphone\b|private.?key|session.?id|user.?id|client.?ip|ip.?address|request.?body|response.?body|payload|http.?header|\bheaders\b|process\.env|os\.environ')
PURPOSE=re.compile(r'(?i)redact|saniti[sz]|obfuscat|sensitive|privacy|\bPII\b|credential|password|api.?key|secret|hide.{0,35}(?:log|output)|(?:log|output).{0,35}(?:hide|sensitive|leak)|leak.{0,35}(?:log|credential|secret)')
CARRIER=re.compile(r'(?i)\b(?:body|payload|request|response|config|headers|transcript|content|environment)\b|JSON\.stringify|json\.dumps|\b(?:url|uri|path|directory)\b')
HIDE=re.compile(r'(?i)redact|saniti[sz]|mask|obfuscat|suppress|hide|remove.{0,40}(?:log|output|print)|delete.{0,40}(?:log|output|print)')
SAFE_LITERALS={'[REDACTED]','[redacted]','<redacted>','***','****','*****','******','[MASKED]','REDACTED','redacted','', 'utf-8','utf8'}
def redact(text,code=False):
 text=text or ''
 text=re.sub(r'-----BEGIN [^-]*(?:PRIVATE KEY|CERTIFICATE)-----.*?-----END [^-]+-----','<REDACTED_KEY_BLOCK>',text,flags=re.S)
 text=re.sub(r'\b(?:sk-[A-Za-z0-9_-]{12,}|gh[pousr]_[A-Za-z0-9]{12,}|github_pat_[A-Za-z0-9_]{12,}|AKIA[A-Z0-9]{16})\b','<REDACTED_CREDENTIAL>',text)
 text=re.sub(r'\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b','<REDACTED_JWT>',text)
 text=re.sub(r'(?i)\b(?:Bearer|Basic)\s+[A-Za-z0-9+/=_\-.]{8,}','<REDACTED_AUTH>',text)
 text=re.sub(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b','<REDACTED_EMAIL>',text)
 text=re.sub(r'\b(?:\d{1,3}\.){3}\d{1,3}\b','<REDACTED_IP>',text)
 text=re.sub(r'(?<!\w)(?:\+?\d[\d ()-]{8,}\d)(?!\w)','<REDACTED_NUMERIC_VALUE>',text)
 text=re.sub(r'[A-Za-z][A-Za-z0-9+.-]*://[^\s"\x27`]+','<REDACTED_URL>',text)
 text=re.sub(r'(?:/Users/|/home/)[^\s"\x27`]+','<REDACTED_USER_PATH>',text)
 text=re.sub(r'(?i)(cloud\s+name\s*:)\s*\S+',r'\1 <REDACTED_RESOURCE>',text)
 text=re.sub(r'\S{8,}',lambda m:'<REDACTED_MIXED_TOKEN>' if re.search('[A-Za-z]',m.group()) and re.search('[0-9]',m.group()) else m.group(),text)
 text=re.sub(r'(?i)((?:password|passwd|api[_ -]?key|access[_ -]?token|refresh[_ -]?token|secret|authorization)\s*[:=]\s*)([^\s,;]+)',r'\1<REDACTED_VALUE>',text)
 # Mask quoted literals in code, preserving syntax identifiers outside quotes.
 if code:
  text=re.sub(r'(["\x27])(?:\\.|(?!\1)[^\\\n])*?\1',lambda m:m.group(0) if m.group(0)[1:-1] in SAFE_LITERALS else m.group(1)+'<LITERAL>'+m.group(1),text)
 text=re.sub(r'\b(?=[A-Za-z0-9_+/=-]{28,}\b)(?=[A-Za-z0-9_+/=-]*[A-Za-z])(?=[A-Za-z0-9_+/=-]*[0-9])[A-Za-z0-9_+/=-]+\b','<REDACTED_OPAQUE>',text)
 return text

def load():
 guard=json.loads((OUT/'guard_receipt.json').read_text());assert guard['checks']=={'allowed':829} and guard['unique_events']==1757
 events=read(PRIOR/'delivery/log_modification_reviews.jsonl');sources={x['evidence_id']:x for x in read(PRIOR/'delivery/motive_evidence.jsonl')}
 edges=collections.defaultdict(list)
 for x in read(PRIOR/'delivery/evidence_links.jsonl'):edges[x['modification_id']].append(x)
 contexts={x['modification_id']:x for x in read(PRIOR/'contexts.jsonl')}
 return events,sources,edges,contexts

def inventory():
 events,sources,edges,contexts=load();screen=[];selected=[]
 for e in events:
  mid=e['modification_id'];obs=e['current_observation'];target='\n'.join([obs.get('before_statement') or '',obs.get('after_statement') or ''])
  target_hit=bool(TARGET.search(target));pids=sorted({l['evidence_id'] for l in edges[mid] if PURPOSE.search(sources[l['evidence_id']]['text'])})
  deleted=bool(obs.get('before_statement') and not obs.get('after_statement'))
  carrier_deleted=deleted and bool(CARRIER.search(target));hide_ids=sorted({eid for eid in pids if HIDE.search(sources[eid]['text'])})
  reasons=(['target_sensitive_or_carrier_term'] if target_hit else [])+(['linked_material_mentions_sensitive_purpose'] if pids else [])+(['removed_record_with_carrier_expression'] if carrier_deleted else [])
  row={'modification_id':mid,'repository':e['repository'],'modification_sha':e['modification_sha'],'file_path':e['file_path'],'selected':bool(reasons),'retrieval_reasons':reasons,
       'source_match_ids':pids,'hiding_source_ids':hide_ids,'target_match':target_hit,'upstream_after_empty':deleted,'target_observation':obs['classification'],
       'prior_motive_status':e['motive_status'],'prior_motive_labels':e['motive_labels'],'review_state':'pending' if reasons else 'not_selected','sensitivity_status':None}
  screen.append(row)
  if reasons:selected.append(row)
 selected.sort(key=lambda r:(0 if r['hiding_source_ids'] and r['target_match'] else 1 if r['target_match'] else 2 if r['hiding_source_ids'] else 3,r['repository'],r['modification_sha'],r['modification_id']))
 # Commit-diverse pilot, followed by all other candidates. No selection is a label.
 pilot=[];seen=collections.Counter()
 for r in selected:
  key=(r['repository'],r['modification_sha'])
  if len(pilot)<40 and seen[key]<4:pilot.append(r['modification_id']);seen[key]+=1
 for r in selected:
  if len(pilot)<40 and r['modification_id'] not in pilot:pilot.append(r['modification_id'])
 order=pilot+[r['modification_id'] for r in selected if r['modification_id'] not in pilot]
 byid={r['modification_id']:r for r in selected}
 for n,mid in enumerate(order):byid[mid]['queue_index']=n+1;byid[mid]['pilot']=n<40
 lines(OUT/'screening.jsonl',screen);lines(OUT/'review_queue.jsonl',[byid[mid] for mid in order])
 groups=collections.defaultdict(list)
 for r in selected:groups[(r['repository'],r['modification_sha'])].append(r['modification_id'])
 lines(OUT/'selected_groups.jsonl',[{'group':n+1,'repository':key[0],'modification_sha':key[1],'event_ids':ids} for n,(key,ids) in enumerate(sorted(groups.items()))])
 write(OUT/'progress.json',{'phase':'inventory_complete','at':now(),'screened':1757,'selected':len(selected),'groups':len(groups),'pilot':len(pilot),'reviewed':0,'pending':len(selected),'not_selected':1757-len(selected)})
 print(json.dumps(json.loads((OUT/'progress.json').read_text()),ensure_ascii=False))

def show(start,end):
 events,sources,edges,contexts=load();es={e['modification_id']:e for e in events};queue=read(OUT/'review_queue.jsonl')
 shown_sources=set()
 for r in queue[start-1:end]:
  e=es[r['modification_id']];o=e['current_observation'];print('\nEVENT',r['queue_index'],e['modification_id'],e['repository'],e['modification_sha'],e['file_path'],o['classification'])
  print('BEFORE',redact(o.get('before_statement'),True));print('AFTER',redact(o.get('after_statement'),True))
  print('TEMPLATE_EXPRESSIONS',[redact(x,True) for x in re.findall(r'\{([^{}]{1,250})\}', (o.get('before_statement') or '')+'\n'+(o.get('after_statement') or ''))][:10])
  print('PRIOR',e['motive_status'],e['motive_labels'],redact(e.get('stated_purpose') or e.get('contextual_inference') or e.get('unknown_reason')))
  for eid in sorted({l['evidence_id'] for l in edges[e['modification_id']]}):
   s=sources[eid]
   if s.get('equivalence_group',eid) in shown_sources:continue
   shown_sources.add(s.get('equivalence_group',eid))
   text=s['text'];hits=list(PURPOSE.finditer(text));direct=any(l['evidence_id']==eid and l['relation']=='modification_session_context' for l in edges[e['modification_id']])
   if hits:
    spans=[]
    h=hits[0];spans.append((max(0,h.start()-80),min(len(text),h.end()+180)))
   elif s['source_type']=='commit_message':spans=[(0,min(450,len(text)))]
   else:continue
   if s['source_type']=='prompt' and len(text)>4000:
    print('SOURCE',eid,'prompt','large_context',len(text),'sensitivity_terms',sorted(set(x.group().lower() for x in hits))[:10]);continue
   print('SOURCE',eid,s['source_type'],'direct_session',direct)
   for a,b in spans:print('EXCERPT',a,b,redact(text[a:b],True))

if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('command',choices=['inventory','show']);p.add_argument('--start',type=int,default=1);p.add_argument('--end',type=int,default=10);a=p.parse_args()
 if a.command=='inventory':inventory()
 else:show(a.start,a.end)

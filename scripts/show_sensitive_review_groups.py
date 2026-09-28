"""Compact, redacted reading view: every event, with no quoted values."""
import argparse,re,json
import sensitive_log_review as s
from annotate_sensitive_log_review import code_values,types_for
p=argparse.ArgumentParser();p.add_argument('start',type=int);p.add_argument('end',type=int);a=p.parse_args()
events,sources,edges,ctx=s.load();es={e['modification_id']:e for e in events};q={r['modification_id']:r for r in s.read(s.OUT/'review_queue.jsonl')}
for g in s.read(s.OUT/'selected_groups.jsonl')[a.start-1:a.end]:
 mids=g['event_ids'];sourceids={l['evidence_id'] for mid in mids for l in edges[mid]};commits=[sources[i] for i in sourceids if sources[i]['source_type']=='commit_message'];titles=sorted({x['text'].splitlines()[0] for x in commits})
 print('\nGROUP',g['group'],g['repository'],g['modification_sha'],'EVENTS',len(mids),'TITLE',s.redact(' | '.join(titles),True)[:230])
 docs=[sources[i] for i in sorted(sourceids) if sources[i]['source_type'] in ('pr_description','commit_message') and s.PURPOSE.search(sources[i]['text'])]
 if docs:
  doc=next((x for x in docs if x['source_type']=='pr_description'),docs[0]);h=s.PURPOSE.search(doc['text']);lo=doc['text'].rfind('\n',0,max(0,h.start()-50))+1;hi=doc['text'].find('\n',h.end()+180);hi=len(doc['text']) if hi<0 else hi
  print('CONTEXT',doc['evidence_id'],s.redact(doc['text'][lo:hi],True).replace('\n',' ')[:420])
 for mid in mids:
  e=es[mid];o=e['current_observation'];b=code_values(o.get('before_statement') or '');aft=code_values(o.get('after_statement') or '')
  symbols=lambda t:list(dict.fromkeys(re.findall(r'\b[A-Za-z_]\w*(?:\.\w+)*\b',t)))
  symbols_b=[x for x in symbols(b) if x not in ('STRING_LITERAL','AGGREGATE','logCtx','ctx','context','summarizeCtx')]
  symbols_a=[x for x in symbols(aft) if x not in ('STRING_LITERAL','AGGREGATE','logCtx','ctx','context','summarizeCtx')]
  hint,_,direct=types_for(e)
  print('Q',q[mid]['queue_index'],e['file_path'],'OBS',o['classification'],'SYMBOLS',','.join(symbols_b),'AFTER',('same' if symbols_a==symbols_b else ','.join(symbols_a)),'TYPES',','.join(t['baseline_type'] for t in hint),'LOG',direct)

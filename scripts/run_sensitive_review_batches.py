"""Only persist reviews for groups with an explicit assistant reading receipt."""
import collections,json
import sensitive_log_review as s
from annotate_sensitive_log_review import annotate,validate

def accepted():
 pilot=json.loads((s.OUT/'accepted_batches.json').read_text())['pilot'];paths=[s.OUT/'batches'/pilot]
 paths+=sorted((s.OUT/'batches').glob('*_followup'))
 rows=[]
 for p in paths:
  if not (p/'validation.json').exists():raise ValueError('incomplete_batch:'+p.name)
  assert json.loads((p/'validation.json').read_text())['status']=='PASS';rows+=s.read(p/'reviews.jsonl')
 assert len({r['modification_id'] for r in rows})==len(rows)
 return rows

def run():
 ee,src,edges,ctx=s.load();es={e['modification_id']:e for e in ee};q=s.read(s.OUT/'review_queue.jsonl');done=accepted();ids={r['modification_id'] for r in done}
 approved=set(json.loads((s.OUT/'manual_group_read_receipts.json').read_text())['approved_group_numbers']);eligible={mid for g in s.read(s.OUT/'selected_groups.jsonl') if g['group'] in approved for mid in g['event_ids']}
 pending=[r for r in q if r['modification_id'] not in ids and r['modification_id'] in eligible]
 bn=2+len(list((s.OUT/'batches').glob('*_followup')))
 while pending:
  chunk=pending[:50]
  if len(chunk)<50 and len(approved)<196:break
  pending=pending[50:];name=f'{bn:03d}_followup';p=s.OUT/'batches'/name;p.mkdir(exist_ok=False)
  rows=[annotate(es[r['modification_id']],r,src,edges[r['modification_id']],name) for r in chunk];receipt=validate(rows,es,src,edges)
  s.lines(p/'reviews.jsonl',rows);s.write(p/'validation.json',receipt);done+=rows
  s.write(s.OUT/'progress.json',{'at':s.now(),'phase':'reviewing' if len(done)<len(q) else 'reviews_complete_pending_global_validation','screened':1757,'selected':len(q),'reviewed':len(done),'pending':len(q)-len(done),'pilot':40,'accepted_pilot':json.loads((s.OUT/'accepted_batches.json').read_text())['pilot'],'new_followup_batches':bn-1,'independent_evaluation':False})
  print(name,'PASS',len(rows),'reviewed',len(done),'remaining',len(q)-len(done),flush=True);bn+=1
if __name__=='__main__':run()

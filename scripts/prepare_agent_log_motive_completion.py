import sys,json,collections
from pathlib import Path
root=Path.cwd();sys.path.insert(0,str(root/'scripts'))
from review_agent_log_motives import read,write,lines,sha,now
from align_swechat_agent_logs import Guard
import agent_log_motivation_v11 as v
out=root/'outputs/agent_log_motive_completion_20260924';out.mkdir(exist_ok=False)
prior=root/'outputs/agent_log_motive_review_20260924';parent=root/'outputs/agent_log_three_stage_complete_20260923'
write(out/'progress.json',{'phase':'guard_revalidation','at':now()})
guard=Guard(root);es,details,gaps,upstream=v.normalize_trace(parent/'stage3_local/trace_view',guard)
old={e['event_id']:e for e in read(parent/'stage3_final/log_modifications.jsonl')}
assert len(es)==len(old)==18173
for e in es:
 assert e['guard_status']=='allowed'
 for k in ('repository','modification_sha','file_path','observed_change','diffs'):assert e.get(k)==old[e['event_id']].get(k)
rows=read(prior/'delivery_v2/log_modification_reviews.jsonl');wanted={r['association_event_ids'][0]:r['modification_id'] for r in rows}
contexts=[]
for e in es:
 if e['event_id'] in wanted:contexts.append(dict(e,modification_id=wanted[e['event_id']]))
lines(out/'contexts.jsonl',contexts)
write(out/'guard_receipt.json',{'at':now(),'allowed_associations':len(es),'checks':dict(guard.calls),'unique_events':len(rows),'parent_code_matched':True,'python':sys.executable})
write(out/'input_hashes.json',{str(p.relative_to(root)).replace('\\','/'):sha(p) for p in [prior/'delivery_v2/log_modification_reviews.jsonl',prior/'delivery_v2/motive_evidence.jsonl',prior/'delivery_v2/evidence_links.jsonl',prior/'delivery_v2/annotations.jsonl',parent/'stage3_final/log_modifications.jsonl',parent/'delivery/unique_log_modifications.jsonl',parent/'stage3_local/trace_view/followups.jsonl']})
write(out/'progress.json',{'phase':'guard_passed','at':now(),'total':len(rows),'prior_reviewed':110,'inherited_association_only':1,'pending':1646})
print('guard passed',len(contexts))

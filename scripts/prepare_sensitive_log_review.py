"""Guard and hash the prior completed review before sensitive-information review."""
import sys,json
from pathlib import Path
root=Path.cwd();sys.path.insert(0,str(root/'scripts'))
from review_agent_log_motives import read,write,sha,now
from align_swechat_agent_logs import Guard
import agent_log_motivation_v11 as v
out=root/'outputs/agent_log_sensitive_review_20260924';out.mkdir(exist_ok=False)
prior=root/'outputs/agent_log_motive_completion_20260924';parent=root/'outputs/agent_log_three_stage_complete_20260923'
write(out/'progress.json',{'phase':'guard_revalidation','at':now()})
guard=Guard(root);events,_,_,_=v.normalize_trace(parent/'stage3_local/trace_view',guard)
assert len(events)==18173 and all(e['guard_status']=='allowed' for e in events)
old={e['event_id']:e for e in read(prior/'contexts.jsonl')}
for e in events:
 if e['event_id'] in old:
  for k in ('repository','modification_sha','file_path','observed_change','diffs'):assert e.get(k)==old[e['event_id']].get(k)
write(out/'guard_receipt.json',{'at':now(),'allowed_associations':len(events),'checks':dict(guard.calls),'unique_events':len(old),'parent_code_matched':True,'python':sys.executable})
paths=[prior/'delivery'/f for f in ('log_modification_reviews.jsonl','motive_evidence.jsonl','evidence_links.jsonl','statistics.json')]+[prior/'contexts.jsonl',prior/'artifact_manifest.json',root/'src/agentlog_unified/taxonomy.py',root/'docs/taxonomy_v120_notes.md',root/'scripts/agent_log_review_delivery.py']
write(out/'input_hashes.json',{str(p.relative_to(root)).replace('\\','/'):sha(p) for p in paths})
write(out/'progress.json',{'phase':'guard_passed_pending_inventory','at':now(),'parent_events':1757,'reviewed':0,'selected':None})
print('guard_passed',len(events),len(old),dict(guard.calls))

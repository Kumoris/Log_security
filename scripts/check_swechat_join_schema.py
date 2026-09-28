"""Read join-key columns only; never load conversation bodies for schema checks."""
from run_swechat_followups import *
sys.path.insert(0,str(ROOT/'outputs/swechat_log_alignment_20260921/dependencies'))
import pyarrow.parquet as pq
if __name__=='__main__':
    frozen=PROJECT/'data/cache/swechat-frozen';cps={};cp_sessions=set();types=Counter();invalid=0
    for b in pq.ParquetFile(frozen/'checkpoints.parquet').iter_batches(columns=['repo_id','checkpoint_pk','session_pks','commit_shas']):
        for r in b.to_pylist():
            try:
                ss=json.loads(r['session_pks'] or '[]');shas=json.loads(r['commit_shas'] or '[]')
                types.update(type(x).__name__ for x in ss+shas)
                cps[(r['repo_id'],r['checkpoint_pk'])]=(set(ss),set(shas));cp_sessions.update(ss)
            except (TypeError,ValueError):invalid+=1
    commit_n=commit_linked=0
    for b in pq.ParquetFile(frozen/'commits.parquet').iter_batches(columns=['repo_id','commit_sha','checkpoint_pk']):
        for r in b.to_pylist():
            if r.get('commit_sha'):
                commit_n+=1;commit_linked+=r['commit_sha'] in cps.get((r['repo_id'],r['checkpoint_pk']),(set(),set()))[1]
    session_ids=set();triple_rows=user_triple_rows=0
    for b in pq.ParquetFile(frozen/'conversations.parquet').iter_batches(columns=['repo_id','checkpoint_pk','session_id','role','is_conversational','tool_name']):
        for r in b.to_pylist():
            session_ids.add(r['session_id'])
            linked=r['session_id'] in cps.get((r['repo_id'],r['checkpoint_pk']),(set(),set()))[0]
            triple_rows+=linked
            user_triple_rows+=linked and r['role']=='user' and r['is_conversational'] is True and not r.get('tool_name')
    result=dict(checkpoint_rows=len(cps),invalid_checkpoint_lists=invalid,list_item_types=dict(types),commit_rows_with_sha=commit_n,
        commits_verified_in_same_repo_checkpoint=commit_linked,checkpoint_session_ids=len(cp_sessions),conversation_session_ids=len(session_ids),
        shared_session_ids=len(cp_sessions&session_ids),conversation_rows_with_exact_triple=triple_rows,conversational_user_rows_with_exact_triple=user_triple_rows,
        conversation_bodies_read=False)
    dump(OUT/'join_schema_validation.json',result);print(json.dumps(result),flush=True)

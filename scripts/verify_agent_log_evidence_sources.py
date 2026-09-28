"""Read back every evidence text against saved API/Git/Parquet sources."""
import argparse
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path
from agent_log_motivation_v11 import rows, file_hash, write_json
from finish_agent_log_delivery import local_path


def verify(root):
    root=Path(root);stage=root/'stage3_final';w=Path(__file__).resolve().parents[1]
    evidence={r['evidence_id']:r for _,r in rows(stage/'motive_evidence.jsonl')}
    proof={};fail=[];payloads={};prompt_refs=defaultdict(set)
    for _,link in rows(stage/'evidence_links.jsonl'):
        if link['source_type']=='prompt':prompt_refs[link['evidence_id']].add(link['association_basis']['conversation_source_row'])
    repo={r['id']:r['repository'] for _,r in rows(root/'stage3_local/trace_view/repositories.jsonl')}
    commits={(repo[r['repository_id']],r['sha'],r['message']) for _,r in rows(root/'stage3_local/trace_view/commits.jsonl')}
    for eid,e in evidence.items():
        p=local_path(e['source_local_path'])
        if p.suffix=='.json':
            if p not in payloads:payloads[p]=json.loads(p.read_text(encoding='utf-8'))['data']
            data=payloads[p];kind=e['source_type']
            if isinstance(data,list):
                match=next((r for r in data if r.get('id')==e.get('comment_id') and r.get('body')==e['text']),None)
                good=match is not None and (not e.get('source_url') or match.get('html_url')==e['source_url'])
            else:
                good=(data.get('title','') or '')+'\n\n'+(data.get('body','') or '')==e['text'] and (not e.get('source_url') or data.get('html_url')==e['source_url'])
            if good:proof[eid]='saved_api_response_exact_id_text_url'
            else:fail.append(dict(evidence_id=eid,reason='raw_API_payload_mismatch'))
        elif e['source_type']=='commit_message' and (e['repository'],e['source_id'],e['text']) in commits:
            proof[eid]='saved_git_commit_exact_repository_sha_message'
    sys.path.insert(0,str(w/'outputs/swechat_log_alignment_20260921/dependencies'))
    import pyarrow.parquet as pq
    frozen=w/'data/cache/swechat-frozen'
    wanted_commits={(e['repository'].lower(),e['source_id'],e['text']):eid for eid,e in evidence.items() if e['source_type']=='commit_message' and eid not in proof}
    for b in pq.ParquetFile(frozen/'commits.parquet').iter_batches(columns=['repo_id','commit_sha','commit_message']):
        for r in b.to_pylist():
            eid=wanted_commits.get(((r.get('repo_id') or '').lower(),r.get('commit_sha'),r.get('commit_message')))
            if eid:proof[eid]='raw_commits_parquet_exact_repository_sha_message'
    row_targets=defaultdict(list)
    for eid,indices in prompt_refs.items():
        for index in indices:row_targets[index].append(eid)
    pos=0
    for b in pq.ParquetFile(frozen/'conversations.parquet').iter_batches(batch_size=4096,columns=['repo_id','session_id','checkpoint_pk','turn_id','role','is_conversational','tool_name','content']):
        for r in b.to_pylist():
            pos+=1
            for eid in row_targets.get(pos,[]):
                e=evidence[eid]
                good=(r['content']==e['text'] and r['repo_id'].lower()==e['repository'].lower() and r['session_id']==e['session_id'] and r['checkpoint_pk']==e['checkpoint_pk'] and r['turn_id']==e.get('turn_id') and r['role']=='user' and r['is_conversational'] is True and not r['tool_name'])
                if good:proof[eid]='raw_conversation_row_exact_repository_checkpoint_session_user_turn_text'
                else:fail.append(dict(evidence_id=eid,reason='raw_prompt_row_or_identity_mismatch'))
    fail.extend(dict(evidence_id=eid,reason='no_original_source_readback') for eid in evidence if eid not in proof)
    result=dict(status='PASS' if not fail else 'FAIL',evidence_rows=len(evidence),verified_source_rows=len(proof),
        validation_methods=dict(Counter(proof.values())),failures=fail,independent_human_accuracy=False)
    dest=root/'verification/source_readback.json'
    if dest.exists():raise FileExistsError(dest)
    write_json(dest,result)
    # One short, non-code user prompt example; association stays context/unknown.
    sample=next((e for e in evidence.values() if e['source_type']=='prompt' and 20<len(e['text'])<300 and '\n' not in e['text'] and '```' not in e['text']),None)
    if sample:
        link=next(r for _,r in rows(stage/'evidence_links.jsonl') if r['evidence_id']==sample['evidence_id'])
        event=next(r for _,r in rows(stage/'log_modifications.jsonl') if r['event_id']==link['event_id'])
        if event['guard_status']!='allowed':raise ValueError('sample_guard_not_allowed')
        fields=['event_id','repository','modification_sha','parent_sha','file_path','observed_change','motive_status']
        write_json(root/'delivery/prompt_traceable_example.json',dict(event={k:event[k] for k in fields},evidence=sample,link=link,
            interpretation='Verified same modification checkpoint/session/user turn; no automatic statement-specific motive inference'))
    write_json(root/'verification/source_readback_manifest.json',dict(parent_manifest_sha256=file_hash(root/'manifest.json'),
        verification_sha256=file_hash(dest),script_sha256=file_hash(__file__),prompt_example_sha256=file_hash(root/'delivery/prompt_traceable_example.json') if sample else None))
    print(json.dumps(result),flush=True)
    if fail:raise SystemExit(1)


if __name__=='__main__':
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--root',type=Path,required=True);a=ap.parse_args();verify(a.root)

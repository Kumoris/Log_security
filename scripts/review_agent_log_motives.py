"""Additive, resumable unique-event motive review. Never mutates stage 1/2 or parent."""
from __future__ import annotations
import argparse, collections, hashlib, json, sys
from pathlib import Path
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parents[1]
PARENT = ROOT / 'outputs/agent_log_three_stage_complete_20260923'
OUT = ROOT / 'outputs/agent_log_motive_review_20260924'

def read(path):
    with Path(path).open(encoding='utf-8-sig') as f:
        return [json.loads(s) for s in f if s.strip()]

def write(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')

def lines(path, records):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('w', encoding='utf-8') as f:
        for record in records:
            f.write(json.dumps(record, ensure_ascii=False, separators=(',', ':')) + '\n')

def sha(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as f:
        for part in iter(lambda: f.read(1024*1024), b''): h.update(part)
    return h.hexdigest()

def now(): return datetime.now(timezone.utc).isoformat()

def prepare():
    OUT.mkdir(exist_ok=False)
    write(OUT/'progress.json', {'phase':'structural_guard', 'started_at':now()})
    import agent_log_motivation_v11 as v11
    from align_swechat_agent_logs import Guard
    guard = Guard(ROOT)
    events, details, gaps, upstream = v11.normalize_trace(PARENT/'stage3_local/trace_view', guard)
    parent_events = {e['event_id']:e for e in read(PARENT/'stage3_final/log_modifications.jsonl')}
    assert set(parent_events) == {e['event_id'] for e in events}, 'event_identity_changed'
    checked = {e['event_id']:e for e in events}
    for e in events:
        p = parent_events[e['event_id']]
        for key in ('guard_status','observed_change','repository','modification_sha','file_path','diffs'):
            assert e.get(key) == p.get(key), ('parent_content_changed', e['event_id'], key)
    unique = read(PARENT/'delivery/unique_log_modifications.jsonl')
    queue = []
    for u in unique:
        es = [checked[i] for i in u['association_event_ids']]
        allowed = all(e['guard_status']=='allowed' for e in es)
        queue.append(dict(u, guard_status='allowed' if allowed else 'blocked_or_unverifiable',
                          review_state='pending' if allowed else 'guard_blocked', motive_status='unknown'))
    lines(OUT/'events.jsonl', queue)
    # Only freshly allowed content can enter review packets.
    lines(OUT/'allowed_associations.jsonl', [e for e in events if e['guard_status']=='allowed'])
    write(OUT/'guard_receipt.json', {'at':now(), 'guard_calls':dict(guard.calls),
        'allowed_associations':sum(e['guard_status']=='allowed' for e in events),
        'event_count':len(unique), 'gap_count':len(gaps), 'upstream':upstream,
        'research_python':sys.executable, 'parent_content_matched':True})
    paths = ['delivery/unique_log_modifications.jsonl','delivery/unique_modification_evidence.jsonl',
             'delivery/association_to_modification.jsonl','stage3_final/log_modifications.jsonl',
             'stage3_final/motive_evidence.jsonl','stage3_final/evidence_links.jsonl',
             'stage3_final/unresolved_records.jsonl','reviewed_motive_annotations.jsonl',
             'verification/final_receipt.json']
    paths += [str(p.relative_to(PARENT)) for p in (PARENT/'stage3_local/trace_view').glob('*.jsonl')]
    write(OUT/'parent_integrity.json', {p:sha(PARENT/p) for p in paths})
    write(OUT/'progress.json', {'phase':'prepared', 'at':now(), 'unique_events':len(unique),
                              'reviewed':0, 'pending':len(unique)})
    print(json.dumps({'prepared':len(unique),'guard':dict(guard.calls)}))

def index():
    assert json.loads((OUT/'guard_receipt.json').read_text())['parent_content_matched']
    if (OUT/'batches').exists(): raise ValueError('index_already_exists')
    events=read(OUT/'events.jsonl')
    allowed={e['modification_id'] for e in events if e['guard_status']=='allowed'}
    edges=[r for r in read(PARENT/'delivery/unique_modification_evidence.jsonl') if r['modification_id'] in allowed]
    evidence={r['evidence_id']:r for r in read(PARENT/'stage3_final/motive_evidence.jsonl')}
    wanted={r['evidence_id'] for r in edges}
    lines(OUT/'evidence.jsonl',[evidence[i] for i in sorted(wanted)])
    original={r['link_id']:r for r in read(PARENT/'stage3_final/evidence_links.jsonl')}
    um={e['modification_id']:e for e in events}
    for r in edges:
        event=um[r['modification_id']]; bases={}
        for lid in r['original_link_ids']:
            link=original[lid]
            assert link['event_id'] in event['association_event_ids']
            assert link['evidence_id']==r['evidence_id']
            assert (link['repository'],link['modification_sha'],link['file_path']) == (event['repository'],event['modification_sha'],event['file_path'])
            bases.setdefault((link['association_method'],link['relation']),link)
        r.update(repository=event['repository'],modification_sha=event['modification_sha'],file_path=event['file_path'],
                 representative_chains=list(bases.values()),parent_links_path='stage3_final/evidence_links.jsonl')
    lines(OUT/'evidence_links.jsonl',edges)
    groups=collections.defaultdict(list)
    for e in events:
        if e['modification_id'] in allowed: groups[e['repository'],e['modification_sha']].append(e)
    ordered=sorted(groups)
    selected_numbers=[5,251,252,255,306,310,311,316,335,363,9,10,12,19,20,23,33,37,43,44,81,180,228,279,280,281,305,308,329,341,342,2,4,55,85,139,201,233,237,248]
    pilot=[sorted(groups[ordered[n-1]],key=lambda e:e['modification_id'])[0]['modification_id'] for n in selected_numbers]
    assert len(set(pilot))==40
    write(OUT/'batches/001_pilot/selection.json',{'selection':'purposive_development_sample_not_random_or_independent_evaluation',
        'basis':'commit metadata; prompt availability; direct and dependency changes; logging-focused and broad changes',
        'selected_group_numbers':selected_numbers,'modification_ids':pilot,'created_at':now()})
    write(OUT/'progress.json',{'phase':'pilot_ready','at':now(),'unique_events':len(events),'reviewed':0,'pending':len(events),'pilot_count':40})
    print(json.dumps({'events':len(events),'evidence':len(wanted),'unique_relation_edges':len(edges),'pilot':40}))


def packets(ids):
    em={e['modification_id']:e for e in read(OUT/'events.jsonl')}
    wanted_associations={em[mid]['association_event_ids'][0] for mid in ids}
    associations={}
    with (OUT/'allowed_associations.jsonl').open(encoding='utf-8') as stream:
        for line in stream:
            e=json.loads(line)
            if e['event_id'] in wanted_associations: associations[e['event_id']]=e
    evidence={e['evidence_id']:e for e in read(OUT/'evidence.jsonl')}
    links=collections.defaultdict(list)
    for r in read(OUT/'evidence_links.jsonl'): links[r['modification_id']].append(r)
    result=[]
    for mid in ids:
        e=em[mid]; assert e['guard_status']=='allowed'
        a=associations[e['association_event_ids'][0]]
        es=[]
        for r in links[mid]:
            ev=evidence[r['evidence_id']]
            es.append(dict(evidence_id=ev['evidence_id'],source_type=ev['source_type'],relation=r['relation'],
                           text=ev['text'],source_url=ev.get('source_url'),source_time=ev.get('source_time')))
        result.append({'event':e,'diffs':a['diffs'],'sources':es})
    return result

def make_batch(batch_name, pending_file, limit):
    import re
    if not re.fullmatch(r'[0-9]{3}_[a-z0-9_]+',batch_name): raise ValueError('invalid_batch_name')
    if not 1 <= limit <= 100: raise ValueError('invalid_batch_size')
    bd=OUT/'batches'/batch_name
    if bd.exists():raise ValueError('batch_already_exists')
    selected=read(pending_file)[:limit]
    assert selected and all(e['guard_status']=='allowed' for e in selected)
    import agent_log_motivation_v11 as v11
    from align_swechat_agent_logs import Guard
    guard=Guard(ROOT)
    events,details,gaps,upstream=v11.normalize_trace(PARENT/'stage3_local/trace_view',guard)
    allowed={e['event_id'] for e in events if e['guard_status']=='allowed'}
    assert all(set(e['association_event_ids']) <= allowed for e in selected), 'new_guard_did_not_allow_batch'
    bd.mkdir()
    write(bd/'guard_receipt.json',{'at':now(),'guard_calls':dict(guard.calls),'allowed_selected':len(selected),'research_python':sys.executable})
    write(bd/'selection.json',{'at':now(),'modification_ids':[e['modification_id'] for e in selected],'source_pending_file':str(pending_file)})
    lines(bd/'packets.jsonl',packets([e['modification_id'] for e in selected]))
    print('Prepared next review batch:',len(selected))

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=['prepare','index','pilot-packets','make-batch'])
    parser.add_argument('--batch-name',default='003_review')
    parser.add_argument('--pending-file',type=Path)
    parser.add_argument('--limit',type=int,default=40)
    args=parser.parse_args()
    if args.command=='prepare': prepare()
    elif args.command=='index': index()
    elif args.command=='pilot-packets':
        ids=json.loads((OUT/'batches/001_pilot/selection.json').read_text())['modification_ids']
        if (OUT/'batches/001_pilot/packets.jsonl').exists():raise ValueError('packets_already_exist')
        lines(OUT/'batches/001_pilot/packets.jsonl',packets(ids))
    elif args.command=='make-batch':
        pending=args.pending_file or OUT/json.loads((OUT/'progress.json').read_text())['resume_from']
        make_batch(args.batch_name,pending,args.limit)

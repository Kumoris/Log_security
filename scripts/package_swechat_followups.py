"""Reconcile every stage-one candidate and package actual stage-two events."""
from run_swechat_followups import *
from datetime import datetime,timezone

def readrows(p):
    if p.exists():
        with p.open(encoding='utf-8-sig') as f:
            for line in f:
                if line.strip():yield json.loads(line)

def ancestor(a,b,parents):
    seen=set();todo=[b]
    while todo:
        x=todo.pop()
        if x==a:return True
        if x not in seen:seen.add(x);todo.extend(parents.get(x,[]))
    return False

def package():
    inv=json.loads((OUT/'inventory.json').read_text(encoding='utf-8'))
    pending=[r['repository'] for r in inv['repositories'] if not any((repository_output_directory(r['repository'])/n).exists() for n in ('summary.json','execution_error.txt'))]
    if pending:raise RuntimeError('Repositories still running: '+', '.join(pending))
    dest=OUT/'stage2';dest.mkdir(exist_ok=False)
    tables={n:[] for n in ['repositories','commits','file_changes','candidate_ledger','log_changes','followups','coverage_intervals','target_branch_integration_events','log_source_anchors','raw_followups']}
    repo_summaries=[];checks=[]
    for row in inv['repositories']:
        name=row['repository'];p=repository_output_directory(name)
        if not (p/'summary.json').exists():
            if not (p/'execution_error.txt').exists():raise RuntimeError('Repository still running: '+name)
            candidates=[r for r in inputs() if r['repo_id']==name]
            tables['candidate_ledger'].extend({k:r[k] for k in ['log_id','repo_id','commit_sha','path','start_line','end_line','attribution_grade','file_attribution_labels']}|
                dict(status='execution_failed',followup_ids=[],error_receipt=str(p/'execution_error.txt')) for r in candidates)
            repo_summaries.append(dict(repository=name,status='execution_failed',candidates=len(candidates),events=0));continue
        s=json.loads((p/'summary.json').read_text(encoding='utf-8'));repo_summaries.append(s)
        local={n:list(readrows(p/(n+'.jsonl'))) for n in tables}
        if not local['raw_followups']:
            case_order={r['case_id']:i for i,r in enumerate(local['log_changes'])}
            positions={(r['case_id'],f):j for r in local['log_changes'] for j,f in enumerate(r['followup_ids'])}
            local['raw_followups']=sorted(local['followups']+local['coverage_intervals'],
                key=lambda f:(case_order[f['case_id']],positions[(f['case_id'],f['id'])]))
        for n in tables:tables[n].extend(local[n])
        if s['status']!='executed':continue
        history=json.loads((p/'history_scope.json').read_text(encoding='utf-8'))
        parents={r['sha']:r['parents'] for r in history['graph']};fp=set(history['first_parent_shas'])
        origins={r['case_id']:r for r in local['log_changes']}
        for f in local['followups']:
            origin=origins[f['case_id']]
            checks.append(dict(id=f['id'],repository=name,
                different_commit=f['sha']!=origin['intro_sha'],
                first_parent=f['sha'] in fp,
                follows_integration=bool(origin.get('integration_sha') and ancestor(origin['integration_sha'],f['sha'],parents)),
                parent_matches_git_graph=f['parent_sha']==(parents.get(f['sha']) or [None])[0],
                is_actual_event=f['change_kind'] not in {'coverage_gap','gap_resumed'},
                original_confidence_preserved=f['behavior_confidence'] in {'supported','possible'}))
    from align_swechat_agent_logs import Guard
    guard=Guard(PROJECT);seen=set();anchor_gaps=[]
    repo_map={r['id']:r for r in tables['repositories']}
    for event in tables['followups']:
        repo=repo_map[event['repository_id']];path=resolve_path(repo['local_repo_path'])
        for side,revision in [('before',event['parent_sha']),('after',event['sha'])]:
            entity=event.get(side)
            if not entity:continue
            key=(repo['id'],revision,entity['path'])
            if key in seen:continue
            seen.add(key)
            source=git(path,['show',revision+':'+entity['path']])
            if source is None:
                anchor_gaps.append(dict(key=key,reason='git_blob_unavailable'));continue
            if guard.check(repo['repository'],entity['path'],source)!='allowed':
                anchor_gaps.append(dict(anchor_key_sha256=hashlib.sha256(str(key).encode()).hexdigest(),reason='guard_blocked_or_unverifiable'));continue
            raw=source.encode('utf-8')
            actual_blob=git(path,['rev-parse',revision+':'+entity['path']])
            computed_blob=hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()
            if actual_blob is None or actual_blob.strip()!=computed_blob:
                anchor_gaps.append(dict(key=key,reason='git_blob_hash_mismatch'));continue
            # git() preserves byte newlines; UTF-8 decoding is validated by the structural guard.
            tables['log_source_anchors'].append(dict(repository_id=repo['id'],sha=revision,path=entity['path'],source=source,
                source_sha256=hashlib.sha256(raw).hexdigest(),git_blob_id=hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest(),
                source_locator=str(path)+' :: '+revision+':'+entity['path']))
    dump(dest/'source_anchor_gaps.json',anchor_gaps)
    original=inputs(); ledger=tables['candidate_ledger'];fs=tables['followups'];cases=tables['log_changes']
    repo_by_name={r['repository']:r for r in tables['repositories']}
    first_images={}
    for r in readrows(ROOT/'outputs/swechat_log_alignment_20260921/final/log_alignment_evidence.jsonl'):
        first_images[r['log_id']]={o.get('postimage_sha256') for o in r.get('observations',[]) if o.get('postimage_sha256')}
    source_memo={};anchor_audit=[]
    for candidate in original:
        name,sha,path=candidate['repo_id'],candidate['commit_sha'],candidate['path'];key=(name,sha,path)
        if key not in source_memo:
            repo=repo_by_name.get(name)
            source=git(resolve_path(repo['local_repo_path']),['show',sha+':'+path]) if repo else None
            status=guard.check(name,path,source) if source is not None else 'git_source_unavailable'
            source_memo[key]=(status,source if status=='allowed' else None)
        status,source=source_memo[key]
        a=dict(log_id=candidate['log_id'],repository=name,introduction_sha=sha,file_path=path,source_status=status)
        if source is not None:
            normalized=source.replace('\r\n','\n');h=hashlib.sha256(normalized.encode()).hexdigest()
            lines=source.splitlines();start,end=int(candidate['start_line']),int(candidate['end_line'])
            a.update(git_final_source_normalized_sha256=h,
                exact_line_statement_verified=candidate['statement'].strip() in '\n'.join(lines[start-1:end]),
                matches_stage1_committed_postimage=h in first_images.get(candidate['log_id'],set()),
                stage1_postimage_variant_count=len(first_images.get(candidate['log_id'],set())),
                all_stage1_postimages_match_git=first_images.get(candidate['log_id'],set())=={h},
                comparison_basis='exact_initial_git_commit_blob_vs_stage1_file_attribution_committed_version')
        anchor_audit.append(a)
    jl(dest/'initial_source_anchor_audit.jsonl',anchor_audit)
    checkmap={r['log_id']:r for r in original}
    for r in ledger:
        r.update({k:checkmap[r['log_id']][k] for k in ('log_detection_status','source_rows','callee')})
    for case in cases:
        for a in case['stage1_attribution']:
            a.update({k:checkmap[a['log_id']][k] for k in ('log_detection_status','source_rows')})
    candidate_preservation=len(ledger)==len(original) and {r['log_id'] for r in ledger}==set(checkmap)
    callee_preservation=all((case.get('after') or {}).get('callee')==checkmap[i]['callee'] for case in cases for i in case['stage1_log_ids'])
    attribution_preservation=all(all(r[k]==checkmap[r['log_id']][k] for k in ['repo_id','commit_sha','path','start_line','end_line','attribution_grade','file_attribution_labels','log_detection_status','source_rows','callee']) for r in ledger)
    for n,rs in tables.items():
        jl(dest/(n+'.jsonl'),rs)
        if n in {'candidate_ledger','followups'}:
            keys=list(dict.fromkeys(k for r in rs for k in r))
            with (dest/(n+'.csv')).open('w',encoding='utf-8-sig',newline='') as f:
                w=csv.DictWriter(f,fieldnames=keys);w.writeheader()
                for r in rs:w.writerow({k:json.dumps(v,ensure_ascii=False) if isinstance(v,(list,dict)) else v for k,v in r.items()})
    unique_events={(r['repository_id'],r['sha'],r['parent_sha'],r['file_path'],(r.get('before') or {}).get('start_line'),(r.get('after') or {}).get('start_line'),r['entity_fingerprint'],r['change_kind']) for r in fs}
    first_summary=json.loads((ROOT/'outputs/swechat_log_alignment_20260921/final/summary.json').read_text(encoding='utf-8'))
    log_file_units=len({(r['repo_id'],r['commit_sha'],r['path']) for r in original})
    counts=dict(stage1_input_file_units=first_summary['input_file_units'],stage1_output_log_candidates=len(original),stage1_output_log_file_units=log_file_units,
        stage2_input_candidates=len(original),mapped_candidates=sum(r.get('case_id') is not None for r in ledger),
        initial_logs_with_followups=sum(bool(r.get('followup_ids')) for r in ledger),stage2_event_links=len(fs),stage2_trace_origins=len(cases),
        stage2_candidate_event_pairs=sum(len(r.get('followup_ids',[])) for r in ledger),
        origins_with_multiple_stage1_ids=sum(len(c.get('stage1_log_ids',[]))>1 for c in cases),
        stage2_unique_modification_events=len(unique_events),stage2_raw_tracker_rows=len(tables['raw_followups']),coverage_intervals=len(tables['coverage_intervals']),
        candidate_status=dict(Counter(r['status'] for r in ledger)),event_relation=dict(Counter(r['relation'] for r in fs)),
        event_confidence=dict(Counter(r['behavior_confidence'] for r in fs)),repositories=len(repo_summaries),
        repository_status=dict(Counter(r['status'] for r in repo_summaries)),
        source_commits=sum(r.get('commits',0) for r in repo_summaries),
        initial_source_status=dict(Counter(r['source_status'] for r in anchor_audit)),
        stage1_postimage_compared=sum('matches_stage1_committed_postimage' in r for r in anchor_audit),
        stage1_postimage_matches=sum(r.get('matches_stage1_committed_postimage',False) for r in anchor_audit))
    by_event_id={f['id']:f for f in fs}
    counts['changed_candidates_with_supported_link']=sum(any(by_event_id[i]['behavior_confidence']=='supported' for i in r.get('followup_ids',[])) for r in ledger)
    counts['changed_candidates_with_possible_links_only']=sum(bool(r.get('followup_ids')) and all(by_event_id[i]['behavior_confidence']=='possible' for i in r['followup_ids']) for r in ledger)
    counts['stage1_all_postimages_match_git']=sum(r.get('all_stage1_postimages_match_git',False) for r in anchor_audit)
    grades=sorted({r['attribution_grade'] for r in ledger})
    counts['attribution_breakdown']={grade:dict(input_candidates=sum(r['attribution_grade']==grade for r in ledger),
        mapped_candidates=sum(r['attribution_grade']==grade and bool(r.get('case_id')) for r in ledger),
        changed_candidates=sum(r['attribution_grade']==grade and bool(r.get('followup_ids')) for r in ledger)) for grade in grades}
    mixed=[r for r in ledger if 'mixed' in json.loads(r['file_attribution_labels'])]
    counts['mixed_breakdown']=dict(input_candidates=len(mixed),mapped_candidates=sum(bool(r.get('case_id')) for r in mixed),changed_candidates=sum(bool(r.get('followup_ids')) for r in mixed))
    counts['stage2_changed_candidate_fraction']=counts['initial_logs_with_followups']/len(original)
    counts['stage1_log_file_fraction']=log_file_units/first_summary['input_file_units']
    counts['stage1_log_detection_status']=dict(Counter(r['log_detection_status'] for r in original))
    counts['mapped_candidate_censoring']=dict(Counter(r.get('censoring_reason') or 'none' for r in ledger if r.get('case_id')))
    counts['censored_by_repository_mining_gaps_candidates']=sum(r.get('censoring_reason')=='history_incomplete' for r in ledger)
    counts['unknown_integration_time_origins']=sum(c.get('integration_time_source')=='unknown' for c in cases)
    counts['observation_policy']='Unchanged original fallback: frozen target history when real PR merge time is unknown; no fabricated 90-day window'
    dump(dest/'summary.json',counts);dump(dest/'repository_summary.json',repo_summaries)
    validation=dict(status='PASS',all_repository_execution_receipts_complete=len(repo_summaries)==len(inv['repositories']) and all(r['status'] in {'executed','history_unavailable'} for r in repo_summaries),candidate_preservation=candidate_preservation,stage1_attribution_preservation=attribution_preservation,anchor_callee_preservation=callee_preservation,
        original_tracker_rows_preserved=len(tables['raw_followups'])==len(fs)+len(tables['coverage_intervals']),
        event_ids_unique=len({f['id'] for f in fs})==len(fs),case_ids_unique=len({c['case_id'] for c in cases})==len(cases),
        all_event_ancestry_and_graph_checks=all(all(v for k,v in r.items() if isinstance(v,bool)) for r in checks),
        every_event_has_case=all(f['case_id'] in {c['case_id'] for c in cases} for f in fs),
        unchanged_stage1_input_sha256=hashlib.sha256(INPUT.read_bytes()).hexdigest()==inv['input_sha256'],
        checked_events=len(checks),evaluated_holdout=False)
    if not all(v for k,v in validation.items() if isinstance(v,bool) and k!='evaluated_holdout'):validation['status']='FAIL'
    jl(dest/'event_graph_validation.jsonl',checks);dump(dest/'validation.json',validation)
    dependencies=[ROOT/'scripts'/n for n in ('run_swechat_followups.py','execute_swechat_followups.py','package_swechat_followups.py','collect_swechat_followup_history.py','hydrate_swechat_initial_ancestry.py','mine_swechat_linux.py','swechat_native_git_mirror.py','swechat_mining_storage.py','swechat_exact_detection_cache.py','swechat_python_mutation_index.py','swechat_python_evaluation_cache.py','swechat_python_file_cache.py','swechat_matching_cache.py','swechat_bounded_history.py','swechat_lineage_gap_storage.py')]+list((PROJECT/'src/agentlog_unified').glob('*.py'))
    dump(dest/'manifest.json',dict(created_at=datetime.now(timezone.utc).isoformat(),input_sha256=inv['input_sha256'],
        artifacts={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in dest.iterdir() if p.is_file()},
        implementation_sha256={str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in dependencies},
        selected_attempts=json.loads((OUT/'selected_repository_attempts.json').read_text(encoding='utf-8')) if (OUT/'selected_repository_attempts.json').exists() else {},
        implementation_hash_scope='Delivered implementation at packaging time; runtime cache/storage/platform adapter receipts are retained per repository',
        original_data_modified=False,history_cutoff='per_repository_collection_receipt',original_matcher_and_tracer_modified=False))
    print(json.dumps(counts,ensure_ascii=False),flush=True)

if __name__=='__main__':package()

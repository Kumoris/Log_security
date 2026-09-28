"""Execute unchanged project miner/detector/tracer with a frozen SWE-chat adapter.

No author, brand, privacy or motive filtering. Isolation guards remove unavailable
source from analysis and expose coverage gaps, never fictitious deletions.
"""
from run_swechat_followups import *
from datetime import datetime, timezone
from functools import lru_cache
import copy, traceback
from align_swechat_agent_logs import Guard
from agentlog_unified import analysis, miner, lineage, detector, matching
from swechat_exact_detection_cache import install
from swechat_python_mutation_index import install as install_scope_index
from swechat_python_evaluation_cache import install as install_evaluation_cache
from swechat_python_file_cache import install as install_file_cache
from swechat_bounded_history import detect as bounded_detect
from swechat_matching_cache import install as install_matching_cache
from swechat_lineage_gap_storage import TraceGapStorage
from agentlog_unified.storage import stable_id
import yaml

def match_anchor(candidate, event):
    a=event.get('after') or {}
    return (event['sha']==candidate['commit_sha'] and a.get('path')==candidate['path']
        and a.get('callee')==candidate.get('callee')
        and a.get('start_line')==int(candidate['start_line']) and a.get('end_line')==int(candidate['end_line'])
        and candidate['statement'].strip() in a.get('statement','').strip())

def memory_capacity_bytes():
    if os.name!='nt':return None
    import ctypes
    class MemoryStatus(ctypes.Structure):
        _fields_=[('length',ctypes.c_ulong),('load',ctypes.c_ulong)]+[(name,ctypes.c_ulonglong) for name in ['total','available','page_total','page_available','virtual_total','virtual_available','extended_available']]
    status=MemoryStatus();status.length=ctypes.sizeof(status)
    return dict(physical=status.available,commit=status.page_available) if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(status)) else None

def available_memory_bytes():
    capacity=memory_capacity_bytes()
    return capacity['physical'] if capacity else None

def execute(name):
    directory=OUT/'repositories'/name.replace('/','--')
    if (directory/'summary.json').exists(): return json.loads((directory/'summary.json').read_text(encoding='utf-8'))
    directory.mkdir(parents=True,exist_ok=True)
    try:
        with (directory/'execution.lock').open('x',encoding='utf-8') as lock:lock.write(str(os.getpid()))
    except FileExistsError:
        print(name,'already_owned_by_another_worker',flush=True);return
    selected=[r for r in inputs() if r['repo_id']==name]
    receipt=json.loads((OUT/'collection'/(name.replace('/','--')+'.json')).read_text(encoding='utf-8'))
    inventory=json.loads((OUT/'inventory.json').read_text(encoding='utf-8'))
    inv=next(r for r in inventory['repositories'] if r['repository']==name)
    source=receipt if receipt['status']=='fetched' else inv['selected']
    ledger=[{k:r[k] for k in ['log_id','repo_id','commit_sha','path','start_line','end_line','attribution_grade','file_attribution_labels']} for r in selected]
    def progress(stage,**extra):
        dump(directory/'progress.json',dict(repository=name,stage=stage,time=datetime.now(timezone.utc).isoformat(),**extra))
        print(name,stage,extra,flush=True)
    progress('start')
    if not source:
        for r in ledger:r.update(status='history_unavailable',reason=receipt.get('error_type'),followup_ids=[])
        jl(directory/'candidate_ledger.jsonl',ledger)
        s=dict(repository=name,status='history_unavailable',candidates=len(ledger),events=0)
        dump(directory/'summary.json',s); return s
    free=available_memory_bytes()
    while free is not None and free<6*1024**3:
        progress('waiting_for_memory',available_gib=round(free/1024**3,2),required_gib=6)
        time.sleep(30);free=available_memory_bytes()
    p=resolve_path(source['path']);os.environ.update(environment(p))
    guard=Guard(PROJECT)
    config=yaml.safe_load((PROJECT/'config.example.yaml').read_text(encoding='utf-8'))
    config['run_mode']='full'
    rid=stable_id('swechat_followup',name)
    repo=dict(id=rid,repository_id=name,repository=name,local_repo_path=str(p),target_ref=source['target_ref'],
        frozen_target_tip=source['tip'],shallow=source.get('shallow',False),missing_shas=[],local_snapshot_only=receipt['status']!='fetched',pr_ids=[])
    # Process an entire repository history. The original budgets and selection stay unchanged.
    start=time.time()
    if os.name=='nt':
        import gzip,pickle
        raw=OUT/'raw-mining-not-for-review'/(name.replace('/','--')+'.pickle.gz')
        def to_wsl(value):
            text=str(value).replace('\\','/')
            return '/mnt/'+text[0].lower()+text[2:] if len(text)>2 and text[1]==':' else text
        site=PROJECT/'research/swechat-windows-continuation-20260914/.venv/Lib/site-packages'
        command=['wsl.exe','--exec','env','PYTHONDONTWRITEBYTECODE=1','PYTHONPATH='+to_wsl(site),
            '/usr/bin/python3',to_wsl(ROOT/'scripts/mine_swechat_linux.py'),'--repository',name,
            '--path',str(p),'--tip',source['tip'],'--output',str(raw)]
        q=subprocess.run(command,capture_output=True)
        if q.returncode:
            raise RuntimeError('Linux mining adapter failed (exit '+str(q.returncode)+'): '+q.stderr.decode('utf-8',errors='replace')[-1500:])
        with gzip.open(raw,'rb') as f:mined=pickle.load(f)
        raw.unlink()  # temporary unguarded acquisition data; only guarded evidence is exported
    else:
        mined=miner.mine_repository(str(p),source['tip'],sorted({r['commit_sha'] for r in selected}),
            max_commits=config['mining']['max_history_commits_per_repository'],max_source_bytes=config['mining']['max_source_file_bytes'])
    mined['repository_id']=rid
    for r in mined['commits']:r.update(id=stable_id(rid,r['sha']),repository_id=rid)
    for r in mined['changes']:
        r.update(id=r['change_id'],repository_id=rid)
        r['native_paths']={k:r.get(k) for k in ('old_path','new_path')}
        for k in ('old_path','new_path'):
            if r.get(k):r[k]=r[k].replace('\\','/')
    for r in mined['gaps']:r.update(repository_id=rid,repository=name)
    repo['missing_shas']=[r.get('sha') for r in mined['gaps'] if r.get('error_type')=='missing_initial_object']
    progress('mined',commits=len(mined['commits']),file_changes=len(mined['changes']),seconds=round(time.time()-start))
    original_snapshot=analysis.snapshot_files; original_detect=analysis.detect_snapshot
    snapshot_calls=0
    def guarded_snapshot(path,sha,**kw):
        nonlocal snapshot_calls
        raw=original_snapshot(path,sha,**kw)
        for f,text in list(raw['files'].items()):
            status=guard.check(name,f,text)
            if status!='allowed':
                del raw['files'][f]
                raw['gaps'].append(dict(path=f,error_type=status,reason='sealed_protocol_source_unavailable',source_analysis_unavailable=True))
        snapshot_calls+=1
        if snapshot_calls%5==0:progress('detecting',snapshots=snapshot_calls,guard_unique_sources=len(guard.cache),elapsed_seconds=round(time.time()-start))
        return raw
    cache={}
    def guarded_detect(files,languages):
        # Exact full-snapshot memoization only; import/dependency context is retained.
        key=hashlib.sha256(json.dumps(files,sort_keys=True,ensure_ascii=False).encode()).hexdigest()
        if key in cache:return copy.deepcopy(cache[key])
        parsed=original_detect(files,languages)
        blocked={e['path'] for e in parsed['entities'] if not guard.api.assess([{'callee':e['callee']}],guard.ids,guard.keys)['allowed']}
        if blocked:
            parsed['entities']=[e for e in parsed['entities'] if e['path'] not in blocked]
            parsed['gaps'].extend(dict(path=p,reason='guard_protected_callee_family',source_analysis_unavailable=True) for p in sorted(blocked))
        if len(cache)>8:cache.pop(next(iter(cache)))
        cache[key]=copy.deepcopy(parsed);return parsed
    analysis.snapshot_files=guarded_snapshot;analysis.detect_snapshot=guarded_detect
    finish_cache=install(detector)
    finish_scope_index=install_scope_index(detector)
    finish_evaluation_cache=install_evaluation_cache(detector)
    finish_file_cache=install_file_cache(detector,accessed_imports=os.environ.get('SWECHAT_PYTHON_FILE_CACHE_MODE')=='accessed-imports')
    finish_matching_cache=install_matching_cache(analysis,matching)
    try: detected=bounded_detect(analysis,repo,mined,config,{r['commit_sha'] for r in selected})
    finally:
        analysis.snapshot_files=original_snapshot;analysis.detect_snapshot=original_detect
        matching_cache_stats=finish_matching_cache()
        file_cache_stats=finish_file_cache()
        pure_cache_stats=finish_cache()
        scope_index_stats=finish_scope_index()
        evaluation_cache_stats=finish_evaluation_cache()
    progress('detected',events=len(detected['events']),snapshots=len(detected['snapshots']))
    dump(directory/'detection_diagnostics.json',dict(snapshots=[dict(sha=s['sha'],entities=len(s['entities']),available_files=len(s['available_paths']),unavailable_files=len(s['unavailable_paths'])) for s in detected['snapshots']], audit_counts=dict(Counter(a['reason'] for a in detected['audit']))))
    event_candidates=defaultdict(list)
    bysha=defaultdict(list)
    for e in detected['events']:bysha[e['sha']].append(e)
    for candidate,row in zip(selected,ledger):
        matches=[e for e in bysha[candidate['commit_sha']] if match_anchor(candidate,e)]
        if len(matches)==1:
            event_candidates[matches[0]['id']].append(row['log_id'])
            row.update(status='anchor_mapped',original_event_id=matches[0]['id'],mapping_basis='same_repository_sha_path_exact_line_range_and_contained_source_statement')
        else:row.update(status='anchor_ambiguous' if matches else 'anchor_not_observed',anchor_match_count=len(matches),followup_ids=[])
    # Frozen, read-only input; identical repository gap lists are stored once.
    all_gaps=tuple(mined['gaps']+detected['gaps'])
    trace_with_shared_gaps=TraceGapStorage(lineage,all_gaps)
    traces={k:[] for k in ['log_changes','followups','provenance','target_branch_integration_events']}
    initial_shas=sorted({r['commit_sha'] for r in selected})
    for context_index,sha in enumerate(initial_shas,1):
        ids={e['id'] for e in bysha[sha] if e['id'] in event_candidates}
        if not ids:continue
        context=dict(id=stable_id(rid,sha,'commit_context'),repository=name,pr_number=None,pr_url=None,
            cohort='swechat_existing_stage1',is_synthetic=False,commit_shas=[sha],head_sha=sha,
            metadata_source='SWE-chat_stage1_commit_context_not_a_claimed_PR',provided_label=None)
        repo['pr_ids']=[context['id']]
        # Only exact stage-one anchors become origins; all later events remain available.
        events=[e for e in detected['events'] if e['sha']!=sha or e['id'] in ids]
        t=trace_with_shared_gaps([repo],[context],[mined],events,detected['snapshots'],receipt['finished_at'],config['observation']['days'],all_gaps)
        for case in t['log_changes']:
            case['stage1_log_ids']=event_candidates[case['log_change_id']]
            case['stage1_attribution']=[{k:r[k] for k in ['log_id','attribution_grade','file_attribution_labels']} for r in selected if r['log_id'] in case['stage1_log_ids']]
        for k in traces:traces[k].extend(t[k])
        progress('tracing',contexts_considered=context_index,total_contexts=len(initial_shas),origins=len(traces['log_changes']),followup_rows=len(traces['followups']))
    actual=[f for f in traces['followups'] if f['change_kind'] not in {'coverage_gap','gap_resumed'}]
    intervals=[f for f in traces['followups'] if f['change_kind'] in {'coverage_gap','gap_resumed'}]
    bycase=defaultdict(list)
    for f in actual:bycase[f['case_id']].append(f)
    cases={i:c for c in traces['log_changes'] for i in c['stage1_log_ids']}
    for row in ledger:
        c=cases.get(row['log_id'])
        if c:
            fs=bycase[c['case_id']]
            row.update(case_id=c['case_id'],followup_ids=[f['id'] for f in fs],status='observed_followup' if fs else c['followup_status'],
                censoring_reason=c['censoring_reason'],integration_sha=c['integration_sha'],lineage_status=c['lineage_status'],
                observation_gap_count=len(c['observation_gaps']))
            if not fs and c['followup_status']=='observed_followup':row['status']='coverage_interval_only'
    # Export only evidence used by these cases/events. Never export unrelated protected code.
    needed={i for e in actual+traces['log_changes'] for i in e.get('file_change_ids',[])}
    safe_files=[]
    for fc in mined['changes']:
        if fc['id'] not in needed:continue
        checks=[guard.check(name,fc[k],fc[side+'_source']) for side,k in [('before','old_path'),('after','new_path')] if fc.get(side+'_source') is not None and fc.get(k)]
        if all(s=='allowed' for s in checks):safe_files.append(fc)
    # Protected paths in repository-wide gaps are not published as review examples.
    gap_counts=Counter((g.get('stage'),g.get('error_type')) for g in all_gaps)
    for c in traces['log_changes']:
        c['coverage_gaps']=[{'stage':stage,'error_type':typ,'count':n} for (stage,typ),n in sorted(gap_counts.items(),key=str)]
    for n,rows in [('repositories',[repo]),('commits',mined['commits']),('file_changes',safe_files),('candidate_ledger',ledger),
                   ('log_changes',traces['log_changes']),('followups',actual),('coverage_intervals',intervals),
                   ('target_branch_integration_events',traces['target_branch_integration_events'])]:jl(directory/(n+'.jsonl'),rows)
    dump(directory/'history_scope.json',dict(history_scope=mined.get('history_scope'),mining_platform=mined.get('platform_adapter'),metrics=mined['metrics'],
        selected_shas=mined['selected_shas'],graph=mined['graph'],first_parent_shas=mined['first_parent_shas'],
        guard_calls=dict(guard.calls),exact_detector_cache=pure_cache_stats,python_scope_index=scope_index_stats,python_evaluation_cache=evaluation_cache_stats,python_file_cache=file_cache_stats,matching_cache=matching_cache_stats,storage_adapter=detected.get('storage_adapter'),lineage_gap_storage=trace_with_shared_gaps.statistics(),gap_counts=[dict(stage=k[0],reason=k[1],count=v) for k,v in gap_counts.items()],config=config))
    s=dict(repository=name,status='executed',candidates=len(ledger),mapped_candidates=len(cases),origins=len(traces['log_changes']),events=len(actual),coverage_intervals=len(intervals),
        initial_logs_with_changes=sum(bool(r.get('followup_ids')) for r in ledger),commits=len(mined['commits']),seconds=round(time.time()-start),ledger_status=dict(Counter(r['status'] for r in ledger)))
    dump(directory/'summary.json',s);progress('complete',**{k:v for k,v in s.items() if k!='repository'});return s

if __name__=='__main__':
    ap=argparse.ArgumentParser();ap.add_argument('--repository',required=True);args=ap.parse_args()
    try:execute(args.repository)
    except Exception:
        p=OUT/'repositories'/args.repository.replace('/','--');p.mkdir(parents=True,exist_ok=True)
        (p/'execution_error.txt').write_text(traceback.format_exc(),encoding='utf-8');raise

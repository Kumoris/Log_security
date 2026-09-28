"""Frozen SWE-chat output-unit pilot, paired evidence analysis and durable batches.

All Git reads are local. Target source is data, never imported or executed.
"""
from __future__ import annotations
import argparse
import ast
from collections import Counter, defaultdict
from contextlib import contextmanager
from datetime import datetime, timezone
import fcntl
import gzip
import heapq
import tempfile
import inspect
from concurrent.futures import ProcessPoolExecutor
import hashlib
from importlib import metadata
import json
import os
from pathlib import Path
import platform
import re
import resource
import shutil
import signal
import sqlite3
import subprocess
import sys
import time
import uuid

from .storage import atomic_write, canonical, stable_id

PROJECT = Path(__file__).resolve().parents[2]
DEFAULT_CONFIG = PROJECT / 'configs/screening_v1.json'
SCHEMA = 'screening-ledger-1'
VARIANTS = ('baseline', 'dfg_augmented')


def now():
    return datetime.now(timezone.utc).isoformat()


def digest(value):
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def resolved_data_path(path):
    p=Path(path)
    return p if p.exists() else Path(str(p)+'.gz')


def file_hash(path):
    original=Path(path);actual=resolved_data_path(path)
    opener=gzip.open if actual!=original else open
    h=hashlib.sha256()
    with opener(actual,'rb') as f:
        for chunk in iter(lambda:f.read(1048576),b''):h.update(chunk)
    return h.hexdigest()


def write(path,value):
    atomic_write(Path(path),canonical(value)+'\n')


def write_rows(path,items):
    path=Path(path)
    if path.parent.name=='discovery' and path.name in {'output_units.jsonl','file_coverage.jsonl'}:
        path=Path(str(path)+'.gz')
    path.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
    fd,temp=tempfile.mkstemp(dir=path.parent,prefix=path.name+'.');os.close(fd)
    try:
        opener=gzip.open if path.suffix=='.gz' else open
        with opener(temp,'wt',encoding='utf-8') as stream:
            for item in items:stream.write(canonical(item)+'\n')
        os.replace(temp,path)
    finally:
        if os.path.exists(temp):os.unlink(temp)


def rows(path):
    actual=resolved_data_path(path)
    opener=gzip.open if actual.suffix=='.gz' else open
    with opener(actual,'rt',encoding='utf-8') as f:
        for line in f:
            if line.strip():yield json.loads(line)


def read(path):
    return json.loads(Path(path).read_text())


def config(path=None):
    c = read(path or DEFAULT_CONFIG)
    if not 1 <= c['batch_case_limit'] <= 100: raise ValueError('batch_limit_must_be_1_to_100')
    if c.get('network') or c.get('ai_review') or c.get('target_execution'):
        raise ValueError('this_runner_is_offline_without_model_or_target_execution')
    for key,lo,hi in [('max_nodes',1,1000),('max_chars',1,48000),('max_hops',1,4),('max_caller_hops',0,4)]:
        if type(c['dfg'][key]) is not int or not lo<=c['dfg'][key]<=hi:raise ValueError('invalid_dfg_budget:'+key)
    for key in ['max_source_bytes','max_dependency_files','max_dependency_bytes','max_case_seconds','discovery_file_seconds']:
        if not isinstance(c[key],(int,float)) or c[key]<=0:raise ValueError('invalid_budget:'+key)
    return c


def code_version():
    sources = {str(p.relative_to(PROJECT)): file_hash(p)
               for p in sorted((PROJECT / 'src/agentlog_unified').glob('*.py'))}
    for p in [PROJECT / 'pyproject.toml', *sorted((PROJECT / 'configs').glob('screening*'))]:
        if p.is_file(): sources[str(p.relative_to(PROJECT))] = file_hash(p)
    deps = {}
    for name in ['PyDriller', 'GitPython', 'PyYAML', 'Pygments', 'jsonschema', 'tree-sitter',
                 'tree-sitter-javascript', 'tree-sitter-typescript', 'tree-sitter-go', 'tree-sitter-java']:
        try: deps[name] = metadata.version(name)
        except metadata.PackageNotFoundError: deps[name] = None
    p = subprocess.run(['git', '-C', str(PROJECT), 'rev-parse', 'HEAD'], capture_output=True, text=True)
    status = subprocess.run(['git', '-C', str(PROJECT), 'status', '--porcelain'], capture_output=True, text=True)
    return {'schema': SCHEMA, 'sources': sources, 'python': platform.python_version(),
            'dependencies': deps, 'git_head': p.stdout.strip() if p.returncode == 0 else None,
            'workspace_status': status.stdout if status.returncode == 0 else 'git_metadata_unavailable',
            'rules': 'screening-policy-v1', 'split_version': 'screening-output-split-1'}


def snapshot_code(out, version):
    out = Path(out)
    for rel, expected in version['sources'].items():
        src = PROJECT / rel
        if file_hash(src) != expected: raise ValueError('code_changed_during_snapshot')
        dest = out / 'source' / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(src, dest)
        os.chmod(dest, 0o600)
    write(out / 'version.json', version)
    p = subprocess.run(['git', '-C', str(PROJECT), 'diff', '--no-ext-diff', '--no-textconv', 'HEAD'], capture_output=True)
    if p.returncode == 0: atomic_write(out / 'uncommitted.patch', p.stdout.decode())


@contextmanager
def deadline(seconds):
    def expired(*_): raise TimeoutError('case_time_budget_exceeded')
    old = signal.signal(signal.SIGALRM, expired)
    signal.setitimer(signal.ITIMER_REAL, seconds)
    try: yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, old)


@contextmanager
def database(path):
    path = Path(path); path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    with path.with_suffix('.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        db = sqlite3.connect(path); db.row_factory = sqlite3.Row; os.chmod(path, 0o600)
        try: yield db
        finally: db.close()


def precheck(out, old, cfg):
    out, old = Path(out), Path(old)
    inputs = [PROJECT/'data/inputs/swechat-full-v3/commit_contexts.jsonl', old / 'preparation.json',
              old / 'final/input.jsonl', old / 'final/batch/batch.sqlite', old / 'risk_candidates.csv']
    v = code_version()
    report = {'created_at': now(), 'code': v, 'config': cfg, 'config_sha256': digest(cfg),
              'inputs': {str(p): {'exists': p.exists(), 'sha256': file_hash(p) if p.exists() else None} for p in inputs},
              'git_head_reason': 'not_a_git_repository' if v['git_head'] is None else None,
              'existing_dfg_export_hard_limit': 100, 'batch_case_limit': cfg['batch_case_limit'],
              'backend': 'existing PyDriller Repository/Git plus explicitly labeled Git object reads',
              'legacy_discovery_scope': 'diff_intersection_or_bounded_dependency_change',
              'new_discovery_scope': cfg['scope'], 'target_code_executed': False}
    write(out / 'precheck/current.json', report)
    snapshot_code(out / 'precheck/execution-code', v)
    return report


def near_key(case, source, cache=None):
    """Group normalized enclosing syntax with one parse per historical file."""
    cache={} if cache is None else cache
    if 'segments' not in cache:
        segments=[]
        if case['path'].endswith('.py'):
            try:
                tree=ast.parse(source)
                for n in ast.walk(tree):
                    if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef)):
                        segments.append((n.lineno,n.end_lineno,ast.get_source_segment(source,n) or source))
            except (SyntaxError,ValueError,RecursionError):pass
        cache['segments']=segments;cache['hashes']={}
    line=case.get('log_anchor',{}).get('line',0)
    choices=[x for x in cache['segments'] if x[0]<=line<=x[1]]
    selected=min(choices,key=lambda x:x[1]-x[0]) if choices else (0,0,source)
    key=selected[:2]
    if key not in cache['hashes']:
        # AST dumps hide literal values but preserve function/name structure;
        # lexical full-file fallback groups whitespace-normalized copies.
        segment=selected[2]
        segment=re.sub(r'\b\d+(?:\.\d+)?\b','<number>',segment)
        segment=re.sub(r'\s+','',segment)
        cache['hashes'][key]=hashlib.sha256(segment.encode()).hexdigest()
    return cache['hashes'][key]


def discover_version(task):
    from .screening_evidence import discover_outputs, discover_file_status
    v,cfg=task
    repo_path=v['repo_path']
    cases = []; source = None; t = time.perf_counter()
    if v['source_state'] == 'present':
        source = Path(v['source_path']).read_bytes().decode('utf-8')
        try:
            with deadline(cfg['discovery_file_seconds']):
                cases = discover_outputs(v['repository'], v['sha'], v.get('parent_sha'),
                    v['source_sha'], v['side'], v['path'], source, files={v['path']:source})
            v.update(processing_status='success', reason='logs_discovered' if cases else 'no_logs_detected')
            with deadline(cfg['discovery_file_seconds']):
                file_status = discover_file_status(v['path'], source)
            v['parser_and_output_support'] = file_status
            if file_status.get('reason_codes') and not cases:
                v.update(processing_status='blocked', reason=';'.join(file_status['reason_codes']))
            if v['path'].endswith('.py'):
                try: ast.parse(source)
                except (SyntaxError,ValueError,RecursionError):
                    v.update(processing_status='blocked',reason='python_parse_failed')
        except Exception as exc:
            v.update(processing_status='blocked', reason=type(exc).__name__)
    else:
        v['processing_status'] = 'excluded' if v['source_state']=='absent_verified' else 'blocked'
    near_cache={}
    for case in cases:
        case['function_scope'] = case.get('scope')
        case.update(file_version_id=v['file_version_id'], input_record_ids=v.get('input_record_ids',[]),
            commit_id=v['commit_id'], repo_path=repo_path, source_path=v['source_path'],
            old_path=v.get('old_path'), new_path=v.get('new_path'),
            legacy_stratum=v.get('old_stratum','not_hit'), legacy_log_ids=v.get('old_log_ids',[]),
            near_duplicate_key=near_key(case,source,near_cache), scope=v.get('scope',case.get('scope','unknown')),
            attribution={'commit_association':'SWE-chat input linkage', 'granularity':'commit',
                         'output_unit_authorship':'unknown','agent_introduction':'unknown',
                         'evidence_ids':v.get('input_record_ids',[])})
    v.update(output_units=len(cases), elapsed_seconds=time.perf_counter()-t)
    return v,cases


def parallel_discover(source_rows,cfg):
    # Small bounded queue; source extraction and framework-only parsers overlap.
    with ProcessPoolExecutor(max_workers=3) as pool:
        pending=[]
        for v in source_rows:
            pending.append(pool.submit(discover_version,(v,cfg)))
            if len(pending)>=12:yield pending.pop(0).result()
        for future in pending:yield future.result()


def discovery_code():
    v=code_version()
    excluded={'src/agentlog_unified/'+x+'.py' for x in ['screening','screening_compare','screening_policy','screening_review','cli']}
    return {'dependencies':{p:h for p,h in v['sources'].items() if p not in excluded and not p.startswith('configs/')},
            'python':v['python'],'versions':v['dependencies'],
            'functions':{f.__name__:hashlib.sha256(inspect.getsource(f).encode()).hexdigest()
                         for f in [discover_version,parallel_discover,discover,near_key]}}


def discover(out, cfg, max_files=None):
    from .screening_history import iter_historical_sources
    from .screening_evidence import discover_outputs, discover_file_status
    out = Path(out); source_manifest = out / 'population/file_versions.jsonl'
    fingerprint = {'input': file_hash(source_manifest), 'config': digest(cfg), 'code': digest(discovery_code())}
    dest = out / 'discovery'; dest.mkdir(parents=True, exist_ok=True)
    marker = dest / 'manifest.json'
    if marker.exists() and read(marker)['fingerprint'] != fingerprint:
        raise ValueError('discovery_input_code_config_changed_use_new_run')
    write(marker, {'fingerprint': fingerprint, 'scope': cfg['scope'], 'created_at': now()})
    if not (dest/'execution-code/version.json').exists():snapshot_code(dest/'execution-code',code_version())
    count = 0; tick = time.perf_counter(); grouped = defaultdict(list)
    for fv in rows(source_manifest): grouped[fv['repo_path']].append(fv)
    with database(dest / 'checkpoint.sqlite') as db:
        db.executescript('CREATE TABLE IF NOT EXISTS files(id TEXT PRIMARY KEY,data TEXT); CREATE TABLE IF NOT EXISTS cases(id TEXT PRIMARY KEY,data TEXT);')
        complete = {r[0] for r in db.execute('SELECT id FROM files')}
        for repo_path, versions in sorted(grouped.items()):
            pending = [v for v in versions if v['file_version_id'] not in complete]
            supported = []
            for v in pending:
                if Path(v.get('path') or v.get('new_path') or v.get('old_path') or '').suffix.lower() not in {'.py','.js','.mjs','.cjs','.ts','.jsx','.tsx','.go','.java','.cs'}:
                    data = {**v, 'processing_status': 'excluded', 'reason': 'unsupported_or_non_code_extension', 'output_units': 0}
                    db.execute('INSERT INTO files VALUES(?,?)', (v['file_version_id'],canonical(data)))
                else: supported.append(v)
            db.commit()
            if max_files is not None: supported = supported[:max(0, max_files-count)]
            source_rows=iter_historical_sources(repo_path, supported, dest, max_bytes=cfg['max_source_bytes'])
            for v,cases in parallel_discover(source_rows,cfg):
                for case in cases:
                    db.execute('INSERT INTO cases VALUES(?,?)',(case['case_id'],canonical(case)))
                db.execute('INSERT INTO files VALUES(?,?)',(v['file_version_id'],canonical(v))); db.commit()
                count += 1
                if count % 250 == 0: print(canonical({'stage':'discover','files_this_call':count}), flush=True)
            if max_files is not None and count >= max_files: break
        actual = [json.loads(r[0]) for r in db.execute('SELECT data FROM files ORDER BY id')]
        cases = [json.loads(r[0]) for r in db.execute('SELECT data FROM cases ORDER BY id')]
        recorded = {r['file_version_id'] for r in actual}
        all_rows = list(rows(source_manifest))
        actual += [{**r,'processing_status':'pending','reason':'not_processed_this_invocation','output_units':0}
                   for r in all_rows if r['file_version_id'] not in recorded]
    write_rows(dest / 'file_coverage.jsonl',actual); write_rows(dest / 'output_units.jsonl',cases)
    report = {'file_versions':len(all_rows),'file_records':len(actual),'output_units':len(cases),
              'log_versions':len({c['log_id'] for c in cases}), 'files_this_call':count,
              'status_counts':dict(Counter(r['processing_status'] for r in actual)),
              'reasons':dict(Counter(r.get('reason') for r in actual)),
              'languages':dict(Counter(c['language'] for c in cases)),
              'elapsed_seconds':time.perf_counter()-tick,
              'frame_sha256':file_hash(dest/'output_units.jsonl'),
              'coverage_limitations':['unmodified_reverse_dependents_not_scanned',
                'cross_file_wrappers_not_discovered_by_single_file_frame_scan',
                'unsupported_log_frameworks_and_dynamic_wrappers_unknown']}
    write(dest/'coverage.json',report); return report


class Groups:
    def __init__(self): self.parent={}
    def find(self, x):
        self.parent.setdefault(x,x)
        if self.parent[x]!=x:self.parent[x]=self.find(self.parent[x])
        return self.parent[x]
    def join(self,a,b):
        a,b=self.find(a),self.find(b)
        if a!=b:self.parent[max(a,b)]=min(a,b)


def stratified(cases, n, seed):
    buckets=defaultdict(list)
    for c in cases: buckets[(c.get('sampling_stratum',c.get('legacy_stratum','not_hit')),c['language'])].append(c)
    for key in buckets: buckets[key].sort(key=lambda c:digest([seed,c['case_id']]))
    picked=[];counts=Counter()
    while len(picked)<n:
        progressed=False
        for key in sorted(buckets):
            if buckets[key] and len(picked)<n:
                picked.append(buckets[key].pop(0));counts['|'.join(key)]+=1;progressed=True
        if not progressed:break
    return picked,dict(counts)


def freeze_context(case, out, cfg):
    """Finite exact-tree local imports; missing dependencies are named gaps."""
    from .git_support import run_git, read_blob
    source=Path(case['source_path']).read_bytes().decode('utf-8')
    if hashlib.sha256(source.encode()).hexdigest()!=case['source_sha256']:
        raise ValueError('historical_source_hash_mismatch')
    files={case['path']:source};gaps=[];pending=[case['path']];total=len(source.encode())
    while pending and len(files)<cfg['max_dependency_files']:
        path=pending.pop(0)
        if not path.endswith('.py'): continue
        try: tree=ast.parse(files[path])
        except (SyntaxError,ValueError,RecursionError): continue
        modules=[]
        for node in ast.walk(tree):
            if isinstance(node,ast.Import): modules += [a.name.replace('.','/') for a in node.names]
            elif isinstance(node,ast.ImportFrom):
                base=Path(path).parent
                if node.level:
                    for _ in range(node.level-1):base=base.parent
                    prefix=str(base / (node.module or '').replace('.','/')).lstrip('./')
                else:prefix=(node.module or '').replace('.','/')
                modules.append(prefix)
                modules += [(prefix+'/'+a.name.replace('.','/')).lstrip('/') for a in node.names if a.name!='*']
        for mod in sorted(set(modules)):
            found=False
            for candidate in [mod+'.py',mod+'/__init__.py',str(Path(path).parent/(mod+'.py'))]:
                if candidate in files:found=True;break
                if len(files)>=cfg['max_dependency_files']:
                    gaps.append('dependency_file_budget_exceeded');break
                try: text,status=read_blob(case['repo_path'],case['source_sha'],candidate,cfg['max_source_bytes'])
                except Exception:status='object_unavailable';text=None
                if status=='ok':
                    if total+len(text.encode())>cfg['max_dependency_bytes']:
                        gaps.append('dependency_bytes_budget_exceeded');break
                    files[candidate]=text;pending.append(candidate);total+=len(text.encode());found=True;break
            if not found:gaps.append('import_unresolved:'+mod)
    versions=[{'path':p,'sha':case['source_sha'],'source_sha256':hashlib.sha256(s.encode()).hexdigest()} for p,s in sorted(files.items())]
    snapshot_id=digest([case['repository'],case['source_sha'],versions])
    path=Path(out)/'private/snapshots'/(snapshot_id+'.json')
    write(path,{'repository':case['repository'],'source_sha':case['source_sha'],'files':files,
                'source_versions':versions,'gaps':sorted(set(gaps)),
                'backend':'GitPython_exact_tree_auxiliary_dependency_read_not_PyDriller_mining'})
    return {**case,'source_versions':versions,'snapshot_ref':str(path),'snapshot_sha256':file_hash(path),
            'dependency_gaps':sorted(set(gaps))}


def active_frame(out):
    out=Path(out)
    manifest=out/'discovery/source-hash-repair.json'
    if manifest.exists():
        m=read(manifest);path=Path(m['output_path'])
        if file_hash(path)!=m['output_physical_sha256']:raise ValueError('repaired_frame_hash_mismatch')
        return path
    return out/'discovery/output_units.jsonl'


def freeze(out,cfg):
    out=Path(out);dest=out/'selection'
    if (dest/'manifest.json').exists():raise ValueError('selection_already_frozen')
    frame=active_frame(out);groups=Groups();near={}
    for c in rows(frame):
        groups.find(c['repository']);key=c['near_duplicate_key']
        if key in near:groups.join(c['repository'],near[key])
        else:near[key]=c['repository']
    membership={r:groups.find(r) for r in groups.parent}
    distinct=sorted(set(membership.values()),key=lambda g:digest([cfg['seed'],'split',g]))
    count=max(1,round(len(distinct)*cfg['holdout_fraction'])) if len(distinct)>1 else 0
    hold=set(distinct[:count]);buckets=defaultdict(list);counts=Counter();all_ids=[]
    legacy_path=out/'population/old_log_observations.jsonl'
    legacy={r['legacy_log_id']:r for r in rows(legacy_path)} if legacy_path.exists() else {}
    def split_rows():
        for c in rows(frame):
            obs=[legacy[x] for x in c.get('legacy_log_ids',[]) if x in legacy]
            c['sampling_stratum']=('legacy_candidate' if any(o.get('privacy_assessment') in {'supported','possible','conditional'} for o in obs)
                else 'legacy_unknown' if any(o.get('privacy_assessment')=='unknown' or o.get('unknown_needs_review') for o in obs)
                else 'legacy_no_hit' if obs else 'legacy_no_log_observation')
            split='evaluation' if membership[c['repository']] in hold else 'engineering'
            c.update(split=split,group_id=stable_id('repo_and_normalized_enclosing_syntax',membership[c['repository']]))
            key=(split,c['sampling_stratum'],c['language']);counts[key]+=1;all_ids.append(c['case_id'])
            heap=buckets[key];limit=cfg['sample_size'] if split=='engineering' else cfg['evaluation_size']
            heapq.heappush(heap,(-int(digest([cfg['seed'],c['case_id']]),16),c['case_id'],c))
            if len(heap)>limit:heapq.heappop(heap)
            yield {k:c[k] for k in ['case_id','repository','group_id','split']}
    write_rows(dest/'groups.jsonl',split_rows())
    dev=[x[2] for k,heap in buckets.items() if k[0]=='engineering' for x in heap]
    evaluation=[x[2] for k,heap in buckets.items() if k[0]=='evaluation' for x in heap]
    chosen,quotas=stratified(dev,cfg['sample_size'],cfg['seed'])
    eval_chosen,eval_quotas=stratified(evaluation,cfg['evaluation_size'],cfg['seed'])
    chosen=[freeze_context(c,out,cfg) for c in chosen];eval_chosen=[freeze_context(c,out,cfg) for c in eval_chosen]
    write_rows(dest/'engineering.jsonl',chosen);write_rows(dest/'evaluation.jsonl',eval_chosen)
    write_rows(dest/'pair_context.jsonl',[])  # No extra analysed units added to the fixed denominator.
    limit=cfg['batch_case_limit']
    def batches(ids):
        return ({'batch_id':i//limit,'case_ids':ids[i:i+limit]} for i in range(0,len(ids),limit))
    write_rows(dest/'batches.jsonl',batches([c['case_id'] for c in chosen]))
    write_rows(dest/'full_batches.jsonl',batches(sorted(all_ids)));write(dest/'config.json',cfg)
    result={'created_at':now(),'population_sha256':file_hash(out/'population/file_versions.jsonl'),
        'frame_sha256':file_hash(frame),'frame_artifact':str(resolved_data_path(frame)),'selection_sha256':file_hash(dest/'engineering.jsonl'),
        'evaluation_sha256':file_hash(dest/'evaluation.jsonl'),'groups_sha256':file_hash(dest/'groups.jsonl'),
        'batches_sha256':file_hash(dest/'batches.jsonl'),'full_batches_sha256':file_hash(dest/'full_batches.jsonl'),
        'config_sha256':digest(cfg),'seed':cfg['seed'],'strata':'mutually exclusive legacy file assessment x language; round robin, no replacement',
        'stratum_information_time':'before_new_DFG','quotas':quotas,'evaluation_quotas':eval_quotas,
        'group_rule':'whole_repository_union_normalized_enclosing_syntax_hash; arbitrary semantic near duplicates not guaranteed',
        'groups':len(distinct),'holdout_groups':count,
        'engineering_frame':sum(v for k,v in counts.items() if k[0]=='engineering'),
        'evaluation_frame':sum(v for k,v in counts.items() if k[0]=='evaluation'),
        'primary_selected':len(chosen),'evaluation_selected':len(eval_chosen),'full_output_frame':len(all_ids),
        'full_batch_count':(len(all_ids)+limit-1)//limit,'batch_limit':limit,
        'replacement_policy':'no_replacement_for_failure_or_outcome','ai_or_human_in_primary_AB':False,
        'frame_coverage':'observed_recoverable_output_units_only; full_source_discovery_disk_blocked',
        'population_prevalence_claim':False}
    write(dest/'manifest.json',result);return result


def load_selected(out):
    out=Path(out);m=read(out/'selection/manifest.json');c=read(out/'selection/config.json')
    for name,key in [('engineering.jsonl','selection_sha256'),('evaluation.jsonl','evaluation_sha256'),
                     ('groups.jsonl','groups_sha256'),('batches.jsonl','batches_sha256')]:
        if file_hash(out/'selection'/name)!=m[key]:raise ValueError('frozen_manifest_hash_mismatch:'+name)
    if digest(c)!=m['config_sha256']:raise ValueError('frozen_config_changed')
    return list(rows(out/'selection/engineering.jsonl')),c,m


def analysis_identity(case,variant,signature):
    return stable_id('analysis',case['case_id'],variant,signature,
                     case['source_versions'],case['snapshot_sha256'])


def execute_batches(out,label='main',batch_ids=None,resume=False,interrupt_after=None,retry_failed=False):
    from .screening_evidence import analyze_dfg
    from .screening_policy import assess
    from .semantic_dfg import svg
    from .screening_history import extract_commit
    out=Path(out);cases,cfg,manifest=load_selected(out);version=code_version()
    signature=digest({'code':version,'config':cfg,'selection':manifest['selection_sha256']})
    dest=out/'analyses'/label;stamp=dest/'signature.json'
    if stamp.exists():
        if read(stamp)['signature']!=signature:raise ValueError('analysis_code_config_or_selection_changed_use_new_label')
        if not resume:raise ValueError('analysis_exists_use_resume')
    else:
        snapshot_code(dest/'execution-code',version)
        write(stamp,{'signature':signature,'code':version,'selection_sha256':manifest['selection_sha256'],
                     'config_sha256':digest(cfg),'created_at':now()})
    selected_batches=[b for b in rows(out/'selection/batches.jsonl') if batch_ids is None or b['batch_id'] in batch_ids]
    lookup={c['case_id']:c for c in cases};processed=0;hits=0;start=time.perf_counter()
    # Record a real PyDriller traversal for every selected event before analysis.
    extraction={}
    for case in cases:
        key=(case['repository'],case['event_sha'])
        if key in extraction:continue
        path=dest/'mining'/stable_id(*key)
        marker=path/'runner-extraction.json'
        if marker.exists():
            r=read(marker)
            if r['code_signature']!=signature:raise ValueError('mining_cache_signature_mismatch')
            if not (retry_failed and r['result'].get('status')!='success'):
                extraction[key]=r['result'];continue
        try:r=extract_commit(case['repo_path'],case['repository'],case['event_sha'],path)
        except Exception as exc:r={'status':'blocked','reason':type(exc).__name__,'file_versions':[]}
        write(marker,{'result':r,'code_signature':signature,'backend':'actual_PyDriller_extraction'})
        extraction[key]=r
    with database(dest/'checkpoint.sqlite') as db:
        db.executescript('''CREATE TABLE IF NOT EXISTS attempts(id TEXT PRIMARY KEY,analysis_id TEXT,case_id TEXT,variant TEXT,status TEXT,data TEXT);
          CREATE TABLE IF NOT EXISTS results(analysis_id TEXT PRIMARY KEY,case_id TEXT,variant TEXT,data TEXT,UNIQUE(case_id,variant));
          CREATE TABLE IF NOT EXISTS batches(id INTEGER PRIMARY KEY,status TEXT,data TEXT);''')
        db.execute("UPDATE attempts SET status='interrupted' WHERE status='started'");db.commit()
        for batch in selected_batches:
            db.execute('INSERT OR REPLACE INTO batches VALUES(?,?,?)',(batch['batch_id'],'running',canonical(batch)));db.commit()
            for cid in batch['case_ids']:
                case=lookup[cid]
                for variant in VARIANTS:
                    aid=analysis_identity(case,variant,signature)
                    existing=db.execute('SELECT data FROM results WHERE analysis_id=?',(aid,)).fetchone()
                    if existing and not (retry_failed and json.loads(existing[0])['processing_status']=='blocked'):
                        r=json.loads(existing[0])
                        for rel,expected in r.get('artifact_hashes',{}).items():
                            if not (dest/rel).exists() or file_hash(dest/rel)!=expected:raise ValueError('cached_evidence_hash_mismatch')
                        if file_hash(case['snapshot_ref'])!=case['snapshot_sha256']:raise ValueError('cached_snapshot_changed')
                        hits+=1;continue
                    attempt=str(uuid.uuid4());began=now();t=time.perf_counter();cpu=time.process_time()
                    db.execute('INSERT INTO attempts VALUES(?,?,?,?,?,?)',(attempt,aid,cid,variant,'started',canonical({'started_at':began})));db.commit()
                    if interrupt_after is not None and processed>=interrupt_after:
                        raise InterruptedError('injected_interruption_after_durable_attempt_start')
                    dfg=None;error=None;artifacts={};files={}
                    try:
                        if file_hash(case['snapshot_ref'])!=case['snapshot_sha256']:raise ValueError('snapshot_hash_mismatch')
                        fresh=extraction[(case['repository'],case['event_sha'])]
                        candidates=[f for f in fresh.get('file_versions',[]) if f.get('source_sha')==case['source_sha'] and f.get('side')==case['side'] and f.get('path')==case['path']]
                        if len(candidates)!=1 or candidates[0].get('source_state')!='present' or candidates[0].get('source_sha256')!=case['source_sha256']:
                            raise ValueError('fresh_PyDriller_historical_case_verification_failed')
                        snapshot=read(case['snapshot_ref'])
                        if snapshot['source_sha']!=case['source_sha']:raise ValueError('snapshot_SHA_mismatch')
                        files=snapshot['files']
                        if [{'path':p,'sha':case['source_sha'],'source_sha256':hashlib.sha256(s.encode()).hexdigest()} for p,s in sorted(files.items())]!=case['source_versions']:
                            raise ValueError('dependency_source_hash_mismatch')
                        if variant=='dfg_augmented':
                            with deadline(cfg['max_case_seconds']):
                                dfg=analyze_dfg(case,files,{**cfg['dfg'],'snapshot_sha':case['source_sha'],'source_versions':case['source_versions']})
                            if dfg.get('graph'):
                                for suffix,content in [('json',canonical(dfg['graph'])+'\n'),('svg',svg(dfg['graph']))]:
                                    rel='graphs/'+aid+'/'+attempt+'.'+suffix;atomic_write(dest/rel,content);artifacts[rel]=file_hash(dest/rel)
                        evidence=dfg.get('evidence') if dfg else None
                        result=assess(case,case['base_evidence'],evidence)
                    except Exception as exc:
                        error=type(exc).__name__+(':'+str(exc) if isinstance(exc,(ValueError,TimeoutError)) else '')
                        failure={'processing_status':'blocked','critical_unknowns':[error], 'risk_clues':[]}
                        base_result=assess(case,case['base_evidence'],None)
                        if variant=='dfg_augmented' and files and base_result['queue']=='A' and not isinstance(exc,ValueError):
                            preserved={**case['base_evidence'],'processing_status':'partial','noncritical_unknowns':case['base_evidence'].get('noncritical_unknowns',[])+[error]}
                            result=assess(case,preserved,None)
                        else:result=assess(case,{**case['base_evidence'],**failure},None)
                    input_index={'case_id':cid,'variant':variant,'base_evidence':case['base_evidence'],
                                 'base_sha256':digest(case['base_evidence']),
                                 'dfg_evidence':dfg.get('evidence') if dfg else None,'snapshot_sha256':case['snapshot_sha256'],
                                 'source_versions':case['source_versions'],'code_signature':signature}
                    rel='evidence/'+aid+'/'+attempt+'.json';write(dest/rel,input_index);artifacts[rel]=file_hash(dest/rel)
                    record={'case_id':cid,'analysis_id':aid,'attempt_id':attempt,'variant':variant,'batch_id':batch['batch_id'],
                            'queue':result['queue'],'assessment':result,
                            'processing_status':'blocked' if error else (dfg.get('processing_status') if dfg else result.get('processing_status','success')),
                            'failure_reason':error,'artifact_hashes':artifacts,'base_evidence_sha256':digest(case['base_evidence']),
                            'elapsed_seconds':time.perf_counter()-t,'cpu_seconds':time.process_time()-cpu,
                            'max_rss_platform_units':resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
                            'cache_hit':False,'base_evidence_origin':'frozen_discovery_cache','timing_scope':'analysis_only_excludes_discovery_and_mining','started_at':began,'finished_at':now(),
                            'dfg_reason_codes':dfg.get('reason_codes',[]) if dfg else [],
                            'ai_review':'pending','human_review':'pending','runtime_confirmed':False}
                    with db:
                        db.execute('INSERT OR REPLACE INTO results VALUES(?,?,?,?)',(aid,cid,variant,canonical(record)))
                        db.execute('UPDATE attempts SET status=?,data=? WHERE id=?',('completed',canonical(record),attempt))
                    processed+=1
            db.execute('INSERT OR REPLACE INTO batches VALUES(?,?,?)',(batch['batch_id'],'complete',canonical(batch)));db.commit()
            print(canonical({'stage':'analysis','batch':batch['batch_id'],'processed':processed,'cache_hits':hits}),flush=True)
    report={'processed_this_invocation':processed,'cache_hits':hits,'elapsed_seconds':time.perf_counter()-start,
            'batch_ids':[b['batch_id'] for b in selected_batches],'signature':signature}
    write(dest/'invocations'/(str(uuid.uuid4())+'.json'),report)
    return report


def export(out,label='main'):
    from .screening_review import export_review_packages, review_metrics
    from .export import write_csv
    out=Path(out);dest=out/'analyses'/label;cases,cfg,manifest=load_selected(out)
    expected_signature=digest({'code':code_version(),'config':cfg,'selection':manifest['selection_sha256']})
    if read(dest/'signature.json')['signature']!=expected_signature:raise ValueError('export_analysis_signature_mismatch')
    with database(dest/'checkpoint.sqlite') as db:
        results=[json.loads(r[0]) for r in db.execute('SELECT data FROM results ORDER BY case_id,variant')]
        attempts=[dict(r) for r in db.execute('SELECT id,analysis_id,case_id,variant,status FROM attempts ORDER BY rowid')]
        batch_states=[dict(r) for r in db.execute('SELECT id,status FROM batches ORDER BY id')]
    for r in results:
        for rel,h in r.get('artifact_hashes',{}).items():
            if not (dest/rel).is_file() or file_hash(dest/rel)!=h:raise ValueError('export_artifact_hash_mismatch')
    indexed={(r['case_id'],r['variant']):r for r in results};pairs=[]
    for c in cases:
        a=indexed.get((c['case_id'],'baseline'));b=indexed.get((c['case_id'],'dfg_augmented'))
        pairs.append({'case_id':c['case_id'],'language':c['language'],'scope':c['scope'],'stratum':c.get('sampling_stratum',c['legacy_stratum']),
                      'baseline_analysis_id':a['analysis_id'] if a else None,'dfg_analysis_id':b['analysis_id'] if b else None,
                      'baseline_queue':a['queue'] if a else None,'dfg_queue':b['queue'] if b else None,
                      'baseline_status':a['processing_status'] if a else 'pending','dfg_status':b['processing_status'] if b else 'pending',
                      'base_evidence_equal':bool(a and b and a['base_evidence_sha256']==b['base_evidence_sha256']),
                      'baseline_seconds':a['elapsed_seconds'] if a else None,'dfg_seconds':b['elapsed_seconds'] if b else None})
    expected={(c['case_id'],v) for c in cases for v in VARIANTS};observed=set(indexed)
    graphs=[]
    for r in results:
        for path in r['artifact_hashes']:
            if path.startswith('graphs/') and path.endswith('.json'):graphs.append(read(dest/path))
    ev=[]
    for g in graphs:
        carries=[e for e in g['edges'] if e.get('carries_value') and e.get('status')=='structural_ast']
        effective=[e for e in carries if e['kind'] in {'assignment','reaching_definition','actual_to_formal','return_value','call_return','field_read','parameter_use','write','projection'}]
        ev.append({'graph_id':g['id'],'value_edges':len(carries),'effective_propagation_edges':len(effective),'origin_counts':g.get('origin_counts',{}),
                   'gaps':g.get('gaps',[]),'history_locations_valid':all(n.get('sha')==g['sha'] for n in g['nodes'] if n.get('sha'))})
    dimensions={}
    for v in VARIANTS:
        rs=[r for r in results if r['variant']==v];ds=[r['assessment'].get('dimensions',r['assessment']) for r in rs]
        dimensions[v]={'count':len(rs),'queue_counts':dict(Counter(r['queue'] for r in rs)),
            'processing_status_counts':dict(Counter(r['processing_status'] for r in rs)),
            'elapsed_seconds':sum(r['elapsed_seconds'] for r in rs),'cpu_seconds':sum(r['cpu_seconds'] for r in rs),
            'critical_unknown_cases':sum(bool(d.get('critical_unknowns')) for d in ds),
            'critical_unknown_ratio':sum(bool(d.get('critical_unknowns')) for d in ds)/len(ds) if ds else None,
            'source_sensitivity':dict(Counter(str(d.get('source_sensitivity','unknown')) for d in ds)),
            'output_sensitivity':dict(Counter(str(d.get('output_sensitivity','unknown')) for d in ds)),
            'connection':dict(Counter(str(d.get('connection',{}).get('status','not_established')) for d in ds)),
            'processing':dict(Counter(str(d.get('processing',{}).get('kind','unknown')) for d in ds)),
            'boundary':dict(Counter(str(d.get('boundary',{}).get('level','unknown')) for d in ds))}
    coverage={'primary_cases':len(cases),'expected_analyses':len(expected),'actual_analyses':len(results),
        'missing':sorted(expected-observed),'unexpected':sorted(observed-expected),'duplicate_results':len(results)-len(observed),
        'paired_base_evidence_equal':all(p['base_evidence_equal'] for p in pairs),
        'queue_migrations':dict(Counter(str(p['baseline_queue'])+'->'+str(p['dfg_queue']) for p in pairs)),
        'variants':dimensions,'graphs':len(graphs),'graphs_with_structural_value_edges':sum(x['value_edges']>0 for x in ev),
        'graph_evidence':ev,'attempts':len(attempts),'interrupted_attempts':sum(a['status']=='interrupted' for a in attempts),
        'batch_states':batch_states,'languages':dict(Counter(c['language'] for c in cases)),
        'scope_counts':dict(Counter(c['scope'] for c in cases)),
        'human_labels':0,'ai_reviews':0,'runtime_confirmed':False,'precision':None,'recall':None,
        'metrics_reason':'independent_human_labels_pending',
        'acceptance':{'process_integrity':not(expected-observed or observed-expected) and len(results)==len(expected),
                      'real_DFG_applicability':any(x['effective_propagation_edges']>0 and x['history_locations_valid'] for x in ev),
                      'synthetic_semantics':'see_actual_pytest_report'},
        'claims_excluded':['full_DFG_census_completed','runtime_leak_confirmed','agent_unique_risk','accuracy_improvement']}
    write_rows(dest/'results.jsonl',results);write_rows(dest/'ab_pairs.jsonl',pairs);write_csv(dest/'ab_pairs.csv',pairs)
    write_rows(dest/'attempts.jsonl',attempts);write(dest/'coverage.json',coverage)
    evaluation=list(rows(out/'selection/evaluation.jsonl'))
    review=export_review_packages(evaluation,out/'review',cfg['policy_version'])
    write(out/'review/metrics.json',review_metrics(evaluation,[],[]))
    from .screening_compare import compare_cases
    extracted=[read(p) for p in (dest/'mining').glob('*/runner-extraction.json')]
    comparisons=compare_cases(cases,results,extracted)
    write_rows(dest/'before_after.jsonl',comparisons)
    paths=[];evidence_index=[]
    for c in cases:
        for eid in c['base_evidence']['evidence_ids']:
            evidence_index.append({'evidence_id':eid,'case_id':c['case_id'],'kind':'base_output_expression',
                'source_sha':c['source_sha'],'source_sha256':c['source_sha256'],'anchor':c['output_anchor'],
                'local_source_ref':c['source_path']})
    for r in results:
        for n,path in enumerate(r['assessment']['dimensions'].get('paths',[])):
            paths.append({'path_id':stable_id(r['analysis_id'],n,path),'case_id':r['case_id'],
                'analysis_id':r['analysis_id'],'variant':r['variant'],**path})
    for graph in graphs:
        for node in graph['nodes']:
            if node.get('evidence'):
                evidence_index.append({'evidence_id':node['evidence']['id'],'case_id':graph['id'],
                    'kind':node['kind'],'anchor':node.get('anchor'),'sha':node.get('sha'),
                    'evidence':node['evidence']})
    write_rows(dest/'paths.jsonl',paths);write_rows(dest/'evidence_index.jsonl',evidence_index)
    write_rows(dest/'risk_labels.jsonl',[{'case_id':r['case_id'],'analysis_id':r['analysis_id'],
        'queue':r['queue'],'variant':r['variant'],'dimensions':r['assessment']['dimensions']} for r in results])
    write_rows(out/'review/private_source_index.jsonl',[{'case_id':c['case_id'],
        'source_path':c['source_path'],'snapshot_ref':c['snapshot_ref'],'snapshot_sha256':c['snapshot_sha256'],
        'source_sha':c['source_sha'],'output_anchor':c['output_anchor']} for c in evaluation])
    # File-origin omission audit comes from full modified files, including zero detections.
    file_rows=list(rows(out/'discovery/file_coverage.jsonl'))
    selected_files=sorted([f for f in file_rows if f.get('legacy_analysis_status') in {'supported_language','unsupported_language'} or Path(f.get('path') or '').suffix in {'.py','.go','.js','.ts','.java','.cs'}],key=lambda f:digest([cfg['seed'],'omission-audit',f['file_version_id']]))[:30]
    write_rows(out/'review/log_detection_omission_sample.jsonl',[
        {k:f.get(k) for k in ['file_version_id','repository','source_sha','path','scope','language','source_state','source_path','source_sha256']}
        | {'log_anchors':None,'reviewer':None,'timestamp':None,'status':'pending','origin':'human',
           'inspection_complete':False,'review_scope':'original_modified_file','annotator_slot':None} for f in selected_files])
    return coverage


def prepare_full_batch(out,batch_id):
    """Materialize one explicitly addressed full-frame batch; never auto-run it."""
    out=Path(out);_,cfg,m=load_selected(out)
    if file_hash(out/'selection/full_batches.jsonl')!=m['full_batches_sha256']:
        raise ValueError('full_batch_manifest_hash_mismatch')
    if file_hash(active_frame(out))!=m['frame_sha256']:
        raise ValueError('full_frame_hash_mismatch')
    batches={b['batch_id']:b for b in rows(out/'selection/full_batches.jsonl')}
    if batch_id not in batches:raise ValueError('full_batch_id_not_found')
    child=out/'full_batches'/('batch-'+str(batch_id))
    if (child/'selection/manifest.json').exists():raise ValueError('full_batch_already_materialized_use_existing_child')
    ids=set(batches[batch_id]['case_ids'])
    cases=[c for c in rows(active_frame(out)) if c['case_id'] in ids]
    if {c['case_id'] for c in cases}!=ids:raise ValueError('full_batch_case_membership_mismatch')
    cases=sorted([freeze_context(c,child,cfg) for c in cases],key=lambda c:c['case_id'])
    for c in cases:c.update(split='full_census_batch',group_id=stable_id(c['repository']))
    selection=child/'selection'
    write_rows(selection/'engineering.jsonl',cases);write_rows(selection/'evaluation.jsonl',[])
    write_rows(selection/'groups.jsonl',[{k:c[k] for k in ['case_id','repository','group_id','split']} for c in cases])
    one=[{'batch_id':0,'case_ids':[c['case_id'] for c in cases]}]
    write_rows(selection/'batches.jsonl',one);write_rows(selection/'full_batches.jsonl',one)
    write(selection/'config.json',cfg);write_rows(selection/'pair_context.jsonl',[])
    frozen={**m,'selection_sha256':file_hash(selection/'engineering.jsonl'),
            'evaluation_sha256':file_hash(selection/'evaluation.jsonl'),'groups_sha256':file_hash(selection/'groups.jsonl'),
            'batches_sha256':file_hash(selection/'batches.jsonl'),'full_batches_sha256':file_hash(selection/'full_batches.jsonl'),
            'primary_selected':len(cases),'evaluation_selected':0,'parent_run':str(out),'parent_full_batch_id':batch_id,
            'full_depth_executed':False,'explicit_batch_only':True}
    write(selection/'manifest.json',frozen)
    fv_ids={c['file_version_id'] for c in cases}
    write_rows(child/'discovery/file_coverage.jsonl',[f for f in rows(out/'discovery/file_coverage.jsonl') if f['file_version_id'] in fv_ids])
    write(child/'parent_manifest.json',{'path':str(out/'selection/manifest.json'),'sha256':file_hash(out/'selection/manifest.json')})
    return {'status':'materialized_not_analyzed','child_run':str(child),'case_count':len(cases),'batch_id':batch_id,
            'next_command':['screening','run','--output',str(child)],'auto_runs_other_batches':False}


def ledger_coverage(out):
    out=Path(out);logs={};file_counts=Counter();source_counts=Counter();langs=Counter();scopes=Counter();reasons=Counter()
    by_commit=defaultdict(Counter);known={};file_n=0
    for f in rows(out/'discovery/file_coverage.jsonl'):
        file_n+=1;file_counts[f['processing_status']]+=1;source_counts[f.get('source_state','unknown')]+=1
        langs[str(f.get('language','unknown'))]+=1;scopes[f.get('scope','unknown')]+=1;reasons[str(f.get('reason'))]+=1
        by_commit[f['commit_id']][f['processing_status']]+=1;known[f['file_version_id']]=f.get('source_sha256')
    case_n=0;seen=set();mapping=True;hash_mismatches=0
    for c in rows(active_frame(out)):
        case_n+=1;seen.add(c['case_id']);mapping &= c['file_version_id'] in known
        hash_mismatches+=known.get(c['file_version_id'])!=c['source_sha256']
        log=logs.setdefault(c['log_id'],{k:c.get(k) for k in ['log_id','original_log_id','repository','event_sha','parent_sha',
            'source_sha','side','path','log_anchor','log_statement_sha256','file_version_id','source_sha256','function_scope','scope']})
        log.setdefault('output_case_ids',[]).append(c['case_id'])
    write_rows(out/'coverage/log_versions.jsonl.gz',(logs[k] for k in sorted(logs)))
    commits=list(rows(out/'population/commits.jsonl'));commits_out=[]
    for c in commits:
        statuses=by_commit[c['commit_id']];n=sum(statuses.values())
        status='blocked' if not n else 'pending' if statuses['pending']==n else 'partial' if statuses['blocked'] or statuses['pending'] else 'success'
        commits_out.append({**c,'processing_status':status,'file_status_counts':dict(statuses),'file_version_count':n,
            'reason':c.get('reason') if not n else 'file_version_coverage_aggregated'})
    write_rows(out/'coverage/commit_status.jsonl',commits_out)
    inputs=list(rows(out/'population/input_records.jsonl'))
    report={'input_records':len(inputs),'input_records_mapped':sum(bool(r.get('commit_ids')) for r in inputs),
        'commits':len(commits),'commit_states':dict(Counter(c['processing_status'] for c in commits_out)),
        'file_versions':file_n,'file_states':dict(file_counts),'source_states':dict(source_counts),
        'file_languages':dict(langs),'file_scopes':dict(scopes),'reason_counts':dict(reasons),
        'log_versions':len(logs),'output_units':case_n,'duplicates':case_n-len(seen),
        'case_file_mapping_valid':mapping,'case_file_source_hash_mismatches':hash_mismatches,
        'source_input_hashes':{k:file_hash(out/'population'/k) for k in ['input_records.jsonl','commits.jsonl','file_versions.jsonl']},
        'denominators':'input associations, deduplicated commits, file sides, log versions and output units are distinct',
        'full_source_discovery_completed':file_counts['pending']==0,'full_DFG_analyzed':False,
        'population_risk_rate':None,'accuracy':None}
    write(out/'coverage/ledger_coverage.json',report);return report


def metrics(out,predictions_file=None,detection_file=None):
    from .screening_review import review_metrics
    out=Path(out);evaluation=list(rows(out/'selection/evaluation.jsonl'))
    history=out/'review/imported/review_history.json'
    reviews=read(history) if history.exists() else []
    predictions=list(rows(predictions_file)) if predictions_file else []
    if set(c['case_id'] for c in predictions)-set(c['case_id'] for c in evaluation):
        raise ValueError('predictions_outside_independent_evaluation')
    detection=read(detection_file) if detection_file else None
    report=review_metrics(evaluation,predictions,reviews,detection)
    write(out/'review/metrics.json',report);return report


def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('stage',choices=['precheck','recover','discover','freeze','run','export','review-import','metrics','prepare-full-batch','ledger-coverage','repair-sources'])
    p.add_argument('--output',required=True);p.add_argument('--old-root',default=str(PROJECT/'research/swechat-full-risk-20260912'))
    p.add_argument('--config',default=str(DEFAULT_CONFIG));p.add_argument('--max-files',type=int)
    p.add_argument('--batch',type=int,action='append');p.add_argument('--resume',action='store_true');p.add_argument('--label',default='main')
    p.add_argument('--retry-failed',action='store_true')
    p.add_argument('--interrupt-after',type=int,help='synthetic recovery validation only')
    p.add_argument('--detection-annotations');
    p.add_argument('--file');p.add_argument('--kind',choices=['human','ai','adjudication'],default='human')
    a=p.parse_args(argv);out=Path(a.output).resolve();out.mkdir(parents=True,exist_ok=True,mode=0o700)
    c=config(a.config)
    if a.stage=='discover' and (out/'discovery/checkpoint.sqlite.gz').exists() and not (out/'discovery/checkpoint.sqlite').exists():
        raise ValueError('discovery_checkpoint_archived_restore_verified_archive_before_resume')
    if a.stage=='precheck':result=precheck(out,a.old_root,c)
    elif a.stage=='recover':
        from .screening_history import recover_population
        result=recover_population(PROJECT,Path(a.old_root),out/'population')
    elif a.stage=='discover':result=discover(out,c,a.max_files)
    elif a.stage=='freeze':result=freeze(out,c)
    elif a.stage=='run':result=execute_batches(out,a.label,a.batch,a.resume,a.interrupt_after,a.retry_failed)
    elif a.stage=='export':result=export(out,a.label)
    elif a.stage=='prepare-full-batch':
        if not a.batch or len(a.batch)!=1:raise ValueError('exactly_one_explicit_full_batch_required')
        result=prepare_full_batch(out,a.batch[0])
    elif a.stage=='ledger-coverage':result=ledger_coverage(out)
    elif a.stage=='repair-sources':
        from .screening_repair import repair_source_hashes
        result=repair_source_hashes(out)
    elif a.stage=='review-import':
        from .screening_review import import_review
        if not a.file:raise ValueError('review_file_required')
        result=import_review(a.file,list(rows(out/'selection/evaluation.jsonl')),out/'review/imported',a.kind)
    else:result=metrics(out,a.file,a.detection_annotations)
    print(canonical(result));return 0


if __name__=='__main__':raise SystemExit(main())

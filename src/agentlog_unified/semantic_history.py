"""Explicit public, unfiltered bare clones plus a bounded completeness audit.

The collector only acquires Git objects. PyDriller still owns commit and diff
extraction. 'Complete' here means objects reachable from advertised local refs,
not every deleted branch or the entire original hosting history.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import subprocess

from .config import now, sha256_file
from .export import write_json,write_jsonl
from .git_support import is_ancestor,repository_object_state,resolve_ref,run_git


def collect(input_path,output,cache,*,offline=True,dry_run=False,resume=False,max_repositories=3,timeout=120):
    rows=[json.loads(line) for line in Path(input_path).read_text().splitlines() if line.strip()]
    if not isinstance(max_repositories,int) or max_repositories<1:raise ValueError('positive repository budget required')
    for row in rows:
        if not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+',row.get('repository','')):raise ValueError('public GitHub owner/repository required')
        if any(not re.fullmatch('[0-9a-f]{40}',sha) for sha in row.get('initial_commit_shas',[])):raise ValueError('initial commits must be full SHA')
    if dry_run:return {'status':'dry_run','files_written':False,'network_requests':0,'repositories':min(len(rows),max_repositories),'exit_code':0}
    output=Path(output);cache=Path(cache);receipt=output/'history_collection.json'
    fingerprint=sha256_file(Path(input_path))
    prior=json.loads(receipt.read_text()) if receipt.exists() else None
    if prior and (not resume or prior['input_sha256']!=fingerprint):raise ValueError('use a new history output or resume the same input')
    results={r['repository']:r for r in prior['repositories']} if prior else {}
    frozen={r['repository']:r for r in (json.loads(line) for line in (output/'input.jsonl').read_text().splitlines())} if (output/'input.jsonl').exists() else {}
    attempted=0
    for row in rows:
        rid=row['repository']
        if rid in results:continue
        if attempted>=max_repositories:break
        attempted+=1;destination=cache/rid.replace('/','--')
        result={'repository':rid,'started_at':now(),'network_mode':'offline' if offline else 'explicit_public_clone',
                'extraction_method':'native_git_object_acquisition_only','fallback_reason':None,'target_code_executed':False}
        try:
            if not destination.exists():
                if offline:raise ValueError('full_clone_missing_offline')
                cache.mkdir(parents=True,exist_ok=True)
                subprocess.run(['git','-c','core.hooksPath=/dev/null','-c','protocol.file.allow=never','clone','--bare',
                                '--no-hardlinks','https://github.com/'+rid+'.git',str(destination)],
                               check=True,capture_output=True,timeout=timeout,
                               env={**os.environ,'GIT_TERMINAL_PROMPT':'0','GIT_LFS_SKIP_SMUDGE':'1'})
            state=repository_object_state(str(destination));tip=resolve_ref(str(destination),'HEAD')
            if not tip:raise ValueError('clone_tip_missing')
            missing_initial=[sha for sha in row.get('initial_commit_shas',[]) if not resolve_ref(str(destination),sha)]
            for sha in missing_initial:
                if offline:continue
                subprocess.run(['git','-c','core.hooksPath=/dev/null','-C',str(destination),'fetch','--no-tags','origin',sha],
                               check=True,capture_output=True,timeout=timeout,env={**os.environ,'GIT_TERMINAL_PROMPT':'0'})
            refs=['--all',*row.get('initial_commit_shas',[])]
            objects=run_git(str(destination),['rev-list','--objects','--missing=print',*refs],timeout=timeout).stdout.splitlines()
            missing=[line[1:].split()[0] for line in objects if line.startswith('?')]
            count=int(run_git(str(destination),['rev-list','--count','--all']).stdout)
            reachable={sha:is_ancestor(str(destination),sha,tip) for sha in row.get('initial_commit_shas',[])}
            result.update(status='objects_complete_for_frozen_refs' if not missing and not state['shallow'] else 'partial',
                          frozen_tip=tip,object_state=state,reachable_commit_count=count,reachable_object_count=len(objects),
                          missing_object_count=len(missing),missing_object_ids=missing,initial_is_ancestor=reachable,
                          scope='local advertised refs plus supplied initial commits; deleted/unadvertised refs not proven complete')
            frozen[rid]={**row,'local_repo_path':str(destination.resolve()),'target_ref':tip,
                         'history_collection_receipt':'history_collection.json','frozen_at':now()}
        except (ValueError,subprocess.SubprocessError,OSError) as exc:
            result.update(status='blocked',reason=str(exc) if isinstance(exc,ValueError) else type(exc).__name__)
        results[rid]=result
        report={'status':'complete_with_declared_gaps','exit_code':0,'input_sha256':fingerprint,
                'input_repository_denominator':len(rows),'attempted_repositories':len(results),'repositories':list(results.values()),
                'remaining_repositories':len(rows)-len(results),'remote_writes':0,'target_code_executions':0}
        write_jsonl(output/'input.jsonl',list(frozen.values()));write_json(receipt,report)
    return json.loads(receipt.read_text()) if receipt.exists() else {'status':'no_input','exit_code':0}


def audit_mining(output,max_commits=1000):
    """Traverse the full frozen target history with PyDriller, independently of
    the smaller semantic sample. Export references/hashes, never source values.
    """
    from .miner import mine_repository
    from .semantic_evidence import digest
    if not isinstance(max_commits,int) or max_commits<1:raise ValueError('positive full-history commit budget required')
    output=Path(output);rows=[json.loads(line) for line in (output/'input.jsonl').read_text().splitlines()]
    reports=[]
    for row in rows:
        rid=row['repository'];directory=output/'full_git_audit'/rid.replace('/','--')
        fingerprint={'repository':rid,'frozen_tip':row['target_ref'],'initial_shas':row['initial_commit_shas'],
                     'max_commits':max_commits,'miner_sha256':sha256_file(Path(__file__).with_name('miner.py'))}
        receipt=directory/'audit.json'
        if receipt.exists():
            existing=json.loads(receipt.read_text())
            if existing['fingerprint']!=fingerprint:raise ValueError('full Git audit config/source changed; choose a new history collection')
            reports.append(existing);continue
        mined=mine_repository(row['local_repo_path'],row['target_ref'],row['initial_commit_shas'],max_commits=max_commits,since_initial=False)
        commits=[{k:c.get(k) for k in ('sha','parents','author_date','committer_date','merge','topo_index','target_reachable','on_target_first_parent','extraction_mode')} for c in mined['commits']]
        differences=[]
        for change in mined['changes']:
            record={k:change.get(k) for k in ('sha','parent_sha','old_path','new_path','change_type','diff_backend','fallback_reason','source_backends','source_status','source_fallback_reasons','extraction_status')}
            record['source_sha256']={side:digest(change[side+'_source']) if isinstance(change.get(side+'_source'),str) else None for side in ('before','after')}
            record['changed_lines']={side:[v[0] for v in change[side]] for side in ('added','deleted')}
            differences.append(record)
        write_jsonl(directory/'commits.jsonl',commits);write_jsonl(directory/'file_differences.jsonl',differences)
        # Failure records may contain source details; retain just typed diagnostics.
        gaps=[{k:g.get(k) for k in ('kind','reason','sha','parent_sha','path','error_type','eligible_count','selected_count','omitted_count')} for g in mined['gaps']]
        write_jsonl(directory/'data_gaps.jsonl',gaps)
        report={'fingerprint':fingerprint,'metrics':mined['metrics'],'history_scope':mined['history_scope'],
                'gap_records':len(gaps),'selected_commits':len(commits),
                'all_requested_commits_extracted':len(commits)==mined['metrics']['eligible_commits'],
                'scope':'all frozen target reachable commits plus supplied initial commits; not every remote branch',
                'semantic_analysis_of_all_commits':False,'target_code_executed':False}
        write_json(receipt,report);reports.append(report)
    report={'status':'complete_with_declared_gaps','exit_code':0,'repositories':reports,
            'pydriller_commits':sum(r['metrics']['pydriller_commits'] for r in reports),
            'pydriller_diff_parsed_calls':sum(r['metrics']['pydriller_diff_parsed_calls'] for r in reports),
            'pydriller_source_reads':sum(r['metrics']['pydriller_source_reads'] for r in reports),
            'all_requested_commits_extracted':all(r['all_requested_commits_extracted'] for r in reports)}
    write_json(output/'full_git_mining_audit.json',report);return report

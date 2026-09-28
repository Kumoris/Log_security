"""Read-only source repositories; network mutations only in dedicated caches."""
from __future__ import annotations
from collections import defaultdict
import os
from pathlib import Path
import re
import subprocess
from .git_support import resolve_ref, run_git
from .storage import stable_id


def collect_repositories(prs: list[dict], config: dict, offline: bool) -> tuple[list[dict],list[dict]]:
    grouped = defaultdict(list)
    for pr in prs:
        repo_id = pr.get('repository') or pr.get('fixture_repository_id') or pr.get('local_repo_path')
        grouped[(repo_id,pr.get('target_ref') or pr.get('base_ref') or 'HEAD')].append(pr)
    rows, gaps = [], []
    cache = Path(config['mining']['repository_cache'])
    for (repository, target_ref), members in grouped.items():
        local = members[0].get('local_repo_path')
        path = Path(local).resolve() if local else cache / stable_id(repository)
        def gap(reason: str, error_type: str = 'RepositoryUnavailable', retryable: bool = False) -> None:
            gaps.append({'stage':'collect','repository':repository,'pr':None,'sha':None,'error_type':error_type,'retryable':retryable,'reason':reason})
        if not path.exists():
            if offline:
                gap('offline_repository_cache_miss')
                continue
            if not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+',str(repository)):
                gap('no_valid_public_repository_for_clone')
                continue
            cache.mkdir(parents=True,exist_ok=True,mode=0o700)
            result = subprocess.run(['git','-c','core.hooksPath=/dev/null','-c','protocol.file.allow=never','clone','--no-checkout',f'https://github.com/{repository}.git',str(path)],capture_output=True,text=True,timeout=300,env={**os.environ,'GIT_TERMINAL_PROMPT':'0','GIT_CONFIG_NOSYSTEM':'1'})
            if result.returncode:
                gap('public_clone_failed', 'CloneFailure', True)
                continue
        tip = resolve_ref(str(path),target_ref) or resolve_ref(str(path),'refs/remotes/origin/'+target_ref)
        if not tip:
            gap('target_ref_unavailable')
            continue
        initial = sorted({s for p in members for s in (p.get('commit_shas') or p.get('initial_commit_shas') or ([p['head_sha']] if p.get('head_sha') else []))})
        anchors = sorted({p['merge_commit_sha'] for p in members if p.get('merge_commit_sha') and p.get('merged_at')})
        missing = []
        for sha in initial + anchors:
            if not resolve_ref(str(path),sha):
                # Only own clones may receive PR refs; user-supplied repositories stay read-only.
                if not offline and not local:
                    for p in members:
                        if p.get('pr_number'):
                            subprocess.run(['git','-C',str(path),'-c','core.hooksPath=/dev/null','fetch','origin',f'refs/pull/{p["pr_number"]}/head:refs/research/pr-{p["pr_number"]}'],capture_output=True,timeout=120)
                if not resolve_ref(str(path),sha):
                    missing.append(sha)
                    gaps.append({'stage':'collect','repository':repository,'sha':sha,'pr':None,'error_type':'MissingCommit','retryable':not offline,'reason':'requested_object_unavailable'})
        shallow = run_git(str(path),['rev-parse','--is-shallow-repository']).stdout.strip() == 'true'
        size = sum(p.stat().st_size for p in (path/'.git'/'objects').rglob('*') if p.is_file()) if (path/'.git').is_dir() else 0
        if size > config['mining']['max_download_gb']*1024**3:
            gap('repository_exceeds_disk_budget','BudgetExceeded')
            continue
        if shallow:
            gap('shallow_repository_history_incomplete','ShallowHistory')
        rows.append({'id':stable_id(repository,target_ref),'repository_id':repository,'repository':members[0].get('repository'),'local_repo_path':str(path),'target_ref':target_ref,'frozen_target_tip':tip,'initial_shas':initial,'integration_anchors':anchors,'missing_shas':missing,'shallow':shallow,'local_snapshot_only':bool(local),'object_bytes':size,'pr_ids':[p['id'] for p in members],'is_synthetic':all(p.get('is_synthetic',False) for p in members)})
    return rows,gaps

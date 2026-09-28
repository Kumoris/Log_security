"""Source-linked PR/commit verification and bounded PyDriller code evidence.

The code pair is not a full-history audit or a verdict that a fix is effective.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import subprocess
import time
import urllib.request
from urllib.error import HTTPError
from urllib.parse import parse_qs, quote, urlsplit

from .config import now, sha256_file
from .export import write_csv, write_json, write_jsonl
from .git_support import resolve_ref
from .miner import mine_repository
from .storage import atomic_write

REPO = r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+'
SHA = r'[0-9a-f]{40}'


def read_public_json(url):
    parsed=urlsplit(url);query=parse_qs(parsed.query)
    direct=bool(re.fullmatch(r'/repos/'+REPO+r'/(pulls/\d+|commits/'+SHA+r')',parsed.path)) and not parsed.query
    search=parsed.path=='/search/commits' and set(query)=={'q','per_page'} and query['per_page']==['20'] and bool(re.fullmatch(r'repo:'+REPO+r' "[A-Z]+-\d+"',query['q'][0]))
    compare=bool(re.fullmatch(r'/repos/'+REPO+r'/compare/'+SHA+r'\.\.\.[A-Za-z0-9_.%/-]+',parsed.path)) and query=={'per_page':['1']}
    if parsed.scheme!='https' or parsed.netloc!='api.github.com' or parsed.fragment or not (direct or search or compare):
        raise ValueError('public_reference_endpoint_not_allowed')
    request=urllib.request.Request(url,headers={'User-Agent':'agentlog-reference/0.9','Accept':'application/vnd.github+json'})
    with urllib.request.urlopen(request,timeout=30) as response:
        data=response.read(8*1024*1024+1)
        if len(data)>8*1024*1024:raise ValueError('reference_response_budget')
        return json.loads(data),{'url':url,'fetched_at':now(),'status':response.status,'bytes':len(data)}


def resolve_closed_pr(row, pr, output):
    """Apache mirrors can close a PR after applying it outside GitHub's merge API.

    Require exact issue/PR references plus target-branch ancestry; never use a
    closed PR's synthetic merge_commit_sha as the final integration commit.
    """
    repository=pr['base']['repo']['full_name'];branch=pr['base']['ref'];key=row['issue']
    query=quote('repo:'+repository+' "'+key+'"',safe='')
    payload,receipt=read_public_json('https://api.github.com/search/commits?q='+query+'&per_page=20')
    atomic_write(output/'private'/f'{key}.commit-search.json',json.dumps(payload,ensure_ascii=False))
    receipts=[receipt]
    if payload.get('incomplete_results') or payload.get('total_count',0)>20:raise ValueError('integration_commit_search_incomplete')
    candidates=[]
    for item in payload.get('items',[]):
        message=item['commit']['message'];sha=item['sha']
        if key not in message or not re.search(r'(?:closes?|pull request|pull)\s*#?'+str(row['pr_number'])+r'\b',message,re.I):continue
        comparison,receipt=read_public_json('https://api.github.com/repos/'+repository+'/compare/'+sha+'...'+quote(branch,safe='')+'?per_page=1')
        receipts.append(receipt)
        atomic_write(output/'private'/f'{key}.ancestry-{sha}.json',json.dumps(comparison,ensure_ascii=False))
        if comparison.get('status') in {'ahead','identical'}:
            candidates.append({'sha':sha,'target_branch':branch,'target_sha':comparison['commits'][-1]['sha'] if comparison.get('status')=='identical' and comparison.get('commits') else None,
                               'ancestry_status':comparison['status'],'comparison_url':receipt['url']})
    if len(candidates)!=1:raise ValueError('integration_commit_missing_or_ambiguous:'+str(len(candidates)))
    return candidates[0],receipts


def validate_selection(row, source):
    if not re.fullmatch(r'[A-Z]+-\d+|Azure-azure-cli-\d+',row.get('issue','')):
        raise ValueError('invalid_issue_identity')
    if source.get('issue')!=row['issue'] or not source.get('complete'):
        raise ValueError('issue_source_not_complete_or_identity_mismatch')
    if not re.fullmatch(REPO,row.get('repository','')) or '..' in row['repository'].split('/'):
        raise ValueError('invalid_public_repository')
    if bool(row.get('pr_number'))==bool(row.get('commit_sha')):
        raise ValueError('select_exactly_one_pr_or_commit')
    if row.get('pr_number') and (type(row['pr_number']) is not int or row['pr_number']<1):
        raise ValueError('invalid_pr_number')
    if row.get('commit_sha') and not re.fullmatch(SHA,row['commit_sha']):
        raise ValueError('invalid_commit_sha')
    payload=source['issue_payload'];fields=payload.get('fields',payload)
    texts=[('D',fields.get('description',fields.get('body','')) or '')]
    texts += [('C'+str(c['id']),c['body']) for c in source['comments']]
    target=('https://github.com/'+row['repository']+'/pull/'+str(row['pr_number']) if row.get('pr_number') else row['commit_sha'])
    refs=[ref for ref,text in texts if re.search(re.escape(target)+r'(?![A-Za-z0-9])',text)]
    if not refs:raise ValueError('selected_change_not_linked_in_frozen_issue')
    return refs


def load_resolution(row, input_path):
    relative=Path(row['resolution_file'])
    if relative.is_absolute() or '..' in relative.parts:raise ValueError('resolution_path_outside_selection')
    path=Path(input_path).parent/relative
    data=json.loads(path.read_text());comparison=data['comparison'];commit=data['selected_commit']
    if data['issue']!=row['issue'] or data['repository']!=row['repository'] or not re.fullmatch(SHA,data['commit_sha']):
        raise ValueError('resolution_identity_mismatch')
    sha=data['commit_sha']
    if commit['sha']!=sha or not re.search(r'(?<![A-Z0-9-])'+re.escape(row['issue'])+r'(?![A-Z0-9-])',commit['title']):
        raise ValueError('resolution_issue_commit_association_missing')
    if comparison['base']!=sha or comparison['repository_full_name']!=row['repository'] or comparison['status'] not in {'ahead','identical'} or comparison['behind_by']!=0:
        raise ValueError('resolution_target_ancestry_not_supported')
    return data,sha256_file(path)


def acquire_pair(repository, sha, destination, *, offline, timeout=180):
    if destination.exists() and resolve_ref(str(destination),sha):return []
    if offline:raise ValueError('historical_commit_missing_offline')
    env={**os.environ,'GIT_TERMINAL_PROMPT':'0','GIT_LFS_SKIP_SMUDGE':'1'}
    receipts=[]
    if not destination.exists():
        destination.parent.mkdir(parents=True,exist_ok=True)
        subprocess.run(['git','init','--bare',str(destination)],check=True,capture_output=True,env=env,timeout=30)
    # ponytail: bounded pair fetch, full branch history remains a separate stage.
    command=['git','-c','core.hooksPath=/dev/null','-c','protocol.file.allow=never','-C',str(destination),
             'fetch','--depth=2','--no-tags','https://github.com/'+repository+'.git',sha]
    subprocess.run(command,check=True,capture_output=True,env=env,timeout=timeout)
    receipts.append({'method':'native_git_fetch_object_acquisition','sha':sha,'depth':2,'fetched_at':now(),
                     'scope':'selected_commit_and_parents_not_full_history'})
    return receipts


def run_references(input_path, source_root, output, cache, *, offline=True, dry_run=False, resume=False,
                   max_cases=12, max_seconds=None):
    if type(max_cases) is not int or max_cases<1:raise ValueError('positive_reference_budget_required')
    input_path=Path(input_path);source_root=Path(source_root);output=Path(output);cache=Path(cache)
    rows=[json.loads(line) for line in input_path.read_text().splitlines() if line.strip()]
    if len({r['issue'] for r in rows})!=len(rows):raise ValueError('duplicate_issue_selection')
    linked={};source_hashes={};resolutions={}
    for row in rows:
        if not re.fullmatch(r'[A-Z]+-\d+|Azure-azure-cli-\d+',row.get('issue','')):raise ValueError('invalid_issue_identity')
        path=source_root/'private'/(row['issue']+'.json')
        linked[row['issue']]=validate_selection(row,json.loads(path.read_text()))
        source_hashes[row['issue']]=sha256_file(path)
        if row.get('resolution_file'):
            data,digest=load_resolution(row,input_path);resolutions[row['issue']]=data
            source_hashes[row['issue']+':integration_resolution']=digest
    if dry_run:return {'status':'dry_run','exit_code':0,'files_written':False,'cases':len(rows),'network_requests':0,'would_use_network':not offline}
    fingerprint={'input_sha256':sha256_file(input_path),'sources':source_hashes,
                 'implementation':{name:sha256_file(Path(__file__).with_name(name)) for name in ('issue_reference.py','miner.py','git_support.py')}}
    manifest_path=output/'manifest.json';prior=None
    if output.exists() and any(output.iterdir()):
        if not resume or not manifest_path.exists():raise ValueError('existing_output_requires_valid_resume')
        prior=json.loads(manifest_path.read_text())
        if prior['fingerprint']!=fingerprint:raise ValueError('reference_input_or_code_changed_use_new_output')
        if any(sha256_file(output/p)!=h for p,h in prior['artifact_sha256'].items()):raise ValueError('reference_artifact_integrity_mismatch')
    results={r['id']:r for r in (json.loads(line) for line in (output/'code_references.jsonl').read_text().splitlines())} if prior else {}
    attempted=0;start=time.monotonic()
    for row in rows:
        key=row['issue']
        if key in results:continue
        if attempted>=max_cases or (max_seconds is not None and time.monotonic()-start>=max_seconds):break
        attempted+=1
        result={'id':key,'repository':row['repository'],'source_evidence_refs':linked[key],
                'status':'pending','runtime_confirmed':False,'human_confirmed':False,'fix_effectiveness':'not_assessed',
                'full_history_verified':False,'receipts':[],'error':None}
        try:
            repository=row['repository'];sha=row.get('commit_sha')
            if key in resolutions:
                resolution=resolutions[key];sha=resolution['commit_sha']
                result['integration']={'method':'external_read_only_connector_commit_search_and_ancestry',**resolution}
                atomic_write(output/'private'/f'{key}.integration.json',json.dumps(resolution,ensure_ascii=False))
            elif row.get('pr_number'):
                if offline:raise ValueError('pr_integration_metadata_unavailable_offline')
                pr,receipt=read_public_json('https://api.github.com/repos/'+repository+'/pulls/'+str(row['pr_number']))
                result['receipts'].append(receipt)
                atomic_write(output/'private'/f'{key}.pr.json',json.dumps(pr,ensure_ascii=False))
                repository=pr['base']['repo']['full_name']
                if pr.get('merged') and pr.get('merge_commit_sha'):
                    sha=pr['merge_commit_sha']
                    result['integration']={'method':'github_merged_pr_metadata','pr_url':pr['html_url'],
                                           'merged_at':pr['merged_at'],'head_sha':pr['head']['sha'],'merge_sha':sha}
                else:
                    integration,receipts=resolve_closed_pr(row,pr,output)
                    result['receipts']+=receipts;sha=integration['sha']
                    result['integration']={**integration,'method':'commit_message_exact_issue_and_pr_reference_plus_target_ancestry',
                                           'pr_url':pr['html_url'],'github_merged_flag':False,'head_sha':pr['head']['sha']}
            if not re.fullmatch(REPO,repository) or not re.fullmatch(SHA,sha):raise ValueError('invalid_resolved_identity')
            result.update(repository=repository,commit_sha=sha)
            if not offline and key not in resolutions:
                commit,receipt=read_public_json('https://api.github.com/repos/'+repository+'/commits/'+sha)
                result['receipts'].append(receipt)
                atomic_write(output/'private'/f'{key}.commit.json',json.dumps(commit,ensure_ascii=False))
                if commit['sha']!=sha:raise ValueError('commit_identity_mismatch')
                result['api_parent_shas']=[p['sha'] for p in commit['parents']]
            destination=cache/repository.replace('/','--')
            result['receipts']+=acquire_pair(repository,sha,destination,offline=offline)
            mined=mine_repository(str(destination),sha,[sha],max_commits=1)
            atomic_write(output/'private'/f'{key}.mined.json',json.dumps(mined,ensure_ascii=False))
            matches=[c for c in mined['commits'] if c['sha']==sha]
            if len(matches)!=1:raise ValueError('pydriller_commit_unavailable')
            if key in resolutions and key not in matches[0].get('message',''):
                raise ValueError('historical_commit_does_not_reference_issue')
            if result.get('api_parent_shas') is not None and matches[0]['parents']!=result['api_parent_shas']:
                raise ValueError('commit_parent_graph_mismatch')
            files=[]
            for change in mined['changes']:
                files.append({k:change.get(k) for k in ('change_id','sha','parent_sha','old_path','new_path','change_type',
                    'diff_backend','fallback_reason','source_backends','source_status','source_fallback_reasons','extraction_status')}
                    | {'line_numbers':{side:[v[0] for v in change[side]] for side in ('added','deleted')}})
            result.update(status='code_pair_extracted' if all(c['extraction_status']=='ok' for c in mined['changes']) else 'partial_code_pair',
                          commit_parents=matches[0]['parents'],local_repo_path=str(destination.resolve()),
                          metrics=mined['metrics'],files=files,gaps=mined['gaps'],
                          review_status='pending_source_code_adjudication')
        except HTTPError as exc:
            result.update(status='blocked',error='http_'+str(exc.code))
            result['receipts'].append({'method':'public_github_api','status':exc.code,'fetched_at':now(),
                'rate_limit_remaining':exc.headers.get('X-RateLimit-Remaining'),
                'rate_limit_reset':exc.headers.get('X-RateLimit-Reset'),'retry_after':exc.headers.get('Retry-After')})
        except (OSError,ValueError,KeyError,subprocess.SubprocessError) as exc:
            result.update(status='blocked',error=str(exc) if isinstance(exc,ValueError) else type(exc).__name__)
        results[key]=result
        write_jsonl(output/'code_references.jsonl',list(results.values()));write_csv(output/'code_references.csv',list(results.values()))
        write_json(output/'evidence'/f'{key}.json',result)
        pending=[r['issue'] for r in rows if r['issue'] not in results]
        write_json(output/'manifest.json',{'fingerprint':fingerprint,'status':'partial' if pending else 'complete_with_declared_gaps',
             'remaining':pending,'target_code_executed':False,'external_model_calls':0,
             'artifact_sha256':{str(p.relative_to(output)):sha256_file(p) for p in output.rglob('*') if p.is_file() and p.name!='manifest.json'}})
    counts={status:sum(r['status']==status for r in results.values()) for status in sorted({r['status'] for r in results.values()})}
    return {'status':'partial' if len(results)<len(rows) else 'complete_with_declared_gaps','exit_code':2 if len(results)<len(rows) else 0,
            'denominator':len(rows),'attempted':len(results),'new_attempts':attempted,'counts':counts,
            'pydriller_commits':sum(r.get('metrics',{}).get('pydriller_commits',0) for r in results.values()),
            'target_code_executed':False,'external_model_calls':0}

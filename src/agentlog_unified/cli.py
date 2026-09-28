from __future__ import annotations
import argparse
from collections import defaultdict
import json
from pathlib import Path
import sys
import traceback
import yaml
from .config import PROJECT,STAGES,load_config,init_run,now,versions,sampling_limits
from .storage import Store,stable_id,atomic_write,redact,canonical
from .ingest import ingest_records
from .github_client import GitHubClient,enrich_pr
from .repo_manager import collect_repositories
from .miner import mine_repository
from .analysis import detect_history
from .lineage import trace_logs,assess
from .export import export_run,write_json,write_jsonl


def all_gaps(store: Store) -> list[dict]:
    return [g for stage in STAGES+['reverse'] for g in store.rows(stage+'_gaps')]


def apply_match_file(store, path, default_reviewer=None):
    """Validate the entire user-supplied match list against exported candidates."""
    if store.status('detect') is None:
        raise ValueError('resolve-match requires existing detection results')
    existing=store.rows('match_overrides')
    events={e['id']:e for e in store.rows('log_events')}
    events.update({o['machine_event']['id']:o['machine_event'] for o in existing if o.get('machine_event')})
    mapping={(o['repository_id'],o['before_sha'],o['after_sha'],o['before_key']):o for o in existing}
    applied=0
    for line in Path(path).read_text(encoding='utf-8').splitlines():
        if not line.strip():continue
        row=json.loads(line)
        allowed={'event_id','repository_id','before_sha','after_sha','before_key','after_key','reviewer','notes'}
        if not isinstance(row,dict) or set(row)-allowed:
            raise ValueError('Match records must contain only documented match fields')
        event=events.get(row.get('event_id'))
        if not event or not event.get('match_candidates'):
            raise ValueError('event_id must identify an exported ambiguous match event')
        reviewer=row.get('reviewer') or default_reviewer
        if not isinstance(reviewer,str) or not reviewer.strip():
            raise ValueError('A nonempty reviewer is required')
        for key,value in [('repository_id',event['repository_id']),('before_sha',event['parent_sha']),('after_sha',event['sha'])]:
            if row.get(key,value)!=value:raise ValueError('Match snapshot does not belong to the selected event')
            row[key]=value
        pair=(row.get('before_key'),row.get('after_key'))
        if 'after_key' not in row or pair not in {(p['before_key'],p['after_key']) for p in event['match_candidates']}:
            raise ValueError('Selected entity pair is not an exported candidate')
        key=(row['repository_id'],row['before_sha'],row['after_sha'],row['before_key'])
        record={**row,'id':stable_id('manual_match',*key),'reviewer':reviewer.strip(),
                'machine_event':event,'scope':'entity_identity_only','recorded_at':now()}
        old=mapping.get(key)
        if old and old['after_key']==row['after_key'] and old['reviewer']==reviewer.strip() and old.get('notes')==row.get('notes'):
            continue
        record['history']=(old.get('history',[])+[{k:v for k,v in old.items() if k!='history'}]) if old else []
        mapping[key]=record;applied+=1
    records=list(mapping.values())
    destinations=[(o['repository_id'],o['after_sha'],o['after_key']) for o in records if o['after_key'] is not None]
    if len(destinations)!=len(set(destinations)):
        raise ValueError('A destination log cannot be assigned to multiple identities')
    return {'overrides':records,'applied':applied}


def execute(stage: str,store: Store,config: dict,manifest: dict,run: Path,offline: bool,fmt: str | None,previous_data=None) -> dict:
    gaps=[];details={}
    if stage=='ingest':
        source=config['input']['prs_path']
        if not source:raise ValueError('input.prs_path is required')
        limit,maximum=sampling_limits(config)
        imported=ingest_records(source,config['input'].get('column_mapping'),fmt or config['input'].get('format'),limit)
        prs=[];repos=set();excluded=[]
        for pr in imported['prs']:
            repository=pr.get('repository') or pr.get('fixture_repository_id') or pr.get('local_repo_path')
            if maximum is not None and repository not in repos and len(repos)>=maximum:
                excluded.append({'id':stable_id(repository,pr.get('pr_number')),'reason':'repository_sampling_budget','repository':repository});continue
            repos.add(repository)
            pr['id']=stable_id(repository,pr.get('pr_number'),pr.get('initial_commit_shas') if not pr.get('pr_number') else None)
            prs.append(pr)
        if config['input'].get('repositories_path'):
            extra=ingest_records(config['input']['repositories_path'])
            for pr in prs:
                matches=[r for r in extra['prs'] if r.get('repository')==pr.get('repository')]
                if len(matches)==1:
                    for k in ('local_repo_path','target_ref'):
                        pr[k]=pr.get(k) or matches[0].get(k)
            gaps.extend(extra['gaps'])
        store.replace('prs',prs);store.replace('sampling_exclusions',excluded)
        store.replace('source_schema',[imported['source_schema']]);gaps+=imported['gaps']
        write_json(run/'sampling_manifest.json',{'selection':'input_order_before_log_detection','seed':config['random_seed'],'repository_limit':maximum,'pr_limit':limit,'selected_ids':[p['id'] for p in prs],'excluded':excluded,'source':imported['source_schema']})
        atomic_write(run/'source_schema.md','# 实际输入 schema\n\n```json\n'+json.dumps(imported['source_schema'],ensure_ascii=False,indent=2)+'\n```\n')
        details={'records':len(prs)}
    elif stage=='collect':
        client=GitHubClient(PROJECT/'data/cache/github',offline=offline,timeout=config['network']['timeout_seconds'],max_retries=config['network']['max_retries'])
        prs=[]
        for pr in store.rows('prs'):
            if pr.get('repository') and pr.get('pr_number'):
                pr=enrich_pr(pr,client,collect_reviews=config['network'].get('collect_reviews',False))
            prs.append(pr)
        repos,rgaps=collect_repositories(prs,config,offline)
        gaps=rgaps+client.failures
        store.replace('prs',prs);store.replace('repositories',repos)
        manifest['metadata_collection']={'actual_requests_this_process':client.requests,'cache_dir':str(PROJECT/'data/cache/github'),'offline':offline,'failure_count':len(client.failures)}
        manifest['history_coverage']=repos
        details={'repositories':len(repos),'gaps':len(gaps)}
    elif stage=='mine':
        mined=[];commits=[];changes=[]
        previous={}
        if previous_data:
            from .extension import validate_extension
            previous=validate_extension(store.rows('repositories'),previous_data)
        for repo in store.rows('repositories'):
            options={'previous':previous[repo['id']]} if repo['id'] in previous else {}
            result=mine_repository(repo['local_repo_path'],repo['frozen_target_tip'],repo['initial_shas']+repo['integration_anchors'],max_commits=config['mining']['max_history_commits_per_repository'],max_source_bytes=config['mining']['max_source_file_bytes'],**options)
            result['repository_id']=repo['id']
            for change in result['changes']:
                change['change_id']=stable_id(repo['repository_id'],change['parent_sha'],change['sha'],change['old_path'],change['new_path'])
                change.update(id=change['change_id'],repository_id=repo['id'])
                changes.append(change)
            for commit in result['commits']:
                for pr in store.rows('prs'):
                    if pr['id'] in repo['pr_ids']:
                        for metadata in pr.get('github_commit_metadata') or []:
                            if metadata.get('sha')==commit['sha']:
                                commit['github_author']=metadata.get('author') or {}
                                commit['evidence_ref']=metadata.get('html_url')
                commit.update(id=stable_id(repo['id'],commit['sha']),repository_id=repo['id']);commits.append(commit)
            gaps.extend({**g,'repository_id':repo['id'],'repository':repo['repository_id']} for g in result['gaps'])
            mined.append(result)
        store.replace('mined',mined);store.replace('commits',commits);store.replace('file_changes',changes)
        links=[{'id':stable_id(pr['id'],sha),'pr_id':pr['id'],'repository':pr.get('repository'),'pr_number':pr.get('pr_number'),'sha':sha} for pr in store.rows('prs') for sha in (pr.get('commit_shas') or pr.get('initial_commit_shas') or [])]
        store.replace('pr_commit_links',links)
        manifest['mining_metrics']=[{'repository_id':r['repository_id'],'metrics':r['metrics'],'history_scope':r.get('history_scope'),'selected_shas':r['selected_shas']} for r in mined]
        details={'commits':len(commits),'file_changes':len(changes)}
    elif stage=='detect':
        events=[];snapshots=[];audit=[]
        for repo in store.rows('repositories'):
            mined=next(r for r in store.rows('mined') if r['repository_id']==repo['id'])
            overrides=store.rows('match_overrides')
            result=detect_history(repo,mined,config,overrides) if overrides else detect_history(repo,mined,config)
            events+=result['events'];snapshots+=result['snapshots'];audit+=result['audit'];gaps+=result['gaps']
        store.replace('log_events',events);store.replace('snapshots',snapshots);store.replace('retrieval_audit',audit)
        entities=[];edges=[]
        for snap in snapshots:
            for e in snap['entities']:
                eid=stable_id(snap['repository_id'],snap['sha'],e['path'],e['identity'])
                entities.append({**e,'id':eid,'repository_id':snap['repository_id'],'snapshot_sha':snap['sha']})
                edges.extend({'id':stable_id(eid,d),'entity_id':eid,'repository_id':snap['repository_id'],'snapshot_sha':snap['sha'],**d} for d in e['dependencies'])
        store.replace('log_entities',entities);store.replace('dependency_edges',edges)
        details={'log_events':len(events),'snapshots':len(snapshots),'dependency_edges':len(edges)}
    elif stage=='trace':
        evidence=[]
        if config['input'].get('provenance_path'):
            with open(config['input']['provenance_path']) as stream:
                evidence=[json.loads(line) for line in stream if line.strip()]
        result=trace_logs(store.rows('repositories'),store.rows('prs'),store.rows('mined'),store.rows('log_events'),store.rows('snapshots'),manifest['collection_cutoff_utc'],config['observation']['days'],all_gaps(store),evidence)
        for name,rows in result.items():store.replace(name,rows)
        details={name:len(rows) for name,rows in result.items()}
    elif stage=='assess':
        rows=assess(store.rows('log_changes'),store.rows('followups'))
        store.replace('candidates',rows)
        details={'candidates':len(rows)}
    elif stage=='reverse':
        from .reverse import scan_reverse
        evidence=[]
        if config['input'].get('provenance_path'):
            evidence=[json.loads(line) for line in Path(config['input']['provenance_path']).read_text().splitlines() if line.strip()]
        result=scan_reverse(store.rows('repositories'),store.rows('mined'),store.rows('prs'),config['reverse'],evidence)
        store.replace('reverse_candidates',result['reverse_candidates'])
        gaps=result['gaps'];details={'reverse_candidates':len(result['reverse_candidates']),**result['metrics']}
        manifest['reverse_metrics']=result['metrics']
    elif stage=='export':
        gaps=all_gaps(store)
        store.replace('coverage_gaps',gaps)
        store.replace('failures',[g for g in gaps if g.get('stage') in {'ingest','collect','mine'} or g.get('retryable')])
        details=export_run(run,store,manifest,config)
        gaps=[]
    elif stage=='match':
        # A control must already have commit-level provenance and same module;
        # unknown names or ordinary authors are not promoted to human controls.
        logs=store.rows('candidates');rows=[]
        for a in logs:
            if a['log_change_actor_type']!='agent':continue
            controls=[b for b in logs if b['repository_id']==a['repository_id'] and b['log_change_actor_type']=='human_led' and b['file_path']==a['file_path'] and b['cohort']==a['cohort'] and b['case_id']!=a['case_id']]
            rows.append({'id':stable_id('control',a['case_id']),'case_id':a['case_id'],'control_case_id':None,'status':'unmatched','reason':'no_independent_same_module_control_in_input' if not controls else 'same_PR_or_task_confounding_requires_task_metadata','candidate_ids':[c['case_id'] for c in controls],'matching_fields':['repository','file_path','cohort','commit_provenance'],'outcome_used_for_matching':False})
        store.replace('human_controls',rows);details={'unmatched':len(rows)}
    store.replace(stage+'_gaps',gaps)
    return details


def main(argv: list[str] | None=None) -> int:
    actual_argv = sys.argv[1:] if argv is None else argv
    if actual_argv and actual_argv[0] == 'screening':
        from .screening import main as screening_main
        return screening_main(actual_argv[1:])
    parser=argparse.ArgumentParser(description='PyDriller application-log history screener; static machine candidates only')
    parser.add_argument('command',choices=['doctor','run','match','discover','reverse','review-import','resolve-match','aidev-import','aidev-coverage','aidev-anchor-export','swechat-import','commit-import','collect-objects','batch-mine','batch-export','content-scan','schema-scan','structured-scan','content-repair','content-advance','content-reconcile','semantic-scan','semantic-codebook','semantic-history','semantic-model','semantic-demand','semantic-dfg','issue-knowledge','issue-reference','reference-library']+STAGES)
    parser.add_argument('--config',default=str(PROJECT/'config.example.yaml'))
    parser.add_argument('--input');parser.add_argument('--format',choices=['csv','jsonl','json','txt','aidev'])
    parser.add_argument('--run-id');parser.add_argument('--offline',action='store_true');parser.add_argument('--dry-run',action='store_true');parser.add_argument('--resume',action='store_true')
    parser.add_argument('--file');parser.add_argument('--reviewer')
    parser.add_argument('--confirm-all-issues',action='store_true',help='issue-knowledge: human confirms every source issue group as sensitive, including link-only groups')
    parser.add_argument('--model',help='Explicit Codex model ID for opt-in semantic-model')
    parser.add_argument('--query',action='append');parser.add_argument('--since',default='2021-01-01');parser.add_argument('--until',default=now()[:10])
    parser.add_argument('--output');parser.add_argument('--max-partitions',type=int,default=100)
    parser.add_argument('--with-reverse',action='store_true')
    parser.add_argument('--extend-from',help='Reuse complete Git extraction from an earlier frozen run into a new run')
    parser.add_argument('--run-mode',choices=['smoke','pilot','full'])
    parser.add_argument('--aidev-dir',help='Local directory containing AIDev Parquet tables')
    parser.add_argument('--swechat-dir',help='Local directory containing SWE-chat Parquet tables')
    parser.add_argument('--cache-dir',help='Dedicated Git cache for batch mining')
    parser.add_argument('--online',action='store_true',help='Allow batch mining to clone/fetch public Git repositories')
    parser.add_argument('--max-repositories',type=int,help='Repositories to attempt this invocation; remaining commits stay queued')
    parser.add_argument('--max-seconds',type=float,help='Batch invocation time budget; remaining commits stay queued')
    parser.add_argument('--max-commits',type=int,help='Exact commits to attempt in object collection')
    parser.add_argument('--retry-failed',action='store_true',help='Retry previously failed batch commits')
    parser.add_argument('--column-map',help='YAML/JSON table-to-column mappings for AIDev import')
    parser.add_argument('--batch-size',type=int,default=8192)
    parser.add_argument('--max-source-chars',type=int,default=1048576,help='Maximum characters per dataset text cell; unscanned tails are coverage gaps')
    parser.add_argument('--max-text-matches',type=int,default=1000,help='Maximum candidate spans per text cell; excess matches are coverage gaps')
    parser.add_argument('--max-json-documents',type=int,default=128)
    parser.add_argument('--max-json-depth',type=int,default=32)
    parser.add_argument('--max-json-nodes',type=int,default=10000)
    parser.add_argument('--max-json-decode-layers',type=int,default=2)
    parser.add_argument('--repair-page-chars',type=int,default=65536,help='Core Unicode characters per repair rule page (1..65536)')
    parser.add_argument('--repair-page-matches',type=int,default=1000,help='Repair page match threshold (1..1000); sibling labels commit together')
    parser.add_argument('--repair-run',help='Completed or partial fixed repair output for read-only reconciliation')
    parser.add_argument('--max-rows',type=int,help='New text source rows to process; zero exports the existing checkpoint')
    parser.add_argument('--min-free-gib',type=float,default=1.0,help='Free-space reserve for compressed text advance')
    parser.add_argument('--max-pages',type=int,help='Repair pages to commit this invocation; remaining work stays checkpointed')
    parser.add_argument('--aidev-import',dest='aidev_import_dir',help='Completed AIDev import directory for corpus coverage')
    parser.add_argument('--analysis-run',action='append',help='Run directory with code/type coverage exports; repeatable')
    args=parser.parse_args(argv);store=None;run=None
    try:
        config=load_config(args.config,args.input)
        if args.run_mode:config['run_mode']=args.run_mode
        if args.format:config['input']['format']=args.format
        if args.with_reverse:config['reverse']['enabled']=True
        offline=args.offline or config['input']['offline']
        if args.command=='reference-library':
            from .reference_library import build_library
            if not args.input or not args.output:raise ValueError('reference-library requires --input source-spec.json --output')
            result=build_library(args.input,args.output,offline=not args.online or args.offline,
                                 dry_run=args.dry_run,resume=args.resume)
            print(json.dumps(result,ensure_ascii=False,indent=2));return result['exit_code']
        if args.command=='semantic-dfg':
            from .semantic_dfg import export_dfg
            if not args.input or not args.output:raise ValueError('semantic-dfg requires --input frozen-semantic-run --output')
            if args.online:raise ValueError('semantic-dfg only reads frozen local history')
            result=export_dfg(args.input,args.output,config.get('dfg'),dry_run=args.dry_run,resume=args.resume,
                              max_cases=args.max_rows if args.max_rows is not None else 20)
            print(json.dumps(result,ensure_ascii=False,indent=2));return result['exit_code']
        if args.command=='issue-reference':
            from .issue_reference import run_references
            if not all((args.input,args.file,args.output,args.cache_dir)):
                raise ValueError('issue-reference requires --input selection.jsonl --file frozen-issue-root --output --cache-dir')
            result=run_references(args.input,args.file,args.output,args.cache_dir,offline=not args.online or args.offline,
                dry_run=args.dry_run,resume=args.resume,max_cases=args.max_rows if args.max_rows is not None else 12,max_seconds=args.max_seconds)
            print(json.dumps(result,ensure_ascii=False,indent=2));return result['exit_code']
        if args.command=='issue-knowledge':
            from .issue_knowledge import run_knowledge
            if not args.input or not args.output:raise ValueError('issue-knowledge requires --input --output')
            if len(args.analysis_run or [])>1:raise ValueError('issue-knowledge accepts one frozen semantic analysis run')
            result=run_knowledge(args.input,args.output,reviewer=args.reviewer,
                analysis_run=(args.analysis_run or [None])[0],max_cases=args.max_rows if args.max_rows is not None else 100,
                offline=True,dry_run=args.dry_run,resume=args.resume,confirm_all_issues=args.confirm_all_issues)
            print(json.dumps(result,ensure_ascii=False,indent=2));return result['exit_code']
        if args.command=='semantic-demand':
            from .semantic_demand import run_demand
            if not args.input or not args.output:raise ValueError('semantic-demand requires --input --output')
            result=run_demand(args.input,args.output,config,offline=not args.online or args.offline,
                              dry_run=args.dry_run,resume=args.resume)
            print(json.dumps(result,ensure_ascii=False,indent=2));return result['exit_code']
        if args.command=='semantic-model':
            from .semantic_model import run_models
            if not args.input or not args.output:raise ValueError('semantic-model requires --input --output')
            result=run_models(args.input,args.output,model=args.model,offline=not args.online or args.offline,
                              dry_run=args.dry_run,resume=args.resume,max_cases=args.max_rows if args.max_rows is not None else 2)
            print(json.dumps(result,ensure_ascii=False,indent=2));return result['exit_code']
        if args.command=='semantic-history':
            from .semantic_history import collect
            if not args.input or not args.output or not args.cache_dir:raise ValueError('semantic-history requires --input --output --cache-dir')
            result=collect(args.input,args.output,args.cache_dir,offline=not args.online or args.offline,dry_run=args.dry_run,
                           resume=args.resume,max_repositories=args.max_repositories or 3)
            if args.max_commits and not args.dry_run:
                from .semantic_history import audit_mining
                result['full_git_mining']=audit_mining(args.output,args.max_commits)
            print(json.dumps(result,ensure_ascii=False,indent=2));return result['exit_code']
        if args.command=='semantic-codebook':
            from .semantic_review import coding
            if not args.input or not args.output:raise ValueError('semantic-codebook requires --input --output')
            result=coding(args.input,args.output,file=args.file,reviewer=args.reviewer,dry_run=args.dry_run,resume=args.resume)
            print(json.dumps(result,ensure_ascii=False,indent=2));return result['exit_code']
        if args.command=='semantic-scan':
            from .semantic_scan import scan_semantics
            if not args.input or not args.output:
                raise ValueError('semantic-scan requires --input and --output')
            if args.online:
                raise ValueError('semantic-scan requires local frozen Git objects')
            try:
                result=scan_semantics(Path(args.input),Path(args.output),config,offline=offline,
                                     dry_run=args.dry_run,resume=args.resume,max_seconds=args.max_seconds)
            except (Exception,KeyboardInterrupt) as exc:
                print(json.dumps({'stage':'semantic-scan','error_type':type(exc).__name__,
                                  'reason':'semantic_scan_failed_without_source_text'}),file=sys.stderr)
                return 130 if isinstance(exc,KeyboardInterrupt) else 1
            print(json.dumps(result,ensure_ascii=False,indent=2))
            return result['exit_code']
        if args.command in {'schema-scan','structured-scan','content-repair','content-advance','content-reconcile'}:
            if not args.input or not args.output:
                raise ValueError(args.command+' requires --input and --output')
            if args.online:
                raise ValueError(args.command+' only reads local frozen sources')
            try:
                if args.command=='structured-scan':
                    from .structured_scan import scan_structured
                    result=scan_structured(Path(args.input),Path(args.output),resume=args.resume,dry_run=args.dry_run,
                                           batch_size=min(args.batch_size,32),max_seconds=args.max_seconds,max_rows=args.max_rows,
                                           max_source_chars=args.max_source_chars,max_matches=args.max_text_matches,
                                           max_documents=args.max_json_documents,max_depth=args.max_json_depth,
                                           max_nodes=args.max_json_nodes,max_decode_layers=args.max_json_decode_layers)
                elif args.command=='schema-scan':
                    from .schema_scan import scan_schema_context
                    result=scan_schema_context(Path(args.input),Path(args.output),resume=args.resume,
                                               dry_run=args.dry_run,batch_size=args.batch_size,max_seconds=args.max_seconds)
                elif args.command=='content-advance':
                    from .content_advance import advance_content
                    result=advance_content(Path(args.input),Path(args.output),resume=args.resume,dry_run=args.dry_run,
                                           batch_size=min(args.batch_size,64),max_seconds=args.max_seconds,
                                           max_rows=args.max_rows,min_free_bytes=int(args.min_free_gib*1024**3))
                elif args.command=='content-reconcile':
                    from .content_reconcile import reconcile_content
                    if not args.repair_run: raise ValueError('content-reconcile requires --repair-run')
                    result=reconcile_content(Path(args.input),Path(args.repair_run),Path(args.output),
                                             offline=True,dry_run=args.dry_run,resume=args.resume)
                else:
                    from .content_repair import run_content_repair
                    result=run_content_repair(Path(args.input),Path(args.output),offline=True,resume=args.resume,
                                              dry_run=args.dry_run,core_chars=args.repair_page_chars,
                                              page_matches=args.repair_page_matches,max_pages=args.max_pages,
                                              max_seconds=args.max_seconds)
            except (Exception,KeyboardInterrupt) as exc:
                print(json.dumps({'stage':args.command,'error_type':type(exc).__name__,
                                  'reason':'dataset_scan_failed_without_source_text'}),file=sys.stderr)
                return 130 if isinstance(exc,KeyboardInterrupt) else 1
            print(json.dumps({key:value for key,value in result.items()
                              if key not in {'fields','type_summary','fingerprint','tables','detector','non_text_columns'}},ensure_ascii=False,indent=2))
            return result['exit_code']
        if args.command=='content-scan':
            from .content_scan import scan_content
            if not args.input or not args.output:
                raise ValueError('content-scan requires --input (completed dataset import) and --output')
            if args.online:
                raise ValueError('content-scan only reads local frozen dataset tables')
            try:
                result=scan_content(Path(args.input),Path(args.output),resume=args.resume,dry_run=args.dry_run,
                                    batch_size=min(args.batch_size,64),max_seconds=args.max_seconds,
                                    max_source_chars=args.max_source_chars,max_matches=args.max_text_matches)
            except (Exception,KeyboardInterrupt) as exc:
                # Decoder/library exceptions can contain dataset text; never echo them.
                print(json.dumps({'stage':'content-scan','error_type':type(exc).__name__,
                                  'reason':'content_scan_failed_without_source_text'}),file=sys.stderr)
                return 130 if isinstance(exc,KeyboardInterrupt) else 1
            # Console summaries contain only aggregate counts; full source references stay in local artifacts.
            print(json.dumps({key:value for key,value in result.items() if key not in {'tables','detector','non_text_columns'}},ensure_ascii=False,indent=2))
            return result['exit_code']
        if args.command=='swechat-import':
            from .swechat import import_swechat
            if not args.swechat_dir or not args.output:
                raise ValueError('swechat-import requires --swechat-dir and --output')
            result=import_swechat(Path(args.swechat_dir),Path(args.output),resume=args.resume,
                                 dry_run=args.dry_run,batch_size=args.batch_size)
            print(json.dumps(redact(result),ensure_ascii=False,indent=2))
            return 0 if result['status'] in {'complete','dry_run'} else 2
        if args.command=='aidev-anchor-export':
            from .aidev_anchors import export_aidev_anchors
            if not args.aidev_import_dir or not args.output:
                raise ValueError('aidev-anchor-export requires --aidev-import and --output')
            result=export_aidev_anchors(Path(args.aidev_import_dir),Path(args.output),
                                        source_dir=Path(args.aidev_dir) if args.aidev_dir else None,
                                        dry_run=args.dry_run,resume=args.resume)
            print(json.dumps(redact(result),ensure_ascii=False,indent=2))
            return int(result.get('exit_code',0))
        if args.command in {'commit-import','collect-objects','batch-mine','batch-export'}:
            from .batch_mine import ingest_commit_contexts,run_batch,export_batch
            if not args.output:
                raise ValueError(args.command+' requires --output (batch directory)')
            if args.offline and args.online:
                raise ValueError('--offline and --online cannot be combined')
            if args.command=='commit-import' and not args.input:
                raise ValueError('commit-import requires --input')
            if args.dry_run:
                print(json.dumps({'dry_run':True,'command':args.command,'input':args.input,
                                  'output':args.output,'would_use_network':args.command in {'batch-mine','collect-objects'} and args.online,
                                  'target_repository_accessed':False,'files_written':False},ensure_ascii=False))
                return 0
            output=Path(args.output)
            if args.command=='commit-import':
                result=ingest_commit_contexts(Path(args.input),output)
            elif args.command=='collect-objects':
                from .object_acquisition import collect_batch_objects
                result=collect_batch_objects(output,Path(args.cache_dir or config['mining']['repository_cache']),
                    offline=not args.online,max_commits=args.max_commits,max_seconds=args.max_seconds,
                    max_repositories=args.max_repositories,retry_failed=args.retry_failed)
            elif args.command=='batch-mine':
                result=run_batch(output,Path(args.cache_dir or config['mining']['repository_cache']),
                                 offline=not args.online,max_repositories=args.max_repositories,
                                 max_seconds=args.max_seconds,retry_failed=args.retry_failed)
            else:
                result=export_batch(output)
            print(json.dumps(redact(result),ensure_ascii=False,indent=2))
            return int(result.get('exit_code',0))
        if args.command=='aidev-coverage':
            from .corpus_coverage import audit_corpus
            if not args.aidev_import_dir or not args.output:
                raise ValueError('aidev-coverage requires --aidev-import, --analysis-run and --output')
            result=audit_corpus(Path(args.aidev_import_dir),[Path(p) for p in args.analysis_run or []],
                                Path(args.output),dry_run=args.dry_run)
            print(json.dumps(redact(result),ensure_ascii=False,indent=2))
            return 0
        if args.command=='aidev-import':
            from .aidev import import_aidev
            if not args.aidev_dir or not args.output:
                raise ValueError('aidev-import requires --aidev-dir and --output')
            mapping=yaml.safe_load(Path(args.column_map).read_text()) if args.column_map else None
            result=import_aidev(Path(args.aidev_dir),Path(args.output),resume=args.resume,
                                dry_run=args.dry_run,batch_size=args.batch_size,column_mapping=mapping)
            print(json.dumps(redact(result),ensure_ascii=False,indent=2))
            return 0 if result['status'] in {'complete','dry_run'} else 2
        if args.command=='doctor':
            from pydriller import Repository,Git
            print(json.dumps({'versions':versions(),'repository_traverse_callable':callable(Repository.traverse_commits),'explicit_parent_diff_callable':callable(Git.diff),'offline':offline,'target_code_executed':False,'external_paid_llm_calls':0},ensure_ascii=False,indent=2));return 0
        if args.dry_run:
            limit,maximum=sampling_limits(config)
            planned=list(STAGES) if args.command=='run' else [args.command]
            if args.command=='run' and config['reverse']['enabled']:planned.insert(planned.index('export'),'reverse')
            print(json.dumps({'dry_run':True,'stages':planned,'run_mode':config['run_mode'],'extend_from':args.extend_from,'input':config['input'],'repository_limit':maximum,'pr_limit':limit,'history_commit_budget':config['mining']['max_history_commits_per_repository'],'would_use_network':not offline,'target_repository_accessed':False},ensure_ascii=False,indent=2));return 0
        if args.command=='discover':
            from .discovery import discover_prs
            client=GitHubClient(PROJECT/'data/cache/github',offline=offline,timeout=config['network']['timeout_seconds'],max_retries=config['network']['max_retries'])
            result=discover_prs(client,args.query or [],args.since,args.until,args.max_partitions)
            output=Path(args.output).resolve() if args.output else PROJECT/'data/inputs/discovered_prs.jsonl'
            write_jsonl(output,result['prs']);write_json(output.with_suffix('.discovery.json'),{**result,'prs_count':len(result['prs']),'failures':client.failures})
            print(json.dumps({'output':str(output),'records':len(result['prs']),'complete':result['complete'],'network_requests':client.requests}))
            return 0 if result['complete'] else 2
        if args.command in {'review-import','resolve-match'}:
            if not args.run_id or not args.file:
                raise ValueError('Review commands require --run-id and --file')
            if not (PROJECT/'outputs/runs'/args.run_id/'run_manifest.json').is_file():
                raise ValueError('Review commands require an existing run')
        run_id=args.run_id or 'run-'+now().replace(':','').replace('-','').split('.')[0]
        run,manifest=init_run(config,run_id,args.resume,sys.argv if argv is None else ['agentlog-unified',*argv])
        store=Store(run/config['storage']['index_database'])
        previous_data=None
        extension_id=args.extend_from or manifest.get('extension',{}).get('from_run_id')
        if extension_id:
            if extension_id==run_id:
                raise ValueError('--extend-from requires a different, earlier run ID')
            from .extension import load_previous_run
            previous_data=load_previous_run(PROJECT,extension_id,manifest,config)
            manifest['extension']={'from_run_id':extension_id,'reuse_policy':'complete_git_extraction_only; downstream_analysis_replayed'}
        if args.command=='review-import':
            from .review import import_reviews
            if store.status('assess') is None:
                raise ValueError('Review import requires assessed candidates')
            result=import_reviews(store,args.file,args.reviewer)
            if not result['errors']:
                export_run(run,store,manifest,config)
            print(json.dumps(redact(result),ensure_ascii=False))
            return 2 if result['errors'] else 0
        if args.command=='resolve-match':
            result=apply_match_file(store,args.file,args.reviewer)
            with store.db:
                store.replace('match_overrides',result['overrides'])
                for stage in ['detect','trace','assess']:
                    detail=execute(stage,store,config,manifest,run,offline,args.format)
                    store.finish(stage,'complete',**detail)
                    manifest['stages'][stage]={'status':'complete','finished_utc':now(),'details':detail}
            with store.db:
                detail=execute('export',store,config,manifest,run,offline,args.format)
                store.finish('export','complete',**detail)
            manifest['stages']['export']={'status':'complete','finished_utc':now(),'details':detail}
            manifest['exit_code']=2 if all_gaps(store) else 0
            manifest['finished_utc']=now()
            atomic_write(run/'run_manifest.json',json.dumps(manifest,ensure_ascii=False,indent=2))
            print(json.dumps({'applied':result['applied'],'replayed':['detect','trace','assess','export'],'privacy_labels_changed':False,'exit_code':manifest['exit_code']}))
            return manifest['exit_code']
        stages=list(STAGES) if args.command=='run' else [args.command]
        if args.command=='run' and config['reverse']['enabled']:
            stages.insert(stages.index('export'),'reverse')
        rerun=False
        for stage in stages:
            previous=STAGES[:STAGES.index(stage)] if stage in STAGES else STAGES[:6]
            if any(store.status(p) is None for p in previous):raise ValueError(f'{stage} requires preceding stages: {previous}')
            if args.resume and not rerun and store.status(stage)=='complete':
                continue
            rerun=True
            with store.db:
                details=execute(stage,store,config,manifest,run,offline,args.format,previous_data=previous_data) if previous_data else execute(stage,store,config,manifest,run,offline,args.format)
                status='partial' if stage in {'collect','mine','reverse'} and store.rows(stage+'_gaps') else 'complete'
                store.finish(stage,status,**details)
            manifest['stages'][stage]={'status':status,'finished_utc':now(),'details':details}
            atomic_write(run/'run_manifest.json',json.dumps(redact(manifest),ensure_ascii=False,indent=2))
            print(json.dumps({'stage':stage,'status':status,'counts':{k:v for k,v in details.items() if isinstance(v,int)}},ensure_ascii=False),flush=True)
        gaps=all_gaps(store)
        result=2 if gaps else 0
        manifest['exit_code']=result;manifest['finished_utc']=now()
        if (run/'fatal_error.json').exists():
            prior=json.loads((run/'fatal_error.json').read_text());prior['resolved_by_successful_resume']=now()
            write_json(run/'fatal_error.json',prior)
        # Keep resolved config and input hashes exact in private manifest. Sources
        # are already normalized; never include raw exceptions/auth headers.
        atomic_write(run/'run_manifest.json',json.dumps(manifest,ensure_ascii=False,indent=2))
        atomic_write(run/'logs/run.jsonl',''.join(canonical({'stage':s,**v})+'\n' for s,v in manifest['stages'].items()))
        print(json.dumps({'run_id':run_id,'output':str(run),'exit_code':result,'coverage_gap_records':len(gaps)},ensure_ascii=False))
        return result
    except (Exception,KeyboardInterrupt) as exc:
        failure={'stage':locals().get('stage','configuration'),'error_type':type(exc).__name__,'reason':str(exc) if isinstance(exc,(ValueError,FileNotFoundError)) else type(exc).__name__,'retryable':isinstance(exc,KeyboardInterrupt),'repository':None,'pr':None,'sha':None}
        if run:
            write_json(run/'fatal_error.json',failure)
        print(json.dumps(redact(failure),ensure_ascii=False),file=sys.stderr)
        return 130 if isinstance(exc,KeyboardInterrupt) else 1
    finally:
        if store:store.close()

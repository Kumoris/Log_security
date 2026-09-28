"""Terminal-only v050 delivery check using completed independent audits.

No source rows, private keys, SQLite or occurrence exports are read. Run only
after root confirms all writers stopped and the final documents were updated.
"""
from contextlib import ExitStack
from datetime import datetime, timezone
from importlib.metadata import version
from pathlib import Path
import argparse
import fcntl
import hashlib
import json
import re
import time
import tomllib
from urllib.parse import unquote

from verify_aidev_delivery_v048 import sha

BASE = Path(__file__).resolve().parents[1]
REPORTS = {'structured':'aidev_structured_v050_verification_attempt02.json',
           'content':'aidev_content_v050_verification.json',
           'repair':'aidev_repair_v050_verification.json',
           'reconciled':'aidev_reconcile_v050_verification.json',
           'inventory':'aidev_inventory_v050_verification.json'}


def verified(report):
    checks=report.get('checks',{})
    return bool(checks) and all(v is True for v in checks.values()) and report.get('all_checks_passed',report.get('all_passed')) is True


def recorded_digest(report,path):
    for field in ('evidence_sha256','evidence_files','files','input_sha256','output_sha256'):
        value=report.get(field,{}).get(str(path))
        if value is not None:return value.get('sha256') if isinstance(value,dict) else value
    return None


def markdown_targets(path,text):
    for target in re.findall(r'(?<!!)\[[^\]]+\]\(([^)]+)\)',text):
        target=unquote(target.strip('<>').split('#')[0])
        if target and not target.startswith(('http:','https:','mailto:')):
            yield (path.parent/target).resolve()


def run(base,output):
    started=datetime.now(timezone.utc).isoformat();clock=time.monotonic();docs=base/'docs';checks={};reads={};metadata={}
    def check(name,value):checks[name]=bool(value)
    def blob(path):
        data=path.read_bytes();digest=hashlib.sha256(data).hexdigest()
        if str(path) in reads and reads[str(path)]!=digest:raise ValueError('Delivery metadata changed while reading')
        reads[str(path)]=digest;return data
    def read(path):return json.loads(blob(path))
    with ExitStack() as stack:
        lock_paths=[base/'content-runs/aidev-v050-seed/.content.lock',base/'structured-runs/aidev-v050/.structured.lock',
                    base/'repair-runs/aidev-v050/scan/.repair.lock',base/'reconciled-runs/aidev-v050/.reconcile.lock']
        for path in lock_paths:
            lock=stack.enter_context(path.open('rb'));fcntl.flock(lock,fcntl.LOCK_SH|fcntl.LOCK_NB)
        check('no_active_pipeline_writer_under_shared_locks',True);metadata['locks_held']=[str(p) for p in lock_paths]
        directories={'structured':base/'structured-runs/aidev-v050','content':base/'content-runs/aidev-v050',
                     'repair':base/'repair-runs/aidev-v050/scan','reconciled':base/'reconciled-runs/aidev-v050'}
        names={'structured':'structured_coverage.json','content':'content_coverage.json','repair':'repair_coverage.json','reconciled':'merged_coverage.json'}
        manifests={k:read(p/'manifest.json') for k,p in directories.items()}
        coverages={k:read(directories[k]/name) for k,name in names.items()}
        state=read(directories['structured']/'export_state.json');advance=read(directories['content']/'advance_state.json')
        check('structured_terminal_fingerprint',state['status']=='complete' and state['fingerprint']==manifests['structured']['fingerprint'])
        check('structured_terminal_coverage_hash',state['outputs']['structured_coverage.json']['sha256']==reads[str(directories['structured']/names['structured'])])
        check('advance_terminal_snapshot',advance['status']=='export_complete' and advance['coverage_sha256']==reads[str(directories['content']/names['content'])])
        check('repair_rules_terminal',coverages['repair']['all_selected_cells_all_rules_finished'] and coverages['repair']['source_verification_complete'])
        check('reconciled_terminal_source_verified',manifests['reconciled']['status']=='complete' and coverages['reconciled']['source_verification_complete'] and manifests['reconciled']['fingerprint']==coverages['reconciled']['fingerprint'])
        check('both_text_row_scans_completed',coverages['structured']['all_source_rows_visited'] and coverages['content']['all_selected_text_rows_visited'])
        check('reconciled_parent_is_final_advance',manifests['reconciled']['parent_run']==str(directories['content']))
        check('nonadditive_pending_boundaries',coverages['reconciled']['parent_and_repair_counts_additive'] is False and all(c['runtime_confirmed'] is False and c['human_review_status']=='pending' for c in coverages.values()))
        audits={key:read(docs/name) for key,name in REPORTS.items()}
        for key,audit in audits.items():
            check(key+'_independent_audit_passed',verified(audit))
            if key in directories:
                path=directories[key]/names[key]
                check(key+'_audit_bound_to_current_coverage',recorded_digest(audit,path)==reads[str(path)])
        resume=read(docs/'aidev_structured_v050_resume_verification.json')
        check('structured_resume_independently_verified',verified(resume))
        inventory=read(docs/'aidev_observed_types_v050_provenance.json')
        check('inventory_audit_bound_to_provenance',audits['inventory'].get('provenance_sha256')==reads[str(docs/'aidev_observed_types_v050_provenance.json')])
        check('versioned_49_catalog_12_sources',inventory['catalog_version']=='1.2.0' and inventory['catalog_subtypes']==49 and len(inventory['sources'])==12 and inventory['row_count']==12*49)
        check('historical_new_types_not_evaluated',inventory['historical_rows_original_fields_preserved']==10*49 and inventory['historical_new_type_not_evaluated_rows']==8*(49-42) and inventory['historical_rows_recomputed'] is False)
        check('final_grid_uses_reconciled_only',inventory['new_plaintext_source']=='final_reconciled_snapshot_only' and inventory['advanced_raw_source_in_final_grid'] is False and inventory['counts_additive_across_scopes_or_runs'] is False)
        check('exactly_two_new_version_sources',sum(s['source_taxonomy_version']=='1.2.0' for s in inventory['sources'])==2 and {s['observation_scope'] for s in inventory['sources'] if s['source_taxonomy_version']=='1.2.0'}=={'dataset_text_reconciled','dataset_structured_text'})
        for path,expected in inventory['output_sha256'].items():check('inventory_digest_'+Path(path).name,sha(Path(path))==expected)
        tests=read(docs/'aidev_v050_tests_execution.json');testout=blob(Path(tests['stdout_path'])).decode()
        check('final_pytest_722_passed',tests['exit_code']==0 and re.search(r'\b722 passed\b',testout) is not None)
        check('final_tested_source_matches_current',tests['source_unchanged'] and tests['source_before']==tests['source_after'] and all(sha(base/p)==digest for p,digest in tests['source_after'].items()))
        progress=read(docs/'datasets_progress.json');commands=read(docs/'aidev_v050_commands.json')
        package=tomllib.loads(blob(base/'pyproject.toml').decode())['project']['version']
        check('package_installed_and_progress_version',package==version('agentlog-unified')==progress['tool_version']=='0.5.0')
        check('progress_catalog_and_exhaustion_boundary',progress['taxonomy_version']=='1.2.0' and progress['controlled_type_catalog_size']==inventory['catalog_subtypes'] and progress['all_real_sensitive_types_identified'] is False and progress['unknown_queue_exhausted'] is False)
        check('progress_report_commands_inventory_pointers',str(progress['current_report']).endswith('aidev_v050_report.md') and str(progress['latest_commands']).endswith('aidev_v050_commands.json') and str(progress['current_type_inventory']).endswith('aidev_observed_types_v050.csv'))
        check('progress_observed_union',progress['observed_controlled_type_label_union']==inventory['observed_catalog_type_union_count'])
        check('progress_structured_counts_match',progress['structured_scan']==coverages['structured'])
        check('commands_are_aidev_only',commands['dataset_scope']=='aidev_only')
        execution_summary=[];production=set()
        for item in commands['executions']:
            path=Path(item['path']);record=read(path);cmd=record['command']
            check('execution_index_'+path.stem,reads[str(path)]==item['sha256'] and record['exit_code']==item['exit_code'] and cmd==item['command'])
            stage=next((s for s in ('content-scan','content-advance','content-repair','content-reconcile','structured-scan') if s in cmd),None)
            if stage:
                if '--dry-run' not in cmd:production.add(stage)
                check('production_terminal_'+path.stem,record.get('finished_at') is not None and record['exit_code'] in (0,2) and record.get('source_unchanged') is True and record['source_before']==record['source_after'])
            for stream in ('stdout','stderr'):
                if stream+'_path' in record and stream+'_sha256' in record:
                    check('execution_'+stream+'_'+path.stem,sha(Path(record[stream+'_path']))==record[stream+'_sha256'])
            execution_summary.append({'record':str(path),'exit_code':record['exit_code'],'source_unchanged':record.get('source_unchanged'),'stage':stage})
        check('real_execution_records_cover_pipeline',production=={'content-scan','content-advance','content-repair','content-reconcile','structured-scan'})
        metadata['execution_records']=execution_summary
        paths=[base.parent/'README.md',base/'README.md',docs/'aidev_v050_report.md'];texts={p:blob(p).decode() for p in paths}
        missing=[];links=0
        for path,text in texts.items():
            for target in markdown_targets(path,text):
                links+=1
                if target!=output and not target.exists():missing.append({'document':str(path),'target':str(target)})
        check('local_markdown_links_resolve',not missing);metadata['links_checked']=links;metadata['missing_links']=missing
        report=texts[docs/'aidev_v050_report.md'];readme=texts[base/'README.md']
        check('readme_current_version_and_report','当前版本 **0.5.0**' in readme and 'aidev_v050_report.md' in readme[:1500] and 'aidev_v050_report.md' in texts[base.parent/'README.md'])
        check('report_identifies_v050','0.5.0' in report[:600])
        check('report_old_taxonomy_not_evaluated_explained','not_evaluated' in report and ('null' in report or '空计数' in report))
        check('report_counts_not_additive',any(x in report for x in ('不能直接相加','不能相加','不可相加')))
        check('report_pending_not_confirmed','pending' in report and 'runtime_confirmed' in report and 'new_type_status' in report)
        primary={'source_rows':coverages['structured']['source_rows'],'structured_candidates':coverages['structured']['candidate_occurrences'],'reconciled_candidate_identities':coverages['reconciled']['candidate_identities'],'observed_type_union':inventory['observed_catalog_type_union_count']}
        metadata['primary_counts_from_terminal_evidence']=primary
        check('report_primary_counts_present',all(str(n) in report or f'{n:,}' in report for n in primary.values()))
        metadata['count_and_completeness_review']='Source-row completion, finite-rule repair completion and unresolved sensitive semantics remain distinct. Advanced and repaired raw occurrences are not extra inventory sources.'
        check('all_read_metadata_unchanged',all(sha(Path(p))==digest for p,digest in reads.items()))
    result={'started_utc':started,'completed_utc':datetime.now(timezone.utc).isoformat(),'elapsed_seconds':time.monotonic()-clock,'checks':checks,'passed':sum(checks.values()),'total':len(checks),'all_checks_passed':all(checks.values()),'metadata':metadata,'input_sha256':reads,'verifier_sha256':sha(Path(__file__)),'raw_source_values_read':False,'sqlite_or_occurrence_exports_read':False,'source_or_tests_modified':False,'active_writer_observed':False,'limitations':['This consumes existing independent data audits; it does not repeat source, gzip-row, repair or inventory verification.','Lock checks cover the declared pipeline writers; they do not claim that no other unrelated process exists.','Text checks establish selected version, links, counts and boundary wording, not full natural-language semantic verification.']}
    if output.exists():raise FileExistsError('Preserve existing delivery verification')
    output.write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps({'report':str(output),'passed':result['passed'],'total':result['total'],'all_checks_passed':result['all_checks_passed'],'failed':[k for k,v in checks.items() if not v]}))
    return 0 if result['all_checks_passed'] else 1


def self_test():
    assert verified({'checks':{'a':True},'all_checks_passed':True})
    assert not verified({'checks':{'a':False},'all_checks_passed':True})
    assert not verified({'checks':{},'all_checks_passed':True})
    assert recorded_digest({'evidence_files':{'/synthetic':{'sha256':'fixed'}}},Path('/synthetic'))=='fixed'
    assert recorded_digest({},Path('/missing')) is None
    assert list(markdown_targets(Path('/tmp/report.md'),'[source](<a%20b.md>) [web](https://example.invalid)'))==[Path('/tmp/a b.md').resolve()]
    print(json.dumps({'self_test':'passed','checks':6,'real_outputs_read':False}))


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--run',action='store_true');parser.add_argument('--self-test',action='store_true');parser.add_argument('--base-dir',type=Path,default=BASE);parser.add_argument('--report',type=Path,default=BASE/'docs/aidev_delivery_v050_verification.json');args=parser.parse_args()
    if args.self_test:self_test()
    elif args.run:raise SystemExit(run(args.base_dir.resolve(),args.report.resolve()))
    else:print('Prepared only. Run after all pipeline writers terminate and root finishes README, progress and commands.')

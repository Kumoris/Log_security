"""Select a complete, independently reconciled attempt without overwriting either."""
from run_swechat_followups import *
from package_swechat_followups import readrows, ancestor
from agent_log_motivation_v11 import file_hash


def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('--repository', required=True)
    ap.add_argument('--attempt-root', required=True, type=Path)
    args=ap.parse_args(); root=args.attempt_root.resolve()
    if not root.is_relative_to((OUT/'additional-attempts').resolve()):
        raise ValueError('Attempt must be isolated under additional-attempts')
    name=args.repository; directory=root/'repositories'/name.replace('/','--')
    provenance=json.loads((root/'attempt_provenance.json').read_text(encoding='utf-8'))
    status=json.loads((root/'attempt_status.json').read_text(encoding='utf-8'))
    summary=json.loads((directory/'summary.json').read_text(encoding='utf-8'))
    history=json.loads((directory/'history_scope.json').read_text(encoding='utf-8'))
    receipt_name=name.replace('/','--')+'.json'
    receipt=json.loads((OUT/'collection'/receipt_name).read_text(encoding='utf-8'))
    ledger=list(readrows(directory/'candidate_ledger.jsonl'))
    original={r['log_id']:r for r in inputs() if r['repo_id']==name}
    cases={r['case_id']:r for r in readrows(directory/'log_changes.jsonl')}
    events=list(readrows(directory/'followups.jsonl'))
    parents={r['sha']:r['parents'] for r in history['graph']}
    fp=set(history['first_parent_shas'])
    frozen_fields=('repo_id','commit_sha','path','start_line','end_line','attribution_grade','file_attribution_labels')
    checks=dict(
        complete=status['status']=='finished' and status['returncode']==0 and summary['status']=='executed',
        same_repository=provenance['repository']==summary['repository']==name,
        same_input=provenance['original_input_sha256']==hashlib.sha256(INPUT.read_bytes()).hexdigest(),
        same_collection=file_hash(root/'collection'/receipt_name)==file_hash(OUT/'collection'/receipt_name)==provenance['frozen_collection_receipt_sha256'],
        same_frozen_tip=history['history_scope']['frozen_tip']==receipt['tip'],
        every_candidate=len(ledger)==len(original)==len({r['log_id'] for r in ledger}) and {r['log_id'] for r in ledger}==set(original),
        unchanged_candidate_fields=all(all(r[k]==original[r['log_id']][k] for k in frozen_fields) for r in ledger),
        exact_callees=all(c['after']['callee']==original[i]['callee'] for c in cases.values() for i in c['stage1_log_ids']),
        event_ids_unique=len(events)==len({e['id'] for e in events}),
        events_have_cases=all(e['case_id'] in cases for e in events),
        exact_first_parent=all(e['sha'] in fp and e['parent_sha']==(parents.get(e['sha']) or [None])[0] for e in events),
        actual_later_events=all(e['sha']!=cases[e['case_id']]['intro_sha'] and e['change_kind'] not in {'coverage_gap','gap_resumed'} for e in events),
        integration_ancestry=all(cases[e['case_id']]['integration_sha'] and ancestor(cases[e['case_id']]['integration_sha'],e['sha'],parents) for e in events),
        declared_event_count=summary['events']==len(events),
    )
    result=dict(status='PASS' if all(checks.values()) else 'FAIL',repository=name,checks=checks,
                candidates=len(ledger),event_links=len(events),original_attempt_interrupted=False,
                artifact_sha256={p.name:file_hash(p) for p in directory.iterdir() if p.is_file() and p.name not in {'progress.json','execution.lock'}})
    dest=root/'selection_validation.json'
    if dest.exists():raise RuntimeError('Selection validation already exists')
    dump(dest,result)
    if result['status']!='PASS':raise RuntimeError('Additional attempt validation failed')
    selection=OUT/'selected_repository_attempts.json'
    selected=json.loads(selection.read_text(encoding='utf-8')) if selection.exists() else {}
    if name in selected:raise RuntimeError('Repository attempt already selected')
    selected[name]=dict(directory=str(directory),validation_status='PASS',validation_path=str(dest),
                        validation_sha256=file_hash(dest),frozen_tip=receipt['tip'],input_sha256=provenance['original_input_sha256'])
    dump(selection,selected)
    print(json.dumps(dict(status='PASS',repository=name,candidates=len(ledger),event_links=len(events))),flush=True)


if __name__=='__main__':main()

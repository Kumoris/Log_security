"""Independent, read-only reconciliation of this additive delivery."""
import argparse
import csv
import json
from pathlib import Path
from agent_log_motivation import file_hash, rows, write_json


def verify(root, output):
    root=Path(root).resolve();checks={};errors=[]
    manifest=json.loads((root/'manifest.json').read_text(encoding='utf-8'))
    checks['manifest_files']=len(manifest['artifacts'])
    for name,h in manifest['artifacts'].items():
        if file_hash(root/name)!=h:errors.append('artifact_hash:'+name)
    audit=json.loads((root/'audit/summary.json').read_text(encoding='utf-8'))
    p=audit['legacy_population']
    checks['population_identity_reconciliation']=all(audit['reconciliation'].values())
    checks['status_partition']=sum(p['extraction_status'].values())==p['rows']==24685
    checks['status_fraction']=p['extraction_complete_fraction']==p['extraction_status']['completed']/p['rows']
    checks['field_partition']=audit['field_rows']['countable']+audit['field_rows']['parent_or_noncountable']==audit['field_rows']['rows']
    checks['legacy_primary_keys_unique']=p['duplicate_log_id_rows']==audit['duplicate_field_id_rows']==0
    integrity=json.loads((root/'audit/input_integrity.json').read_text(encoding='utf-8'))
    checks['audit_inputs_unchanged_now']=all(file_hash(path)==h for path,h in integrity['input_sha256'].items())
    for name in ['swechat_stage3_final','calibration_delivery']:
        directory=root/name
        summary=json.loads((directory/'summary.json').read_text(encoding='utf-8'))
        events=[r for _,r in rows(directory/'log_modifications.jsonl')]
        evidence={r['evidence_id']:r for _,r in rows(directory/'motive_evidence.jsonl')}
        links=[r for _,r in rows(directory/'evidence_links.jsonl')]
        motives=[r for _,r in rows(directory/'motives.jsonl')]
        joined=[r for _,r in rows(directory/'modifications_with_evidence.jsonl')]
        checks[name+':event_count']=len(events)==summary['events']
        checks[name+':left_join']={r['event_id'] for r in joined}=={r['event_id'] for r in events}=={r['event_id'] for r in motives}
        checks[name+':foreign_keys']=all(r['evidence_id'] in evidence for r in links)
        checks[name+':link_ids_unique']=len({r['link_id'] for r in links})==len(links)
        checks[name+':evidence_identity_unique']=len({(r['source_type'],r['repository'],r['source_id'],r['content_sha256']) for r in evidence.values()})==len(evidence)
        for table in ['log_modifications','motive_evidence','evidence_links','motives','modifications_with_evidence','unresolved_records']:
            a=[r for _,r in rows(directory/(table+'.jsonl'))]
            with (directory/(table+'.csv')).open(encoding='utf-8-sig',newline='') as f:b=list(csv.DictReader(f))
            checks[name+':csv_rows:'+table]=len(a)==len(b)
        for conclusion in motives:
            linked={r['evidence_id'] for r in links if r['event_id']==conclusion['event_id']}
            for claim in conclusion['claims']:
                for citation in claim['citations']:
                    if citation['evidence_id'] not in linked or citation['quote'] not in evidence[citation['evidence_id']]['text']:
                        errors.append('invalid_claim_citation')
        provenance=summary['provenance']
        checks[name+':implementation_hash']=provenance['script_sha256']==file_hash(root/'code/agent_log_motivation.py')
        if provenance.get('input_sha256'):
            checks[name+':upstream_unchanged_now']=all(file_hash(p)==h for p,h in provenance['input_sha256'].items())
        if summary['delivery_status']=='awaiting_upstream_stage2':
            checks[name+':missing_is_not_zero_population']=summary['population_event_count'] is None and all(v is None for v in summary['motive_distribution'].values())
        else:
            checks[name+':distribution_partition']=sum(summary['motive_distribution'].values())==len(events)
            for kind,c in summary['source_coverage'].items():
                expected=len({r['event_id'] for r in links if r['source_type']==kind})
                checks[name+':coverage:'+kind]=c['events']==expected and c['denominator']==len(events)
    for name,value in checks.items():
        if value is False:errors.append(name)
    write_json(output,{'status':'PASS' if not errors else 'FAIL','checks':checks,'errors':errors,
                       'limits':'Integrity and implemented invariants; not independent human attribution/motivation accuracy.'})
    print(json.dumps({'status':'PASS' if not errors else 'FAIL','checks':len(checks),'errors':errors}))
    if errors:raise SystemExit(1)


if __name__=='__main__':
    ap=argparse.ArgumentParser();ap.add_argument('--root',type=Path,required=True);ap.add_argument('--output',type=Path,required=True)
    a=ap.parse_args();verify(a.root,a.output)

"""Independently reconcile exported artifacts, relations, citations and counts."""
from run_swechat_followups import *
from agent_log_motivation_v11 import file_hash,digest,TYPES,STATUSES
from package_swechat_followups import readrows

def verify(stage3_name='stage3'):
    s2=OUT/'stage2';s3=OUT/stage3_name;checks={}
    for directory in [s2,s3]:
        manifest=json.loads((directory/'manifest.json').read_text(encoding='utf-8'))
        checks[directory.name+'_artifact_hashes']=all(file_hash(directory/n)==h for n,h in manifest['artifacts'].items())
    ledger=list(readrows(s2/'candidate_ledger.jsonl'));original=inputs()
    checks['all_4128_input_ids_preserved']=len(ledger)==len(original)==len({r['log_id'] for r in ledger}) and {r['log_id'] for r in ledger}=={r['log_id'] for r in original}
    fs=list(readrows(s2/'followups.jsonl'));raw=list(readrows(s2/'raw_followups.jsonl'));gaps=list(readrows(s2/'coverage_intervals.jsonl'))
    stage2_summary=json.loads((s2/'summary.json').read_text(encoding='utf-8'))
    checks['candidate_event_pair_grain_explicit']=stage2_summary['stage2_candidate_event_pairs']==sum(len(r.get('followup_ids',[])) for r in ledger)
    checks['raw_tracker_rows_preserved']=len(raw)==len(fs)+len(gaps)
    checks['coverage_intervals_not_claimed_as_actual_edits']=all(f['change_kind'] not in {'coverage_gap','gap_resumed'} for f in fs)
    anchors=list(readrows(s2/'log_source_anchors.jsonl'))
    checks['source_anchor_byte_hashes']=all(hashlib.sha256(r['source'].encode()).hexdigest()==r['source_sha256'] and hashlib.sha1(b'blob '+str(len(r['source'].encode())).encode()+b'\0'+r['source'].encode()).hexdigest()==r['git_blob_id'] for r in anchors)
    events=list(readrows(s3/'log_modifications.jsonl'));eids={r['event_id']:r for r in events}
    evidence=list(readrows(s3/'motive_evidence.jsonl'));evmap={r['evidence_id']:r for r in evidence}
    links=list(readrows(s3/'evidence_links.jsonl'));motives=list(readrows(s3/'motives.jsonl'))
    joined=list(readrows(s3/'modifications_with_evidence.jsonl'))
    summary=json.loads((s3/'summary.json').read_text(encoding='utf-8'))
    cache_hashes=summary['provenance'].get('external_cache_artifacts',{})
    checks['raw_external_response_hashes']=all(file_hash(s3/'external_cache'/name)==h for name,h in cache_hashes.items())
    checks['all_stage2_inputs_retained']=len(fs)==len(events)==len(eids)
    checks['source_rows_unique']=len(evmap)==len(evidence)
    checks['source_content_hashes']=all(r['content_sha256']==digest(r['text']) for r in evidence)
    checks['source_types_valid']=all(r['source_type'] in TYPES for r in evidence)
    checks['links_unique']=len({r['link_id'] for r in links})==len(links)
    checks['link_foreign_keys']=all(r['event_id'] in eids and r['evidence_id'] in evmap for r in links)
    checks['exact_event_link_locators']=all(r['modification_sha']==eids[r['event_id']]['modification_sha'] and r['file_path']==eids[r['event_id']]['file_path'] and r['repository']==eids[r['event_id']]['repository'] for r in links)
    checks['motives_cover_all_events']={r['event_id'] for r in motives}==set(eids) and len(motives)==len(events)
    checks['left_join_keeps_unlinked_events']={r['event_id'] for r in joined}==set(eids)
    checks['joined_code_and_stage1_ids_preserved']=all(r.get('observed_change')==eids[r['event_id']].get('observed_change') and r.get('stage1_log_ids')==eids[r['event_id']].get('stage1_log_ids') for r in joined)
    linked={(r['event_id'],r['evidence_id']) for r in links}
    checks['quotes_exist_and_are_associated']=all((m['event_id'],q['evidence_id']) in linked and q['quote'] in evmap[q['evidence_id']]['text'] for m in motives for a in m['claims'] for q in a['citations'])
    checks['motive_distribution_matches']=all(summary['motive_distribution'][s]==sum(m['motive_status']==s for m in motives) for s in STATUSES)
    checks['all_motive_statuses_valid']=all(m['motive_status'] in STATUSES for m in motives)
    checks['not_presented_as_human_ground_truth']=all(m['human_validated'] is False for m in motives)
    for kind in TYPES:
        n=len({r['event_id'] for r in links if r['source_type']==kind});c=summary['source_coverage'][kind]
        checks['coverage_'+kind]=c['events']==n and c['denominator']==len(events) and c['fraction']==(n/len(events) if events else None)
    checks['stage_one_denominator_preserved']=summary['upstream']['stage1_rows']==len(original)
    checks['second_stage_validation_passed']=json.loads((s2/'validation.json').read_text(encoding='utf-8'))['status']=='PASS'
    checks['third_stage_validation_passed']=json.loads((s3/'validation.json').read_text(encoding='utf-8'))['status']=='PASS'
    result=dict(status='PASS' if all(checks.values()) else 'FAIL',checks=checks,checked_events=len(events),checked_sources=len(evidence),checked_links=len(links),
        known_limit='Structural correctness is not independent human motive accuracy')
    dump(OUT/(stage3_name+'_independent_validation.json'),result)
    print(json.dumps({k:v for k,v in result.items() if k!='checks'}),flush=True)
    return result

if __name__=='__main__':
    ap=argparse.ArgumentParser();ap.add_argument('--stage3-name',default='stage3');a=ap.parse_args();result=verify(a.stage3_name);sys.exit(0 if result['status']=='PASS' else 1)

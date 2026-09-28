"""Validate the review overlay against immutable v12 sources; never rerun tracing."""
import sys,json,collections,subprocess,hashlib,argparse,re
from pathlib import Path
from review_agent_log_motives import ROOT,PARENT,OUT,read,write,lines,sha,now
from agent_log_review_delivery import validate_annotation

def main(delivery_name='delivery_v2'):
    if not re.fullmatch(r'delivery_v[0-9]+',delivery_name):raise ValueError('invalid_delivery_name')
    d=OUT/delivery_name;v=OUT/'verification'/delivery_name;v.mkdir(exist_ok=True);checks=[]
    def check(name,value,detail=None):
        checks.append({'check':name,'pass':bool(value),'detail':detail})
    events=read(d/'log_modification_reviews.jsonl');old=read(PARENT/'delivery/unique_log_modifications.jsonl')
    old_by={r['modification_id']:r for r in old};em={r['modification_id']:r for r in events}
    check('all_unique_events_retained',len(em)==len(events)==len(old)==1757 and set(em)==set(old_by))
    invariant=('association_count','association_event_ids','change_relation','file_path','lineage_confidence_counts','modification_sha','new_path','observed_change','old_path','parent_sha','repository','stage1_log_ids')
    check('original_code_lineage_and_candidate_associations_unchanged',all(all(r[k]==old_by[r['modification_id']][k] for k in invariant) for r in events))
    check('all_associations_retained',sum(r['association_count'] for r in events)==18173)
    evs=read(d/'motive_evidence.jsonl');ev={e['evidence_id']:e for e in evs};pe=read(PARENT/'stage3_final/motive_evidence.jsonl')
    check('unique_evidence_ids',len(ev)==len(evs))
    check('all_parent_evidence_content_and_provenance_preserved',all(all(ev[e['evidence_id']][k]==val for k,val in e.items()) for e in pe))
    check('evidence_content_hashes',all(hashlib.sha256(e['text'].encode()).hexdigest()==e['content_sha256'] for e in evs))
    links=read(d/'evidence_links.jsonl');ix=collections.defaultdict(list)
    for l in links:ix[l['modification_id'],l['evidence_id']].append(l)
    check('evidence_link_foreign_keys',all(l['modification_id'] in em and l['evidence_id'] in ev for l in links))
    check('evidence_link_target_binding',all(all(l[k]==em[l['modification_id']][k] for k in ('repository','modification_sha','file_path')) for l in links))
    keys=[(l['modification_id'],l['evidence_id'],l['relation']) for l in links]
    check('no_duplicate_event_evidence_relation',len(keys)==len(set(keys)))
    oldlinks={r['link_id']:r for r in read(PARENT/'stage3_final/evidence_links.jsonl')};ids=set()
    valid=True
    for l in links:
        for lid in l.get('original_link_ids',[]):
            ids.add(lid);p=oldlinks.get(lid)
            valid &= bool(p and p['event_id'] in em[l['modification_id']]['association_event_ids'] and p['evidence_id']==l['evidence_id'])
    check('all_original_191672_chains_resolvable',valid and ids==set(oldlinks),{'count':len(ids)})
    annotations=read(d/'annotations.jsonl');errors=[]
    for a in annotations:
        try:validate_annotation(a,em[a['modification_id']],ev,ix)
        except Exception as exc:errors.append({'modification_id':a['modification_id'],'error':str(exc)})
    check('annotation_quotes_targets_and_status_contracts',not errors,{'checked':len(annotations),'errors':errors})
    stats=json.loads((d/'statistics.json').read_text())
    pending=read(d/'pending_events.jsonl')
    check('unknown_and_pending_not_dropped',sum(r['motive_status']=='unknown' for r in events)==stats['motive_distribution']['unknown'] and {r['modification_id'] for r in pending}=={r['modification_id'] for r in events if r['review_state']=='pending_semantic_review'} and len(pending)==stats['pending_semantic_review'])
    hashes=json.loads((OUT/'parent_integrity.json').read_text());changed=[p for p,h in hashes.items() if sha(PARENT/p.replace('\\','/'))!=h]
    check('parent_input_hashes_unchanged',not changed,{'checked_files':len(hashes),'changed':changed})
    # New saved responses are checked against imported source text and locators.
    added=read(OUT/'supplement/evidence.jsonl');bad=[]
    for e in added:
        receipt=json.loads(Path(e['source_local_path']).read_text());body=json.loads(receipt['response_text']);objects=body if isinstance(body,list) else [body]
        matches=[o for o in objects if str(o.get('id'))==e['source_id']]
        if len(matches)!=1:bad.append(e['evidence_id']);continue
        o=matches[0];text=((o.get('title')+'\n\n') if o.get('title') else '')+(o.get('body') or '')
        if text!=e['text'] or o.get('html_url')!=e['source_url']:bad.append(e['evidence_id'])
    check('new_external_source_readback',not bad,{'checked':len(added),'errors':bad})
    outcomes=read(OUT/'supplement/request_outcomes.jsonl')
    aliases=read(d/'supplemental_evidence_aliases.jsonl');raw_added={e['evidence_id']:e for e in added}
    check('supplemental_source_duplicates_reuse_parent_ids',len(aliases)==8 and all(raw_added[a['fetched_evidence_id']]['source_url']==ev[a['retained_evidence_id']]['source_url'] and raw_added[a['fetched_evidence_id']]['text'].replace('\r\n','\n').strip()==ev[a['retained_evidence_id']]['text'].replace('\r\n','\n').strip() for a in aliases))
    check('readonly_receipt_hashes',all(sha(OUT/r['receipt'])==r['receipt_sha256'] for r in outcomes))
    check('failures_and_empty_sources_distinguished',collections.Counter(r['state'] for r in outcomes)=={'success':4,'success_empty':2,'redirect_unresolved':1,'tool_endpoint_not_supported':1})
    test=subprocess.run([sys.executable,'-m','unittest','discover','-s','scripts','-p','test_agent_log_review_delivery.py','-v'],cwd=ROOT,capture_output=True,text=True)
    (v/'contract_tests.txt').write_text(test.stdout+test.stderr,encoding='utf-8');check('synthetic_contract_tests',test.returncode==0,{'independent_accuracy_evaluation':False})
    result={'at':now(),'status':'PASS' if all(c['pass'] for c in checks) else 'FAIL','checks':checks,'semantic_review_complete':False,'independent_evaluation':False}
    write(v/'validation.json',result);print(json.dumps(result,ensure_ascii=False,indent=2))
    if result['status']!='PASS':raise SystemExit(1)
if __name__=='__main__':
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--delivery-name',default='delivery_v2');args=ap.parse_args();main(args.delivery_name)

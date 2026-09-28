"""Bounded two-cell investigation; never prints or exports source text or value hashes."""
from pathlib import Path
from datetime import datetime, timezone
import hashlib
import json
import time

import pyarrow.parquet as pq
from agentlog_unified import content_types as ct, content_cursor as cursor

BASE = Path(__file__).resolve().parent.parent
TARGETS = {2989: [(1046759,1046788,'BIZ','business_object'),(1046950,1046956,'DIAG','exception_message'),(1048434,1048436,'CFG','environment')],
           4562: [(391763,391765,'BIZ','request_body'),(391763,391765,'BIZ','business_object')]}


def identity(row): return row['start'],row['end'],row['category'],row['subtype']


def complete_finite_reference(text):
    rows={}
    for iterator in (ct._literal_candidates(text),ct._named_candidates(text)):
        for row in iterator: rows.setdefault(identity(row),row)
    return rows


def paged(text, deadline):
    state={'rule_index':0,'search_offset':0};result={};gaps=[];pages=0
    while state['rule_index'] < len(cursor.SPECS):
        if time.monotonic()>deadline: raise TimeoutError()
        rows,next_state,more_gaps=cursor.page(text,state,core=65536,max_rows=1000)
        if state==next_state:raise RuntimeError()
        for row in rows:result.setdefault(identity(row),row)
        gaps.extend(more_gaps);pages+=1;state=next_state
    return result,pages,gaps


def envelopes(text, targets):
    result=[]
    for match in ct._NAMED.finditer(text):
        covered=[t for t in targets if match.start()<=t[0] and t[1]<=match.end()]
        if not covered:continue
        raw=match['value'];quoted=len(raw)>=2 and raw[0] in "\"'" and raw[-1]==raw[0]
        result.append({'raw_match_span':list(match.span()),'key_span':list(match.span('key')),'value_span':list(match.span('value')),
                       'quoted_value':quoted,'key_has_controlled_taxonomy':bool(ct._matches(match['key'])),
                       'key_has_unknown_hint_rule':bool(ct._UNKNOWN_KEY.fullmatch(match['key'])),
                       'covered_target_spans':[list(t[:2]) for t in covered]})
    return result


def main():
    started=datetime.now(timezone.utc).isoformat();deadline=time.monotonic()+180
    manifest=json.loads((BASE/'content-runs/swechat-v044/manifest.json').read_text())
    table=next(t for t in manifest['tables'] if t['path']=='commits.parquet');path=Path(table['absolute_path'])
    stat_before=path.stat();h=hashlib.sha256()
    with path.open('rb') as stream:
        while chunk:=stream.read(1024*1024):
            if time.monotonic()>deadline:raise TimeoutError()
            h.update(chunk)
    if h.hexdigest()!=table['sha256'] or stat_before.st_size!=table['bytes']:raise ValueError()
    parquet=pq.ParquetFile(path);group_start=0;values={};arrow_batches=0
    for group in range(parquet.metadata.num_row_groups):
        end=group_start+parquet.metadata.row_group(group).num_rows
        targets={n for n in TARGETS if group_start<n<=end}
        if targets:
            n=group_start
            for batch in parquet.iter_batches(batch_size=1,row_groups=[group],columns=['file_attribution']):
                n+=1;arrow_batches+=1
                if time.monotonic()>deadline:raise TimeoutError()
                if n in targets:values[n]=batch.column(0)[0].as_py()
                if n>=max(targets):break
        group_start=end
    if set(values)!=set(TARGETS):raise ValueError()
    results=[]
    for source_row,text in values.items():
        targets=TARGETS[source_row];prefix=text[:ct.MAX_SOURCE_CHARS]
        parent=ct.classify_text(prefix,max_matches=1000)
        prefix_all=complete_finite_reference(prefix);full=complete_finite_reference(text)
        paged_full,pages,gaps=paged(text,deadline)
        target_details=[]
        for target in targets:
            target_details.append({'span':list(target[:2]),'category':target[2],'subtype':target[3],
                'parent_capped':next((r for r in parent['matches'] if identity(r)==target),None),
                'prefix_uncapped':prefix_all.get(target),'full_reference':full.get(target),'paged_full':paged_full.get(target)})
        common=set(full)&set(paged_full)
        ordered_unique={}
        for iterator in (ct._literal_candidates(prefix),ct._named_candidates(prefix)):
            for row in iterator:ordered_unique.setdefault(identity(row),row)
        ordered=list(ordered_unique)
        result={'source_row':source_row,'table_path':'commits.parquet','column_name':'file_attribution','characters':len(text),'parent_prefix_characters':len(prefix),
                'parent_capped_count':len(parent['matches']),'parent_match_cap_triggered':parent['truncated'],
                'prefix_uncapped_count':len(prefix_all),'full_reference_count':len(full),'paged_count':len(paged_full),'pages':pages,'gap_count':len(gaps),
                'paged_full_identity_equal':set(full)==set(paged_full),'paged_full_details_equal':all(full[k]==paged_full[k] for k in common),
                'full_reference_missing_from_pages':len(set(full)-set(paged_full)),'paged_extra_vs_reference':len(set(paged_full)-set(full)),
                'targets':target_details,'prefix_raw_match_envelopes':envelopes(prefix,targets),'full_raw_match_envelopes':envelopes(text,targets),
                'target_rule_order_positions_one_based':[{'span':list(t[:2]),'category':t[2],'subtype':t[3],'position':ordered.index(t)+1 if t in ordered_unique else None} for t in targets]}
        results.append(result)
    # Invented strings demonstrate the mechanism without reproducing real keys/values.
    synthetic='outer_unmapped="data=opaque-value; error=opaque-value; environment=opaque-value;"'
    synthetic_short=synthetic[:-1]
    a=list(ct._named_candidates(synthetic_short));b=list(ct._named_candidates(synthetic));c,_,_=paged(synthetic,deadline)
    final_stat=path.stat();stable=(stat_before.st_dev,stat_before.st_ino,stat_before.st_size,stat_before.st_mtime_ns,stat_before.st_ctime_ns)==(final_stat.st_dev,final_stat.st_ino,final_stat.st_size,final_stat.st_mtime_ns,final_stat.st_ctime_ns)
    report={'started_utc':started,'completed_utc':datetime.now(timezone.utc).isoformat(),'results':results,
        'frozen_table_sha256_verified':True,'source_stat_unchanged':stable,'selected_cells_converted_to_python_strings':len(values),
        'arrow_batches_materialized_in_selected_column':arrow_batches,'other_source_cells_converted_to_python_strings':False,
        'synthetic_boundary_mechanism':{'prefix_named_candidates':len(a),'full_named_candidates':len(b),'full_paged_candidates':len(c)},
        'execution_source_sha256':{n:hashlib.sha256((BASE/'src/agentlog_unified'/n).read_bytes()).hexdigest() for n in ['content_types.py','content_cursor.py','content_repair.py']},
        'raw_source_printed_or_exported':False,'dynamic_keys_exported':False,'value_hashes_exported':False,'credential_values_verified':False,
        'shared_databases_accessed':False,'existing_runs_modified':False,'package_source_modified':False,
        'reference_semantics':'Uncapped finite reference reuses the literal and named generators, retains first observation per (start,end,type), and bypasses only the public 1 Mi-character guard for the selected 1,052,614-character cell; it is not full semantic parsing.'}
    out=BASE/'docs/swechat_reconcile_v046_replacement_causes.json'
    if out.exists():raise RuntimeError()
    out.write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps({'report':str(out),'source_stat_unchanged':stable,'cells':[{'source_row':r['source_row'],'parent_count':r['parent_capped_count'],'prefix_all':r['prefix_uncapped_count'],'full_reference':r['full_reference_count'],'paged':r['paged_count'],'identities_equal':r['paged_full_identity_equal'],'details_equal':r['paged_full_details_equal'],'target_positions':r['target_rule_order_positions_one_based']} for r in results]},ensure_ascii=False))


if __name__=='__main__':
    try:main()
    except BaseException as exc:
        print(json.dumps({'status':'failed','error_type':type(exc).__name__,'source_text_omitted':True}))
        raise SystemExit(1)

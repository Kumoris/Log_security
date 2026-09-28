"""Offline rescan of a frozen selection of previously truncated text cells.

Output is a separate observation scope. Rescanned results must not be directly
added to parent occurrences. All source cells remain semantically unreviewed.
"""
from __future__ import annotations
from collections import Counter, defaultdict
from contextlib import ExitStack
import csv
import fcntl
import gzip
import hashlib
import hmac
import json
import math
import re
import os
from pathlib import Path
import shutil
import sqlite3
import time

from . import content_cursor, content_types
from .storage import atomic_write, canonical, csv_cell, stable_id
from .taxonomy import TAXONOMY_VERSION, taxonomy_catalog

SCOPE = {'observation_scope':'dataset_text_cell_rescan','application_log_evidence':False,
         'runtime_confirmed':False,'human_review_status':'pending','full_dataset_coverage_claim':False,
         'taxonomy_version':TAXONOMY_VERSION,'new_type_status':'not_established'}
MATCH_FIELDS = {'start','end','category','subtype','rule','basis','confidence','value_status','candidate_status'}
SOURCE_FIELDS = {'id','table_path','source_row','column_name','field_scope','characters','scanned_characters','text_hmac_sha256'}
TYPE_KEYS = {(c['category'],s['subtype']) for c in taxonomy_catalog()['categories'] for s in c['subtypes']} | {(None,None)}
LIMITATIONS = ['Full rule traversal is not complete semantic sensitive-type detection.',
 'Quoted named values beyond the finite 4096-token rule remain unresolved; no additional semantic rules are added.',
 'Regex windows and result pages are bounded; Arrow still materializes a complete selected string scalar.',
 'Parent and repair occurrences must not be directly summed; use source-cell/span/type reconciliation.',
 'All selected cells remain in the unknown review queue, including completed lexical scans.']


class _BudgetExpired(Exception):
    pass


def _check_time(deadline):
    if deadline is not None and time.monotonic() >= deadline:
        raise _BudgetExpired


def _digest(path, deadline=None):
    result=hashlib.sha256()
    with Path(path).open('rb') as stream:
        while chunk:=stream.read(1024*1024):
            _check_time(deadline);result.update(chunk)
    return result.hexdigest()


def _stat(path):
    value=Path(path).stat()
    return value.st_dev,value.st_ino,value.st_size,value.st_mtime_ns,value.st_ctime_ns


def _key(parent, manifest):
    value=(parent/'.fingerprint-key').read_bytes()
    if len(value)!=32 or hashlib.sha256(value).hexdigest()!=manifest['fingerprint_key_sha256']:
        raise ValueError('Parent private fingerprint key is missing or changed')
    return value


def _parent_sources(parent, manifest):
    imported=Path(manifest['source_import']).resolve()
    path=imported/'manifest.json'
    if _digest(path)!=manifest['source_manifest_sha256']:
        raise ValueError('Frozen import manifest changed')
    document=json.loads(path.read_text())
    if document.get('status')!='complete': raise ValueError('Frozen import is not complete')
    signature=document['source_signature']; root=Path(signature['source_dir']).resolve()
    frozen={row['path']:row for row in signature['inputs']}
    tables={}
    for row in manifest['tables']:
        relative=row['path']; target=(root/relative).resolve()
        if relative not in frozen or not target.is_relative_to(root) or target!=Path(row['absolute_path']).resolve():
            raise ValueError('Parent source table escapes its frozen import')
        if any(row[k]!=frozen[relative][k] for k in ('sha256','bytes')):
            raise ValueError('Parent source table fingerprint is inconsistent')
        tables[relative]=row
    return tables


def _safe_output(output, protected):
    if any(output==p or output.is_relative_to(p) for p in protected):
        raise ValueError('Repair output must be independent of inputs and parent outputs')


def prepare_repair_selection(parent_run, selection_dir, *, dry_run=False):
    """Freeze exact metadata rows from one finished export, without source decode."""
    # Import at call time: reconciliation shares this module's source validators.
    from .content_reconcile import _parent_view, _lock, _readonly, _validate_parent
    parent=Path(parent_run).resolve(); output=Path(selection_dir).resolve()
    view=_parent_view(parent);manifest,original,ancestor,checkpoint,locks=view
    advanced=manifest.get('engine')=='content_advance_v1'
    manifest_path=parent/'manifest.json'
    queue=parent/('content_unknown_type_review_queue.jsonl.gz' if advanced else 'content_unknown_type_review_queue.jsonl')
    with ExitStack() as stack:
        for path in sorted(set(locks)): _lock(stack,path)
        if _parent_view(parent)!=view: raise ValueError('Parent changed while acquiring selection locks')
        tables=_parent_sources(parent,manifest);_key(parent,manifest);_key(ancestor,original)
        coverage_path=parent/'content_coverage.json';coverage=json.loads(coverage_path.read_text())
        if advanced:
            state_path=parent/'advance_state.json';state=json.loads(state_path.read_text())
            if state.get('status')!='export_complete' or state.get('coverage_sha256')!=_digest(coverage_path):
                raise ValueError('Advance export is incomplete or stale')
            current_classifier={name:_digest(Path(content_types.__file__).with_name(name)) for name in ('content_types.py','taxonomy.py','storage.py')}
            if any(original['fingerprint']['source_sha256'].get(name)!=value for name,value in current_classifier.items()):
                raise ValueError('Advance parent differs from the current finite classifier')
            db=_readonly(checkpoint);stack.callback(db.close)
            _validate_parent(db,coverage,manifest)
        if coverage.get('source_manifest_sha256')!=manifest['source_manifest_sha256']:
            raise ValueError('Parent coverage does not match its source manifest')
        if coverage.get('observation_scope')!='dataset_text_cells': raise ValueError('Parent is not a text-cell scan')
        required=[coverage.get('unknown_type_review_export_records'),coverage.get('unknown_type_review_cells'),coverage.get('counts',{}).get('truncated_cells')]
        if any(type(value) is not int or value<0 for value in required):
            raise ValueError('Parent coverage lacks required queue completeness counters')
        if not queue.is_file(): raise ValueError('Parent review queue is missing')
        selected=[];seen=set();statuses=Counter();before=_stat(queue);expanded=0;intervals=defaultdict(list)
        columns={relative:{f['column']:f for f in table['columns'] if f['selected']} for relative,table in tables.items()}
        with (gzip.open(queue,'rt',encoding='utf-8') if advanced else queue.open(encoding='utf-8')) as stream:
            for line in stream:
                row=json.loads(line); statuses[str(row.get('status'))]+=1
                table=tables.get(row.get('table_path'));start=row.get('start_row');end=row.get('end_row');count=row.get('row_count')
                if table is None or type(start) is not int or type(end) is not int or type(count) is not int or not 1<=start<=end<=table['rows'] or count!=end-start+1:
                    raise ValueError('Parent review queue has invalid source ranges')
                if row.get('column_name') not in columns[row['table_path']] or row.get('field_scope')!=columns[row['table_path']][row['column_name']]['field_scope']:
                    raise ValueError('Parent review queue has an invalid source column')
                if row.get('id')!=stable_id('content-cell',manifest['source_manifest_sha256'],row['table_path'],start,row['column_name']):
                    raise ValueError('Parent review queue source identity differs')
                if row.get('record_kind')=='cell':
                    if row.get('source_row')!=start or count!=1 or row.get('status') not in {'truncated','scanned_with_semantic_gaps'}:
                        raise ValueError('Parent review cell reference is inconsistent')
                elif row.get('record_kind')=='source_row_range':
                    if row.get('source_row') is not None or row.get('status')!='unclassified_text':
                        raise ValueError('Parent review range reference is inconsistent')
                else: raise ValueError('Parent review record kind is unknown')
                expanded+=count;intervals[(row['table_path'],row['column_name'])].append((start,end))
                if row.get('status')!='truncated': continue
                if row.get('record_kind')!='cell': raise ValueError('Truncated review record must identify one cell')
                safe={k:row[k] for k in SOURCE_FIELDS}
                table=tables.get(safe['table_path']);n=safe['source_row']
                if table is None or type(n) is not int or not 1<=n<=table['rows']:
                    raise ValueError('Selected source row is out of bounds')
                fields={f['column']:f for f in table['columns'] if f['selected']}
                if safe['column_name'] not in fields or fields[safe['column_name']]['field_scope']!=safe['field_scope']:
                    raise ValueError('Selected source column is not a frozen text column')
                expected=stable_id('content-cell',manifest['source_manifest_sha256'],safe['table_path'],n,safe['column_name'])
                if safe['id']!=expected or expected in seen: raise ValueError('Selected cell identity is inconsistent or duplicated')
                if type(safe['characters']) is not int or safe['characters']<=0: raise ValueError('Selected character count is invalid')
                if not isinstance(safe['text_hmac_sha256'],str) or not re.fullmatch('[0-9a-f]{64}',safe['text_hmac_sha256']):
                    raise ValueError('Selected cell lacks a private source fingerprint')
                if type(safe['scanned_characters']) is not int or not 0<=safe['scanned_characters']<=safe['characters']:
                    raise ValueError('Selected prior character prefix is invalid')
                if advanced:
                    original_cell=db.execute('SELECT * FROM cells WHERE id=?',(expected,)).fetchone()
                    if original_cell is None or original_cell['status']!='truncated' or any(original_cell[k]!=safe[k] for k in SOURCE_FIELDS):
                        raise ValueError('Selected queue metadata differs from the shared checkpoint')
                seen.add(expected);selected.append(safe)
        queue_hash=_digest(queue)
        if before!=_stat(queue): raise ValueError('Parent queue changed during selection')
        if sum(statuses.values())!=required[0] or expanded!=required[1] or len(selected)!=required[2]:
            raise ValueError('Parent queue and coverage counters disagree; export may be interrupted')
        for spans in intervals.values():
            previous=0
            for start,end in sorted(spans):
                if start<=previous: raise ValueError('Parent review source ranges overlap')
                previous=end
        selected.sort(key=lambda row:(row['table_path'],row['source_row'],row['column_name']))
        text=''.join(canonical(row)+'\n' for row in selected)
        document={'selection_version':1,'parent_run':str(parent),'parent_manifest_sha256':_digest(manifest_path),
                  'parent_ancestor_run':str(ancestor),'parent_ancestor_manifest_sha256':_digest(ancestor/'manifest.json'),
                  'parent_queue_name':queue.name,'parent_queue_format':'gzip_jsonl' if advanced else 'jsonl',
                  'parent_coverage_sha256':_digest(coverage_path),'parent_queue_sha256':queue_hash,
                  'source_manifest_sha256':manifest['source_manifest_sha256'],
                  'parent_fingerprint_key_sha256':manifest['fingerprint_key_sha256'],
                  'source_status':'truncated','selected_cells':len(selected),'selected_characters':sum(r['characters'] for r in selected),
                  'selection_sha256':hashlib.sha256(text.encode()).hexdigest(),'queue_status_counts':dict(statuses),
                  'queue_record_count':sum(statuses.values()),'queue_expanded_cell_count':expanded,'queue_coverage_counts_verified':True,**SCOPE}
        if advanced:
            document.update(parent_advance_state_sha256=_digest(state_path),parent_checkpoint_path=str(checkpoint),
                            parent_checkpoint_identity=manifest['checkpoint_identity'])
        _safe_output(output,[parent,ancestor,Path(manifest['source_import']).resolve()]+[Path(t['absolute_path']).parent for t in tables.values()])
        if dry_run: return {**document,'files_written':False,'source_values_decoded':False}
        if output.exists() and any(output.iterdir()): raise ValueError('Selection directory is not empty')
        output.mkdir(parents=True,exist_ok=True,mode=0o700)
        atomic_write(output/'selection.jsonl',text)
        atomic_write(output/'selection_manifest.json',canonical(document)+'\n')
        return {**document,'files_written':True,'source_values_decoded':False}


def _load_selection(selection):
    from .content_reconcile import _parent_view
    document=json.loads((selection/'selection_manifest.json').read_text())
    if _digest(selection/'selection.jsonl')!=document['selection_sha256']:
        raise ValueError('Frozen repair selection changed')
    parent=Path(document['parent_run']).resolve()
    if _digest(parent/'manifest.json')!=document['parent_manifest_sha256']:
        raise ValueError('Parent scan manifest changed')
    manifest,original,ancestor,checkpoint,locks=_parent_view(parent)
    if ('parent_ancestor_run' in document and
        (Path(document['parent_ancestor_run']).resolve()!=ancestor or document['parent_ancestor_manifest_sha256']!=_digest(ancestor/'manifest.json'))):
        raise ValueError('Frozen repair parent ancestry changed')
    tables=_parent_sources(parent,manifest);key=_key(parent,manifest);_key(ancestor,original)
    rows=[json.loads(line) for line in (selection/'selection.jsonl').read_text().splitlines()]
    if len(rows)!=document['selected_cells'] or any(set(row)!=SOURCE_FIELDS for row in rows):
        raise ValueError('Frozen selection shape changed')
    return document,parent,manifest,tables,key,rows


def _verify_tables(cells,tables,deadline):
    verified={}
    for relative in sorted({row['table_path'] for row in cells}):
        table=tables[relative];path=Path(table['absolute_path']);before=_stat(path)
        if path.stat().st_size!=table['bytes'] or _digest(path,deadline)!=table['sha256']:
            raise ValueError('Selected frozen Parquet changed')
        if _stat(path)!=before: raise ValueError('Selected frozen Parquet changed during verification')
        verified[relative]=before
    return verified


def _selected_values(cells,tables,deadline,verified):
    """Decode selected fields only, in row order; no target code is imported."""
    import pyarrow.parquet as pq
    grouped=defaultdict(list)
    for cell in cells: grouped[cell['table_path']].append(cell)
    for relative,selected in sorted(grouped.items()):
        table=tables[relative];path=Path(table['absolute_path']);before=verified[relative]
        if _stat(path)!=before: raise ValueError('Selected frozen source changed after verification')
        parquet=pq.ParquetFile(path);group_start=0
        for group in range(parquet.metadata.num_row_groups):
            end=group_start+parquet.metadata.row_group(group).num_rows
            targets=defaultdict(list)
            for cell in selected:
                if group_start<cell['source_row']<=end: targets[cell['source_row']].append(cell)
            if targets:
                columns=sorted({row['column_name'] for rows in targets.values() for row in rows})
                last=max(targets);row_number=group_start
                try:
                    for batch in parquet.iter_batches(batch_size=1,row_groups=[group],columns=columns):
                        _check_time(deadline);row_number+=1
                        for cell in targets.get(row_number,[]):
                            value=batch.column(columns.index(cell['column_name']))[0].as_py()
                            if not isinstance(value,str): raise ValueError('Selected cell is no longer a string')
                            yield cell,value,path,before
                        if row_number>=last: break
                except _BudgetExpired: raise
                except Exception: raise RuntimeError('Selected Parquet decoding failed without source text') from None
            group_start=end
        if _stat(path)!=before: raise ValueError('Selected frozen source changed during reading')


def _verify_hmac(text,key,expected,deadline):
    result=hmac.new(key,digestmod=hashlib.sha256)
    for start in range(0,len(text),65536):
        _check_time(deadline);result.update(text[start:start+65536].encode('utf-8'))
    if not hmac.compare_digest(result.hexdigest(),expected):
        raise ValueError('Selected source cell HMAC does not match its prior fingerprint')


def _write_rows(output,name,rows,fields):
    js=output/(name+'.jsonl.tmp');cs=output/(name+'.csv.tmp')
    with js.open('w',encoding='utf-8') as j,cs.open('w',newline='',encoding='utf-8') as c:
        os.chmod(js,0o600);os.chmod(cs,0o600);writer=csv.DictWriter(c,fieldnames=fields);writer.writeheader()
        count=0
        for row in rows:
            if set(row)!=set(fields): raise ValueError('Unapproved repair export fields')
            j.write(canonical(row)+'\n');writer.writerow({key:csv_cell(row[key]) for key in fields});count+=1
    os.replace(js,output/(name+'.jsonl'));os.replace(cs,output/(name+'.csv'))
    return count


def _export(db,output,manifest,stop_reason,source_verification_complete):
    def observations(excluded):
        for row in db.execute('SELECT m.id,m.cell_id,m.details,c.source FROM matches m JOIN cells c ON c.id=m.cell_id WHERE excluded=? ORDER BY m.id',(excluded,)):
            source=json.loads(row[3]);detail=json.loads(row[2])
            yield {'id':row[0],'cell_id':row[1],**{k:source[k] for k in ('table_path','source_row','column_name','field_scope')},**detail,**SCOPE}
    fields=['id','cell_id','table_path','source_row','column_name','field_scope']+sorted(MATCH_FIELDS)+list(SCOPE)
    candidate_count=_write_rows(output,'repair_type_occurrences',observations(0),fields)
    excluded=_write_rows(output,'repair_excluded',observations(1),fields)
    def review():
        for row in db.execute('SELECT id,source,cursor,status,pages FROM cells ORDER BY id'):
            source=json.loads(row[1])
            yield {'cell_id':row[0],**{k:source[k] for k in ('table_path','source_row','column_name','field_scope','characters','text_hmac_sha256')},
                   'cursor':json.loads(row[2]),'status':row[3],'pages':row[4],
                   'reason':'full_text_semantics_and_finite_named_value_limits_unresolved',**SCOPE}
    review_fields=['cell_id','table_path','source_row','column_name','field_scope','characters','text_hmac_sha256','cursor','status','pages','reason']+list(SCOPE)
    _write_rows(output,'repair_unknown_type_review_queue',review(),review_fields)
    def gaps():
        for row in db.execute('SELECT cell_id,details FROM gaps ORDER BY id'):
            yield {'cell_id':row[0],**json.loads(row[1]),**SCOPE}
    gap_count=_write_rows(output,'repair_data_gaps',gaps(),['cell_id','start','end','reason']+list(SCOPE))
    statuses=dict(db.execute('SELECT status,COUNT(*) FROM cells GROUP BY status'))
    recorded_complete=statuses.get('complete_with_semantic_gaps',0)
    complete=statuses.get('pending',0)+statuses.get('partial',0)==0 and source_verification_complete
    evidence=defaultdict(dict)
    for category,subtype,status,status_count in db.execute("SELECT category,subtype,json_extract(details,'$.candidate_status'),COUNT(*) FROM matches WHERE excluded=0 GROUP BY category,subtype,3"):
        evidence[(category,subtype)][status]=status_count
    labels=[{'category':r[0],'subtype':r[1],'occurrence_count':r[2],'distinct_cell_count':r[3],
             'candidate_status_counts':evidence[(r[0],r[1])],**SCOPE} for r in db.execute('SELECT category,subtype,COUNT(*),COUNT(DISTINCT cell_id) FROM matches WHERE excluded=0 GROUP BY category,subtype')]
    _write_rows(output,'repair_type_summary',iter(labels),['category','subtype','occurrence_count','distinct_cell_count','candidate_status_counts']+list(SCOPE))
    result={'status':'complete_with_semantic_gaps' if complete else 'partial','selected_cells':manifest['selected_cells'],
            'selected_characters':manifest['selected_characters'],'all_selected_cells_all_rules_finished':complete,
            'recorded_completed_cells':recorded_complete,'source_verification_complete':source_verification_complete,
            'candidate_occurrences':candidate_count,'excluded_occurrences':excluded,'data_gap_records':gap_count,
            'unknown_type_review_cells':sum(statuses.values()),'cell_status_counts':statuses,
            'committed_pages':db.execute('SELECT COALESCE(SUM(pages),0) FROM cells').fetchone()[0],
            'stop_reason':stop_reason,'type_summary':labels,'limitations':LIMITATIONS,
            'parent_and_repair_counts_additive':False,'exit_code':2,**SCOPE}
    atomic_write(output/'repair_coverage.json',canonical(result)+'\n')
    return result


def _validate_budgets(*,core_chars=65536,page_matches=1000,max_pages=None,max_seconds=None):
    if type(core_chars) is not int or not 1<=core_chars<=65536: raise ValueError('Invalid repair core character budget')
    if type(page_matches) is not int or not 1<=page_matches<=1000: raise ValueError('Invalid repair page match threshold')
    if max_pages is not None and (type(max_pages) is not int or max_pages<0): raise ValueError('Invalid page budget')
    if max_seconds is not None and (type(max_seconds) not in (int,float) or not math.isfinite(max_seconds) or max_seconds<=0): raise ValueError('Invalid time budget')


def repair_content(selection_dir,output_dir,*,offline=True,resume=False,dry_run=False,
                   core_chars=65536,page_matches=1000,max_pages=None,max_seconds=None):
    """Execute finite rule pages; 2 denotes explicit semantic/coverage gaps."""
    if not offline: raise ValueError('Repair supports offline sources only')
    _validate_budgets(core_chars=core_chars,page_matches=page_matches,max_pages=max_pages,max_seconds=max_seconds)
    started=time.monotonic();deadline=started+max_seconds if max_seconds is not None else None
    selection=Path(selection_dir).resolve();output=Path(output_dir).resolve()
    selected,parent,old,tables,key,cells=_load_selection(selection)
    _safe_output(output,[selection,parent,Path(selected.get('parent_ancestor_run',parent)),Path(old['source_import']).resolve()]+[Path(t['absolute_path']).parent for t in tables.values()])
    fingerprint={'selection_manifest_sha256':_digest(selection/'selection_manifest.json'),'selection_sha256':selected['selection_sha256'],
                 'core_chars':core_chars,'page_matches':page_matches,
                 'source_sha256':{name:_digest(Path(__file__).with_name(name)) for name in ('content_repair.py','content_cursor.py','content_reconcile.py')},
                 'classifier_sha256':{name:_digest(Path(content_types.__file__).with_name(name)) for name in ('content_types.py','taxonomy.py','storage.py')}}
    if dry_run:
        for relative in {r['table_path'] for r in cells}:
            table=tables[relative]
            if Path(table['absolute_path']).stat().st_size!=table['bytes'] or _digest(table['absolute_path'])!=table['sha256']:
                raise ValueError('Selected frozen Parquet changed')
        return {'status':'dry_run','selected_cells':len(cells),'selected_characters':selected['selected_characters'],
                'files_written':False,'source_values_decoded':False,'exit_code':0,'fingerprint':fingerprint,**SCOPE}
    output.mkdir(parents=True,exist_ok=True,mode=0o700)
    with (output/'.repair.lock').open('a') as lock:
        try: fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError: raise RuntimeError('Repair already has an active writer') from None
        manifest_path=output/'manifest.json'
        if manifest_path.exists():
            manifest=json.loads(manifest_path.read_text())
            if not resume or manifest['fingerprint']!=fingerprint: raise ValueError('Repair resume requires identical frozen selection, classifier and limits')
        else:
            if any(p.name!='.repair.lock' for p in output.iterdir()): raise ValueError('Repair output is not empty')
            manifest={'fingerprint':fingerprint,'selected_cells':len(cells),'selected_characters':selected['selected_characters'],
                      'selection_dir':str(selection),'parent_run':str(parent),'parent_manifest_sha256':selected['parent_manifest_sha256'],**SCOPE}
            atomic_write(manifest_path,canonical(manifest)+'\n')
        db=sqlite3.connect(output/'repair.sqlite');os.chmod(output/'repair.sqlite',0o600)
        db.executescript('CREATE TABLE IF NOT EXISTS cells(id TEXT PRIMARY KEY,source TEXT,cursor TEXT,status TEXT,pages INTEGER DEFAULT 0); CREATE TABLE IF NOT EXISTS matches(id TEXT PRIMARY KEY,cell_id TEXT,category TEXT,subtype TEXT,excluded INTEGER,details TEXT); CREATE TABLE IF NOT EXISTS gaps(id TEXT PRIMARY KEY,cell_id TEXT,details TEXT);')
        pages=0;stop_reason=None;source_verification_complete=False
        try:
            with db:
                db.executemany('INSERT OR IGNORE INTO cells(id,source,cursor,status) VALUES(?,?,?,?)',[(r['id'],canonical(r),canonical({'rule_index':0,'search_offset':0}),'pending') for r in cells])
            pending={r[0] for r in db.execute("SELECT id FROM cells WHERE status!='complete_with_semantic_gaps'")}
            try:
                verified=_verify_tables(cells,tables,deadline);source_verification_complete=True
                if max_pages==0 and pending: stop_reason='page_budget'
                else:
                    for cell,text,path,before in _selected_values([r for r in cells if r['id'] in pending],tables,deadline,verified):
                        if len(text)!=cell['characters']: raise ValueError('Selected source character count changed')
                        _verify_hmac(text,key,cell['text_hmac_sha256'],deadline)
                        while True:
                            state=json.loads(db.execute('SELECT cursor FROM cells WHERE id=?',(cell['id'],)).fetchone()[0])
                            if state['rule_index']==len(content_cursor.SPECS): break
                            _check_time(deadline)
                            if max_pages is not None and pages>=max_pages: stop_reason='page_budget';break
                            if shutil.disk_usage(output).free<2*1024**3: stop_reason='disk_budget';break
                            if _stat(path)!=before: raise ValueError('Selected source changed during rule traversal')
                            rows,next_state,gaps=content_cursor.page(text,state,core=core_chars,max_rows=page_matches)
                            if _stat(path)!=before: raise ValueError('Selected source changed during rule traversal')
                            with db:
                                for row in rows:
                                    if set(row)!=MATCH_FIELDS or (row['category'],row['subtype']) not in TYPE_KEYS or not 0<=row['start']<row['end']<=len(text):
                                        raise ValueError('Unapproved repair candidate metadata')
                                    mid=stable_id(cell['id'],row['start'],row['end'],row['category'],row['subtype'])
                                    db.execute('INSERT OR IGNORE INTO matches VALUES(?,?,?,?,?,?)',(mid,cell['id'],row['category'],row['subtype'],int(row['value_status']=='placeholder_or_example'),canonical(row)))
                                for gap in gaps:
                                    if set(gap)!={'start','end','reason'} or gap['reason']!='unclosed_private_key_envelope' or not 0<=gap['start']<gap['end']<=len(text): raise ValueError('Unapproved repair gap metadata')
                                    db.execute('INSERT OR IGNORE INTO gaps VALUES(?,?,?)',(stable_id(cell['id'],gap),cell['id'],canonical(gap)))
                                status='complete_with_semantic_gaps' if next_state['rule_index']==len(content_cursor.SPECS) else 'partial'
                                db.execute('UPDATE cells SET cursor=?,status=?,pages=pages+1 WHERE id=?',(canonical(next_state),status,cell['id']))
                            pages+=1
                        if stop_reason: break
            except _BudgetExpired: stop_reason='time_budget'
            result=_export(db,output,manifest,stop_reason,source_verification_complete)
            result.update(pages_this_invocation=pages,elapsed_seconds=round(time.monotonic()-started,3),network_accessed=False,target_code_executed=False)
            atomic_write(output/'repair_coverage.json',canonical(result)+'\n')
            return result
        finally: db.close()


def run_content_repair(parent_run,output_dir,*,offline=True,resume=False,dry_run=False,**budgets):
    """Single user-facing entry: freeze output/selection and write output/scan."""
    if not offline: raise ValueError('Repair supports offline sources only')
    _validate_budgets(**budgets)
    parent=Path(parent_run).resolve();output=Path(output_dir).resolve();selection=output/'selection'
    if dry_run:
        result=prepare_repair_selection(parent,selection,dry_run=True)
        return {**result,'status':'dry_run','exit_code':0,'planned_output':str(output),'network_accessed':False,'target_code_executed':False}
    if resume:
        document=json.loads((selection/'selection_manifest.json').read_text())
        if Path(document['parent_run']).resolve()!=parent:
            raise ValueError('Repair input differs from its fixed parent selection')
    else:
        prepare_repair_selection(parent,selection)
    return repair_content(selection,output/'scan',offline=offline,resume=resume,**budgets)

"""Adjacent commits must not discard each other's recovered historical files."""
from copy import deepcopy
import json
import sqlite3

import pytest

from agentlog_unified.config import sha256_file
from agentlog_unified.semantic_context import load_run, merge_snapshot


def test_same_revision_union_survives_reload_and_rejects_source_conflicts(tmp_path):
    sha='a'*40
    left={'sha':sha,'files':{'shared.ts':'const n = 1','only-left.ts':'left'},
          'file_provenance':{'only-left.ts':{'source_backend':'pydriller'}},
          'gaps':[{'reason':'bounded_snapshot'}]}
    right={'sha':sha,'files':{'shared.ts':'const n = 1','only-right.ts':'right'},
           'file_provenance':{'only-right.ts':{'source_backend':'pydriller'}},
           'gaps':[{'reason':'bounded_snapshot'},{'reason':'missing_dependency'}]}
    untouched=deepcopy(left)
    snapshots={}
    merge_snapshot(snapshots,'org/repo',sha,left)
    merge_snapshot(snapshots,'org/repo',sha,right)
    merged=deepcopy(snapshots)
    assert set(snapshots['org/repo',sha]['files'])=={'shared.ts','only-left.ts','only-right.ts'}
    assert len(snapshots['org/repo',sha]['gaps'])==2 and left==untouched
    assert len(snapshots['org/repo',sha]['file_provenance'])==2
    with pytest.raises(ValueError,match='conflicting_same_revision'):
        merge_snapshot(snapshots,'org/repo',sha,{'sha':sha,'files':{'shared.ts':'different'}})
    with pytest.raises(ValueError,match='sha_mismatch'):
        merge_snapshot(snapshots,'org/repo','b'*40,left)
    assert snapshots==merged
    db=sqlite3.connect(tmp_path/'checkpoint.sqlite')
    db.execute('CREATE TABLE records(kind TEXT, data TEXT)')
    for raw in (left,right):
        db.execute('INSERT INTO records VALUES(?,?)',('mined_units',json.dumps({'repository':'org/repo','snapshots':{sha:raw}})))
    db.commit();db.close()
    (tmp_path/'manifest.json').write_text(json.dumps({'status':'complete',
        'artifact_sha256':{'checkpoint.sqlite':sha256_file(tmp_path/'checkpoint.sqlite')}}))
    assert load_run(tmp_path)[1]==merged

import sys
from pathlib import Path
from collections import Counter
from types import SimpleNamespace
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src'))
from agentlog_unified import miner
from swechat_mining_storage import install


def fixture():
    source=''.join(['payload = ',repr('repeated content 你好'), '\n'])
    return SimpleNamespace(old_path='fixture.py',new_path='fixture.py',change_type=SimpleNamespace(name='MODIFY'),
        source_code_before=source,source_code=''.join([source,'']),content_before=source.encode(),content=source.encode(),
        diff_parsed={'added':[(1,source.rstrip())],'deleted':[(1,source.rstrip())]},diff='@@ -1 +1 @@\n-'+source+'+'+source)


def collect(tmp_path):
    gaps=[];metrics=Counter()
    rows=[miner._record_file(str(tmp_path),'b'*40,'a'*40,fixture(),'fixture',None,2**20,gaps,metrics,{}) for _ in range(3)]
    return rows,gaps,dict(metrics)


def test_records_metrics_gaps_and_fingerprint_remain_identical(tmp_path):
    expected,gaps,metrics=collect(tmp_path)
    fingerprints=[miner._file_fingerprint(x) for x in [[],expected,expected[:1],list(reversed(expected))]]
    finish=install(miner)
    try:
        actual,new_gaps,new_metrics=collect(tmp_path)
        assert (actual,new_gaps,new_metrics)==(expected,gaps,metrics)
        assert [miner._file_fingerprint(x) for x in [[],actual,actual[:1],list(reversed(actual))]]==fingerprints
        assert actual[0]['before_source'] is actual[1]['before_source']
        actual[0]['added'][0][1]='changed only this row'
        assert actual[1]['added'][0][1]!='changed only this row'
    finally:
        stats=finish()
    assert stats['duplicate_string_values_shared']>0 and stats['selection_changed'] is False

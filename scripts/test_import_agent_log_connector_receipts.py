import hashlib
import json
import sys
from pathlib import Path
import pytest
sys.path.insert(0,str(Path(__file__).resolve().parent))
from import_agent_log_connector_receipts import ingest


def test_successful_retry_retains_failure_receipt(tmp_path):
    batches=tmp_path/'batches';batches.mkdir();out=tmp_path/'cache'
    url='https://api.github.com/repos/fixture/repo/issues/1/comments?per_page=100'
    failed=dict(url=url,success=False,reason='transport decode failure',collected_at='2026-01-01',association_basis={'from':'exact_commit_PR'})
    good={**failed,'success':True,'data':[],'collected_at':'2026-01-02'}
    (batches/'batch-00000.json').write_text(json.dumps([failed]))
    (batches/'retry_transport.json').write_text(json.dumps(good))
    ingest(batches,out)
    key=hashlib.sha256(url.encode()).hexdigest()+'.json'
    assert (out/'failures'/key).exists() and (out/'external_cache'/key).exists()
    summary=json.loads((out/'summary.json').read_text())
    assert summary['unique_successful_urls']==1 and summary['unique_unavailable_urls']==0
    with pytest.raises(FileExistsError):ingest(batches,out)


def test_unassociated_response_is_rejected(tmp_path):
    batches=tmp_path/'batches';batches.mkdir()
    (batches/'batch-0.json').write_text(json.dumps([dict(url='https://api.github.com/repos/fixture/repo/issues/1',success=True,data={},association_basis={})]))
    with pytest.raises(ValueError,match='association'):ingest(batches,tmp_path/'out')

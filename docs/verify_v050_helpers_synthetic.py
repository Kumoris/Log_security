import sys, json, tempfile
from pathlib import Path
base=Path('/Users/lzh/Downloads/Log 研究/agentlog_unified')
sys.path.insert(0,str(base/'docs'))
from agentlog_unified import aidev,content_scan,content_advance,content_repair,content_reconcile
import pyarrow as pa, pyarrow.parquet as pq
from verify_aidev_repair_v050 import verify as vr
from verify_aidev_reconcile_v050 import verify as vm
with tempfile.TemporaryDirectory(prefix='v050-verifier-selfcheck-') as tmp:
 root=Path(tmp);raw=root/'raw';raw.mkdir()
 pq.write_table(pa.table({'body':['192.0.2.1 192.0.2.2','text without field clues']}),raw/'all_pull_request.parquet')
 aidev.import_aidev(raw,root/'imported')
 content_scan.scan_content(root/'imported',root/'seed',max_seconds=1e-9,max_matches=1)
 content_advance.advance_content(root/'seed',root/'advanced',min_free_bytes=1)
 content_repair.run_content_repair(root/'advanced',root/'fixed')
 content_reconcile.reconcile_content(root/'advanced',root/'fixed',root/'merged')
 repair_status=vr(root/'fixed',root/'repair-verification.json')
 merge_status=vm(root/'merged',root/'merge-verification.json')
 reports={k:json.loads((root/(k+'-verification.json')).read_text()) for k in ('repair','merge')}
 result={'kind':'real_synthetic_import_seed_advance_repair_merge_helper_selfcheck','real_dataset_values_read':False,'source_values_exported':False,'repair_verifier_exit':repair_status,'merge_verifier_exit':merge_status,'checks':{k:{'passed':r['passed'],'total':r['total'],'failed':[n for n,v in r['checks'].items() if not v]} for k,r in reports.items()}}
 out=base/'docs/aidev_v050_verification_helpers_self_test.json'
 if out.exists():raise FileExistsError('Preserve original self test')
 out.write_text(json.dumps(result,indent=2)+'\n')
 print(json.dumps(result))
 assert repair_status==merge_status==0

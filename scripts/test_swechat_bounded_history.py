import sys,copy,pytest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src'))
from agentlog_unified import analysis,lineage
from swechat_bounded_history import Changes,integration_snapshots,detect

def test_shared_prefix_has_list_order_and_no_parent_mutation():
    a=Changes([1,2]);a.extend([3]);b=Changes(a);b.extend([4,5]);c=Changes(a);c.extend([6])
    assert list(a)==[1,2,3] and list(b)==[1,2,3,4,5] and c+[7]==[1,2,3,6,7]

def test_first_parent_integration_snapshot_includes_side_branch_merge():
    m=dict(graph=[{'sha':'a','parents':[]},{'sha':'b','parents':['a']},{'sha':'c','parents':['a']},
                  {'sha':'d','parents':['c','b']},{'sha':'e','parents':['d']}],first_parent_shas=['a','c','d','e'])
    assert integration_snapshots(m,['b'])=={'b','d'}

@pytest.mark.parametrize('sources',[
    ["print('a')\n",None,"print('b')\n","print('c')\n"],
    ["print('a')\nprint('a')\n","print('a')\n",None,"print('b')\nprint('b')\n"],
])
def test_storage_adapter_preserves_events_gaps_and_trace(monkeypatch,sources):
    shas=[str(i)*40 for i in range(1,5)]
    by=dict(zip(shas,sources))
    def snapshot(path,sha,**kwargs):
        source=by[sha]
        return dict(files={} if source is None else {'app.py':source},
            gaps=[dict(path='app.py',error_type='source_unavailable')] if source is None else [],backend='fixture',fallback_reason=None)
    monkeypatch.setattr(analysis,'snapshot_files',snapshot)
    commits=[];changes=[]
    for i,sha in enumerate(shas):
        parent=shas[i-1] if i else None
        commits.append(dict(sha=sha,parents=[parent] if parent else [],topo_index=i,merge=False,on_target_first_parent=True,target_reachable=True,committer_date='2026-01-01T00:00:00Z'))
        changes.append(dict(change_id=sha,sha=sha,parent_sha=parent,old_path='app.py' if parent else None,new_path='app.py',added=[[1,'x']],deleted=[[1,'x']] if parent else [],diff_backend='fixture',fallback_reason=None,extraction_status='ok'))
    mined=dict(repository_id='r',commits=commits,changes=changes,graph=[{'sha':c['sha'],'parents':c['parents']} for c in commits],first_parent_shas=shas)
    repo=dict(id='r',repository_id='fixture/repo',local_repo_path='unused',pr_ids=['p'],target_ref='main',frozen_target_tip=shas[-1],shallow=False,missing_shas=[],local_snapshot_only=True)
    config=dict(mining={'max_snapshot_files':100,'max_source_file_bytes':10000},languages=['python'])
    original=analysis.detect_history(repo,mined,config)
    retained=detect(analysis,repo,mined,config,[shas[0]])
    for key in ['events','gaps','audit']:assert original[key]==retained[key]
    context=dict(id='p',repository='fixture/repo',cohort='fixture',is_synthetic=False,commit_shas=[shas[0]])
    def trace(result):return lineage.trace_logs([repo],[context],[mined],result['events'],result['snapshots'],'2026-09-22T00:00:00Z',90,result['gaps'])
    assert trace(original)==trace(retained)
    assert any(f['change_kind']=='gap_resumed' for f in trace(retained)['followups'])

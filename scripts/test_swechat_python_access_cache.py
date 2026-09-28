import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src'))
from agentlog_unified import detector
from align_swechat_agent_logs import Guard
from swechat_python_mutation_index import install as install_index
from swechat_python_evaluation_cache import install as install_evaluation
from swechat_python_file_cache import install


def test_exact_access_receipts_invalidate_missing_targets_classes_and_nested_calls():
    # Two roots evaluate shared AST nodes; a cross-root value cache must never
    # conceal the nested import receipts from the second root.
    entry='import logging\nfrom helper import wrap\nfrom models import Data\nlogging.info("%s %s",wrap(2),Data())\n'
    base={'a.py':entry,'b.py':entry,'helper.py':'from nested import convert\ndef wrap(x):\n    return convert(x)\n',
          'nested.py':'def convert(x):\n    return {"value":x}\n','models.py':'class Data:\n    count: int\n'}
    changes=[{}, {'nested.py':'def convert(x):\n    return str(x)\n'},
             {'models.py':'class Data:\n    name: str\n'}, {'models.py':'x=1\n'},
             {'helper.py':'from missing import convert\ndef wrap(x):\n    return convert(x)\n'},
             {'helper.py':'from missing import convert\ndef wrap(x):\n    return convert(x)\n','missing.py':'def convert(x):\n    return {"tag":x}\n'},
             {'helper.py':'def wrap(x):\n    return x\n'}, {}]
    snapshots=[dict(base,**change) for change in changes]
    guard=Guard(Path(__file__).resolve().parents[1])
    for files in snapshots:
        for path,source in files.items():
            assert guard.check('synthetic/access-cache-equivalence',path,source)=='allowed'
    expected=[detector.detect_snapshot(files) for files in snapshots]
    assert guard.api.assess([{'callee':e['callee']} for r in expected for e in r['entities']],guard.ids,guard.keys)['allowed']
    fi=install_index(detector);fe=install_evaluation(detector);ff=install(detector,accessed_imports=True)
    try:
        actual=[detector.detect_snapshot(files) for files in snapshots]
        assert actual==expected
    finally:ff();fe();fi()


def test_unchanged_result_reused_when_unused_transitive_import_changes():
    first={'app.py':'import logging\nfrom helper import unused\nlogging.info("same")\n',
           'helper.py':'from nested import unused\n','nested.py':'unused=1\n'}
    second={**first,'nested.py':'unused=2\n'}
    guard=Guard(Path(__file__).resolve().parents[1])
    for files in [first,second]:
        for path,source in files.items():
            assert guard.check('synthetic/access-cache-equivalence',path,source)=='allowed'
    expected=[detector.detect_snapshot(files) for files in [first,second]]
    fi=install_index(detector);fe=install_evaluation(detector);ff=install(detector,accessed_imports=True)
    try:assert [detector.detect_snapshot(files) for files in [first,second]]==expected
    finally:stats=ff();fe();fi()
    assert stats['access_validation_hits']>=2

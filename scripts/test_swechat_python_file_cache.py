import sys
import pytest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src'))
from agentlog_unified import detector
from swechat_python_mutation_index import install as index_install
from swechat_python_evaluation_cache import install as evaluation_install
from swechat_python_file_cache import install
from test_swechat_python_evaluation_cache import versions


@pytest.mark.parametrize('accessed_imports',[False,True])
def test_exact_outputs_across_import_changes_invalid_syntax_and_suffix_ambiguity(accessed_imports):
    snapshots=versions()
    src='import logging\nfrom helper import wrap\nlogging.info("%s",wrap("test"))\n'
    snapshots += [
        {'entry.py':src,'helper.py':'def wrap(x):\n    return {"one": x}\n','untouched.py':'import logging\nlogging.info("stable")\n'},
        {'entry.py':src,'helper.py':'def wrap(x):\n    return {"two": x}\n','untouched.py':'import logging\nlogging.info("stable")\n'},
        {'entry.py':src,'pkg/helper.py':'def wrap(x):\n    return x\n'},
        {'entry.py':src,'pkg/helper.py':'def wrap(x):\n    return x\n','other/helper.py':'def wrap(x):\n    return str(x)\n'},
        {'entry.py':src,'helper.py':'def syntax error','readme.txt':'ignored'},
        {'entry.py':src,'helper.py':'from nested import project\ndef wrap(x):\n    return project(x)\n','nested.py':'def project(x):\n    return {"k":x}\n'},
        {'entry.py':src,'helper.py':'from nested import project\ndef wrap(x):\n    return project(x)\n','nested.py':'def project(x):\n    return {"key":str(x)}\n'},
    ]
    expected=[detector.detect_snapshot(s) for s in snapshots]
    fi=index_install(detector);fe=evaluation_install(detector);ff=install(detector,accessed_imports=accessed_imports)
    try:
        actual=[detector.detect_snapshot(s) for s in snapshots]
        assert actual==expected
        # Mutating a consumer result cannot contaminate subsequent cache hits.
        actual[-1]['entities'][0]['statement']='consumer mutation'
        assert detector.detect_snapshot(snapshots[-1])==expected[-1]
    finally:
        stats=ff();fe();fi()
    assert stats['index_hits']>0 and stats['entity_hits']>0


@pytest.mark.parametrize('accessed_imports',[False,True])
def test_resolution_changes_even_when_transitive_file_set_is_unchanged(accessed_imports):
    source='from helper import logwrap\nimport pkg.helper as keep_reachable\nlogwrap("example")\n'
    helper='import logging\ndef logwrap(value):\n    logging.info("%s",value)\n'
    first={'entry.py':source,'pkg/helper.py':helper}
    unrelated={**first,'unrelated.py':'x=1\n'}
    ambiguous={**unrelated,'other/helper.py':'x=2\n'}
    expected=[detector.detect_snapshot(x) for x in (first,unrelated,ambiguous)]
    fi=index_install(detector);fe=evaluation_install(detector);ff=install(detector,accessed_imports=accessed_imports)
    try:actual=[detector.detect_snapshot(x) for x in (first,unrelated,ambiguous)]
    finally:stats=ff();fe();fi()
    assert actual==expected
    assert stats['entity_hits']>=3
    assert len(expected[0]['entities'])>len(expected[2]['entities'])

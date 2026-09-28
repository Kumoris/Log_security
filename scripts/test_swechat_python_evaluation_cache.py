import sys
import ast
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src'))
from agentlog_unified import detector
from swechat_python_evaluation_cache import install,Dependencies
from swechat_python_mutation_index import install as index_install


def test_dependency_reduction_retains_order_and_last_value():
    base=dict(path='app.py',symbol='f',start_line=1,end_line=1,kind='definition',code='first')
    rows=[base,{**base,'start_line':2,'code':'second'},{**base,'code':'last'}]
    expected=list({(r['path'],r['symbol'],r['start_line'],r['end_line'],r['kind']):r for r in rows}.values())
    deps=Dependencies();deps.extend(rows)
    assert list(deps)==expected


def versions():
    body='''import logging
from helper import wrap
def run(flag, username: str):
    payload = {"count": 1, "user_id": username}
    alias = payload
    for _ in range(2):
        alias.update({"tag": "x"})
        if flag:
            alias["count"] += 1
    nested = [payload, [payload, payload], {"again": payload}]
    logging.info("values %s %s", nested, nested)
    logging.debug("wrapped %s", wrap(nested))
    alias.pop("user_id")
    logging.warning("after %s", nested)
'''
    base={'app.py':body,'helper.py':'def wrap(value):\n    return {"wrapped": value}\n'}
    return [base,{**base,'app.py':body.replace('alias.pop("user_id")','alias.clear()')},
            {**base,'helper.py':'def wrap(value):\n    return str(value)\n'},
            {**base,'app.py':body.replace('payload = {"count": 1, "user_id": username}',
                'payload = {"count": 1, "user_id": username}\n    if flag:\n        payload = {"nested": payload}')},
            {**base,'app.py':body.replace('logging.info("values %s %s", nested, nested)',
                'logging.info("values %s %s", [nested, nested, nested], nested)')}]


def test_complete_outputs_match_original_with_cross_file_and_conditional_changes():
    fixtures=versions()
    expected=[detector.detect_snapshot(files) for files in fixtures]
    finish_index=index_install(detector);finish=install(detector)
    try:
        actual=[detector.detect_snapshot(files) for files in fixtures]
        assert actual==expected
    finally:
        stats=finish();finish_index()
    assert stats['value_cache_hits']>0 and stats['dependency_cache_hits']>0


def test_values_return_independent_objects_and_respect_depth_and_bindings():
    source='import logging\nx={"count":1}\nlogging.info("%s",x)\n'
    finish=install(detector)
    try:
        snapshot=detector.PythonSnapshot({'app.py':source})
        node=next(n for n in ast.walk(snapshot.trees['app.py']) if isinstance(n,ast.Name) and n.id=='x' and isinstance(n.ctx,ast.Load))
        a=snapshot.value('app.py',node,'<module>',(3,0),[])
        a.gaps.append('mutated by consumer')
        b=snapshot.value('app.py',node,'<module>',(3,0),[])
        assert 'mutated by consumer' not in b.gaps
        limited=snapshot.value('app.py',node,'<module>',(3,0),[],depth=11)
        assert limited.gaps==['local_expression_depth_limit']
        unknown=ast.Name(id='argument',ctx=ast.Load())
        one=snapshot.value('app.py',unknown,'f',(3,0),[],{'argument':detector.Value(known=True,masked=True)})
        two=snapshot.value('app.py',unknown,'f',(3,0),[],{'argument':detector.Value(known=False)})
        assert one.masked and not two.masked
    finally:finish()

import sys
from pathlib import Path
from collections import OrderedDict
from types import SimpleNamespace
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from agentlog_unified import detector
from swechat_python_mutation_index import install, _items


def test_exact_predicate_order_and_no_duplicate_scope():
    data=OrderedDict([(('x.py','global','v'),[1]), (('y.py','global','v'),[2]),
                      (('x.py','f','b'),[3]), (('x.py','other','c'),[4]),
                      (('x.py','global','z'),[5])])
    obj=SimpleNamespace(mutations=data)
    for scopes in [('global','f'),('global','global'),('other','absent')]:
        assert _items(obj,'x.py',scopes)==[(k,v) for k,v in data.items() if k[0]=='x.py' and k[1] in set(scopes)]


def test_complete_outputs_equal_across_dependency_and_mutation_changes():
    base={'unrelated.py': 'values={}\nvalues.update({"password":"secret"})\n',
          'helpers.py': 'def identity(value):\n    return value\n',
          'app.py': '''import logging
from helpers import identity
payload = {"user_id": "a", "count": 1}
payload.update({"tag": "start"})
def run(extra):
    data = payload
    data["extra"] = extra
    data.pop("user_id")
    logging.info("result %s", identity(data))
    data.clear()
    logging.debug("clear %s", data)
'''}
    versions=[base,{**base,'app.py':base['app.py'].replace('data.clear()','data["count"] += 1')},
              {**base,'helpers.py':'def identity(value):\n    return {"wrapped": value}\n'},
              {**base,'app.py':base['app.py'].replace('data.pop("user_id")','del data["user_id"]')}]
    expected=[detector.detect_snapshot(files) for files in versions]
    finish=install(detector)
    try:
        actual=[detector.detect_snapshot(files) for files in versions]
        assert actual==expected
    finally:
        finish()
